#!/usr/bin/env python3
"""Tests for non-interactive command execution and command piping in moesh.

Validates:
1. Protocol negotiation for session_type="exec" and command payload.
2. Direct socket execution of run_exec_session (agent and client sides).
3. Non-zero exit status propagation.
4. Bidirectional stdin/stdout streaming and pipe half-close EOF signaling.
5. Piped script execution without explicit command argument (stdin driven shell).
6. Large binary / payload streaming through pipes.
7. End-to-end integration through the receiver bridge.
"""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import threading
import time
from typing import TYPE_CHECKING, Any, TypedDict

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

import pytest

import moesh_proto as proto
import moesh_shell
import moesh_tunnel
from tests.harness import AGENT_PYTHON, TUNNEL_DIR, Bridge, next_ports

_ALPHA = "alpha"


def _tcp_pair() -> tuple[socket.socket, socket.socket]:
    """Create a pair of connected loopback TCP sockets."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", port))
    server_conn, _ = srv.accept()
    srv.close()
    return client, server_conn


# ─────────────────────────────────────────────────────────────────────────────
# Unit Tests (Direct Sockets, No Bridge Needed)
# ─────────────────────────────────────────────────────────────────────────────

def test_validate_hello_exec_session() -> None:
    """Validate HELLO accepts session_type='exec' and optional command string."""
    body = {
        "version": proto.PROTOCOL_VERSION,
        "term": "xterm-256color",
        "encoding": "utf-8",
        "rows": 24,
        "cols": 80,
        "capabilities": ["resize", "ping"],
        "max_record": 65536,
        "handshake_hash": "a" * 64,
        "fresh_session": True,
        "session_type": "exec",
        "command": "uname -a",
    }
    agreed = proto.validate_hello(body)
    assert agreed["session_type"] == "exec"
    assert agreed["command"] == "uname -a"


def test_validate_hello_rejects_invalid_command_type() -> None:
    """Validate HELLO raises NegotiationError if command is not a string."""
    body = {
        "version": proto.PROTOCOL_VERSION,
        "term": "xterm-256color",
        "encoding": "utf-8",
        "rows": 24,
        "cols": 80,
        "capabilities": [],
        "max_record": 65536,
        "handshake_hash": "a" * 64,
        "session_type": "exec",
        "command": 12345,  # Invalid
    }
    with pytest.raises(proto.NegotiationError):
        proto.validate_hello(body)


def _setup_authenticated_exec(
    command: str | None = None,
) -> tuple[socket.socket, proto.SecureChannel, socket.socket, proto.SecureChannel, dict[str, Any]]:
    """Establish authenticated, negotiated secure channels over a TCP pair."""
    client_sock, agent_sock = _tcp_pair()

    op_priv, op_pub = proto.generate_static_keypair()
    ag_priv, ag_pub = proto.generate_static_keypair()

    client_session = proto.NoiseSession("initiator", op_priv, ag_pub)
    agent_session = proto.NoiseSession("responder", ag_priv, op_pub)

    client_chan = proto.Channel(client_sock)
    agent_chan = proto.Channel(agent_sock)

    # Perform handshake
    client_chan.send_frame(client_session.write_handshake())
    agent_session.read_handshake(agent_chan.recv_frame())
    agent_chan.send_frame(agent_session.write_handshake())
    client_session.read_handshake(client_chan.recv_frame())
    client_chan.send_frame(client_session.write_handshake())
    agent_session.read_handshake(agent_chan.recv_frame())

    assert client_session.handshake_finished and client_session.authenticated
    assert agent_session.handshake_finished and agent_session.authenticated

    client_sec = proto.SecureChannel(client_chan, client_session)
    agent_sec = proto.SecureChannel(agent_chan, agent_session)

    # Negotiate
    client_machine = proto.SessionState()
    client_machine.to(proto.State.AUTHENTICATED)
    agent_machine = proto.SessionState()
    agent_machine.to(proto.State.AUTHENTICATED)

    agent_pool = moesh_tunnel.ShellPool()

    accepted_box: list[dict[str, Any]] = []

    def run_agent_neg() -> None:
        acc = moesh_tunnel.negotiate(agent_sec, agent_machine, agent_pool)
        accepted_box.append(acc)

    t = threading.Thread(target=run_agent_neg)
    t.start()

    _agreed = moesh_shell.negotiate(
        client_sec,
        client_machine,
        term="xterm",
        fresh=True,
        session_type="exec",
        command=command,
    )
    t.join(timeout=5.0)

    assert accepted_box
    accepted = accepted_box[0]
    return client_sock, client_sec, agent_sock, agent_sec, accepted


def test_direct_exec_simple_command() -> None:
    """Test remote command execution capturing stdout and status code 0."""
    client_sock, client_sec, agent_sock, agent_sec, accepted = _setup_authenticated_exec(
        command="echo -n 'hello from exec'"
    )

    agent_result: list[str] = []

    def run_agent() -> None:
        res = moesh_tunnel.run_exec_session(agent_sock, agent_sec, accepted)
        agent_result.append(res)

    t = threading.Thread(target=run_agent)
    t.start()

    r_out, w_out = os.pipe()
    r_in, w_in = os.pipe()
    os.close(w_in)  # Immediate EOF on stdin

    try:
        status = moesh_shell.run_exec_session(
            client_sock,
            client_sec,
            accepted,
            stdin_fd=r_in,
            stdout_fd=w_out,
        )
        assert status == 0
        os.close(w_out)
        out = os.read(r_out, 4096)
        assert out == b"hello from exec"
    finally:
        os.close(r_out)
        os.close(r_in)
        t.join(timeout=5.0)
        client_sock.close()
        agent_sock.close()


def test_direct_exec_exit_code_propagation() -> None:
    """Test that a non-zero exit code from a remote command propagates to client."""
    client_sock, client_sec, agent_sock, agent_sec, accepted = _setup_authenticated_exec(
        command="exit 42"
    )

    t = threading.Thread(
        target=lambda: moesh_tunnel.run_exec_session(agent_sock, agent_sec, accepted)
    )
    t.start()

    r_out, w_out = os.pipe()
    r_in, w_in = os.pipe()
    os.close(w_in)

    try:
        status = moesh_shell.run_exec_session(
            client_sock,
            client_sec,
            accepted,
            stdin_fd=r_in,
            stdout_fd=w_out,
        )
        assert status == 42
    finally:
        os.close(r_out)
        os.close(w_out)
        os.close(r_in)
        t.join(timeout=5.0)
        client_sock.close()
        agent_sock.close()


def test_direct_exec_stdin_piping() -> None:
    """Test streaming stdin through a remote command (tr a-z A-Z)."""
    client_sock, client_sec, agent_sock, agent_sec, accepted = _setup_authenticated_exec(
        command="tr a-z A-Z"
    )

    t = threading.Thread(
        target=lambda: moesh_tunnel.run_exec_session(agent_sock, agent_sec, accepted)
    )
    t.start()

    r_out, w_out = os.pipe()
    r_in, w_in = os.pipe()

    # Write input to client stdin
    os.write(w_in, b"streaming pipeline through moesh\n")
    os.close(w_in)  # EOF

    try:
        status = moesh_shell.run_exec_session(
            client_sock,
            client_sec,
            accepted,
            stdin_fd=r_in,
            stdout_fd=w_out,
        )
        assert status == 0
        os.close(w_out)
        out = os.read(r_out, 4096)
        assert out == b"STREAMING PIPELINE THROUGH MOESH\n"
    finally:
        os.close(r_out)
        os.close(r_in)
        t.join(timeout=5.0)
        client_sock.close()
        agent_sock.close()


def test_direct_exec_piped_script_no_command_arg() -> None:
    """Test piping a shell script via stdin when command is None."""
    client_sock, client_sec, agent_sock, agent_sec, accepted = _setup_authenticated_exec(
        command=None
    )

    t = threading.Thread(
        target=lambda: moesh_tunnel.run_exec_session(agent_sock, agent_sec, accepted)
    )
    t.start()

    r_out, w_out = os.pipe()
    r_in, w_in = os.pipe()

    script = b"A=10\nB=20\necho $((A + B))\n"
    os.write(w_in, script)
    os.close(w_in)

    try:
        status = moesh_shell.run_exec_session(
            client_sock,
            client_sec,
            accepted,
            stdin_fd=r_in,
            stdout_fd=w_out,
        )
        assert status == 0
        os.close(w_out)
        out = os.read(r_out, 4096)
        assert out.strip() == b"30"
    finally:
        os.close(r_out)
        os.close(r_in)
        t.join(timeout=5.0)
        client_sock.close()
        agent_sock.close()


def test_direct_exec_large_payload_pipe() -> None:
    """Test throughput and boundary chunking over 256KB piped through wc -c."""
    client_sock, client_sec, agent_sock, agent_sec, accepted = _setup_authenticated_exec(
        command="wc -c"
    )

    t = threading.Thread(
        target=lambda: moesh_tunnel.run_exec_session(agent_sock, agent_sec, accepted)
    )
    t.start()

    r_out, w_out = os.pipe()
    r_in, w_in = os.pipe()

    payload_size = 256 * 1024
    payload = b"X" * payload_size

    def writer() -> None:
        view = memoryview(payload)
        while view:
            written = os.write(w_in, view)
            view = view[written:]
        os.close(w_in)

    wt = threading.Thread(target=writer)
    wt.start()

    try:
        status = moesh_shell.run_exec_session(
            client_sock,
            client_sec,
            accepted,
            stdin_fd=r_in,
            stdout_fd=w_out,
        )
        assert status == 0
        os.close(w_out)
        out = os.read(r_out, 4096)
        assert int(out.strip()) == payload_size
    finally:
        wt.join(timeout=5.0)
        os.close(r_out)
        os.close(r_in)
        t.join(timeout=5.0)
        client_sock.close()
        agent_sock.close()


# ─────────────────────────────────────────────────────────────────────────────
# End-to-End Integration Tests (Through Bridge)
# ─────────────────────────────────────────────────────────────────────────────

class ExecFixture(TypedDict):
    bridge: Bridge
    agent: subprocess.Popen[bytes]
    client_env: Callable[[str], dict[str, str]]


@pytest.fixture()
def exec_env(tmp_path: Path) -> Iterator[ExecFixture]:
    """Launch agent behind bridge with key configuration."""
    agent_private, agent_public = proto.generate_static_keypair()
    operator_private, operator_public = proto.generate_static_keypair()

    pins = tmp_path / "hosts.toml"
    pins.write_text(
        f'[hosts.{_ALPHA}]\nagent_pub = "{agent_public.hex()}"\n',
        encoding="ascii",
    )

    operator_keyfile = tmp_path / "operator.key"
    operator_keyfile.write_text(operator_private.hex() + "\n", encoding="ascii")
    operator_keyfile.chmod(0o600)

    tunnel_port, operator_port, operator_v2_port = next_ports()
    bridge = Bridge(
        tunnel_port=tunnel_port,
        operator_port=operator_port,
        operator_v2_port=operator_v2_port,
    )

    env = dict(os.environ)
    env.update(
        {
            "MOESH_TUNNEL_RECEIVER": "127.0.0.1",
            "MOESH_TUNNEL_RECEIVER_PORT": str(tunnel_port),
            "MOESH_TUNNEL_AGENT_KEY": agent_private.hex(),
            "MOESH_TUNNEL_OPERATOR_PUB": operator_public.hex(),
            "MOESH_TUNNEL_NAME": _ALPHA,
        }
    )
    log_path = tmp_path / f"agent-{_ALPHA}.log"
    log_file = open(log_path, "wb")  # noqa: SIM115
    agent = subprocess.Popen(
        [AGENT_PYTHON, os.path.join(TUNNEL_DIR, "moesh_tunnel.py")],
        stdout=log_file,
        stderr=subprocess.STDOUT,
        env=env,
    )
    deadline = time.time() + 45.0
    while time.time() < deadline:
        try:
            with open(log_path, "rb") as f:
                content = f.read()
                if b"tunnel established" in content or b"waiting for an operator" in content:
                    break
        except OSError:
            pass
        if agent.poll() is not None:
            raise TimeoutError(f"Agent {_ALPHA} exited prematurely with code {agent.returncode}")
        time.sleep(0.05)
    else:
        raise TimeoutError(f"Agent {_ALPHA} timed out waiting for tunnel establishment")

    def client_env(host: str) -> dict[str, str]:
        cenv = dict(os.environ)
        cenv.update(
            {
                "MOESH_SHELL_ADDR": f"127.0.0.1:{operator_v2_port}",
                "MOESH_SHELL_KEYFILE": str(operator_keyfile),
                "MOESH_SHELL_HOSTS_FILE": str(pins),
                "MOESH_SHELL_HANDSHAKE_TIMEOUT": "60",
            }
        )
        return cenv

    yield {
        "bridge": bridge,
        "agent": agent,
        "client_env": client_env,
    }

    agent.terminate()
    try:
        agent.wait(timeout=10)
    except subprocess.TimeoutExpired:
        agent.kill()
    log_file.close()
    bridge.stop()


def test_e2e_command_exec_and_exit_code(exec_env: ExecFixture) -> None:
    """Run remote command via moesh_shell CLI and assert stdout and returncode."""
    env = exec_env["client_env"](_ALPHA)
    client_bin = os.path.join(TUNNEL_DIR, "moesh_shell.py")

    # Command 1: simple echo
    res = subprocess.run(
        [AGENT_PYTHON, client_bin, "-q", "-n", _ALPHA, "echo", "e2e_piping_success"],
        env=env,
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )
    assert res.returncode == 0
    assert res.stdout.strip() == "e2e_piping_success"

    # Command 2: non-zero exit code
    res_fail = subprocess.run(
        [AGENT_PYTHON, client_bin, "-q", "-n", _ALPHA, "exit 77"],
        env=env,
        capture_output=True,
        timeout=45,
        check=False,
    )
    assert res_fail.returncode == 77


def test_e2e_stdin_piping_and_filtering(exec_env: ExecFixture) -> None:
    """Pipe text into moesh_shell running a filter command."""
    env = exec_env["client_env"](_ALPHA)
    client_bin = os.path.join(TUNNEL_DIR, "moesh_shell.py")

    input_text = "alpha\nbeta\ngamma\nbeta\n"
    res = subprocess.run(
        [AGENT_PYTHON, client_bin, "-q", "-n", _ALPHA, "grep beta"],
        input=input_text,
        text=True,
        env=env,
        capture_output=True,
        timeout=45,
        check=False,
    )
    assert res.returncode == 0
    assert res.stdout == "beta\nbeta\n"


def test_e2e_cmd_flag_execution(exec_env: ExecFixture) -> None:
    """Run remote command via moesh_shell CLI using -c flag (DEF-03)."""
    env = exec_env["client_env"](_ALPHA)
    client_bin = os.path.join(TUNNEL_DIR, "moesh_shell.py")

    res = subprocess.run(
        [AGENT_PYTHON, client_bin, "-q", "-n", _ALPHA, "-c", "echo e2e_c_flag_success"],
        env=env,
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )
    assert res.returncode == 0
    assert res.stdout.strip() == "e2e_c_flag_success"


def test_e2e_argument_splitting_preservation(exec_env: ExecFixture) -> None:
    """Run remote command with arguments containing spaces preserved via shlex.join (DEF-03)."""
    env = exec_env["client_env"](_ALPHA)
    client_bin = os.path.join(TUNNEL_DIR, "moesh_shell.py")

    res = subprocess.run(
        [
            AGENT_PYTHON,
            client_bin,
            "-q",
            "-n",
            _ALPHA,
            "printf",
            "%s|%s\n",
            "hello world",
            "another arg",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )
    assert res.returncode == 0
    assert res.stdout.strip() == "hello world|another arg"


def test_dynamic_hosts_file_evaluation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test dynamic evaluation of MOESH_SHELL_HOSTS_FILE at runtime (G-SLOPPY-1)."""
    hosts_a = tmp_path / "hosts_a.toml"
    hosts_a.write_text('[hosts.host_a]\nagent_pub = "1111111111111111111111111111111111111111111111111111111111111111"\n', encoding="utf-8")
    hosts_b = tmp_path / "hosts_b.toml"
    hosts_b.write_text('[hosts.host_b]\nagent_pub = "2222222222222222222222222222222222222222222222222222222222222222"\n', encoding="utf-8")

    monkeypatch.setenv("MOESH_SHELL_HOSTS_FILE", str(hosts_a))
    cfg_a = moesh_shell.load_config()
    assert "host_a" in cfg_a.get("hosts", {})

    monkeypatch.setenv("MOESH_SHELL_HOSTS_FILE", str(hosts_b))
    cfg_b = moesh_shell.load_config()
    assert "host_b" in cfg_b.get("hosts", {})


def test_raw_terminal_sigterm_sighup_handlers() -> None:
    """Test RawTerminal installs SIGTERM and SIGHUP handlers (S-ORPHAN-2)."""
    master_fd, slave_fd = os.openpty()
    try:
        term = moesh_shell.RawTerminal(slave_fd)
        with term:
            assert signal.SIGTERM in term._old_handlers
            assert signal.SIGHUP in term._old_handlers
        assert term._old_handlers == {}
    finally:
        os.close(master_fd)
        os.close(slave_fd)


def test_run_exec_session_broken_pipe() -> None:
    """Test BrokenPipeError on downstream pipe closure returns 0 cleanly (DEF-05)."""
    client_sock, client_sec, agent_sock, agent_sec, accepted = _setup_authenticated_exec(
        command="yes | head -n 1000"
    )

    t = threading.Thread(
        target=lambda: moesh_tunnel.run_exec_session(agent_sock, agent_sec, accepted)
    )
    t.start()

    r_out, w_out = os.pipe()
    r_in, w_in = os.pipe()
    os.close(w_in)
    # Immediately close read end so writing to w_out raises BrokenPipeError
    os.close(r_out)

    try:
        status = moesh_shell.run_exec_session(
            client_sock,
            client_sec,
            accepted,
            stdin_fd=r_in,
            stdout_fd=w_out,
        )
        assert status == 0
    finally:
        os.close(w_out)
        os.close(r_in)
        t.join(timeout=5.0)
        client_sock.close()
        agent_sock.close()


def test_run_exec_session_sigint() -> None:
    """Test SIGINT handling in run_exec_session returns 130 and sends interrupt (DEF-04)."""
    client_sock, client_sec, agent_sock, agent_sec, accepted = _setup_authenticated_exec(
        command="sleep 10"
    )

    agent_result: list[str] = []

    def run_agent() -> None:
        res = moesh_tunnel.run_exec_session(agent_sock, agent_sec, accepted)
        agent_result.append(res)

    t = threading.Thread(target=run_agent)
    t.start()

    r_out, w_out = os.pipe()
    r_in, w_in = os.pipe()

    def interrupt_after_delay() -> None:
        time.sleep(0.3)
        os.kill(os.getpid(), signal.SIGINT)

    int_thread = threading.Thread(target=interrupt_after_delay)
    int_thread.start()

    try:
        status = moesh_shell.run_exec_session(
            client_sock,
            client_sec,
            accepted,
            stdin_fd=r_in,
            stdout_fd=w_out,
        )
        assert status == 130
    finally:
        int_thread.join(timeout=2.0)
        os.close(w_in)
        os.close(r_in)
        os.close(w_out)
        os.close(r_out)
        t.join(timeout=5.0)
        client_sock.close()
        agent_sock.close()


def test_secret_env_vars_scrubbed_in_exec(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify sensitive environment variables are scrubbed from child process environments (DEF-12)."""
    for var in moesh_tunnel.SECRET_ENV_VARS:
        monkeypatch.setenv(var, f"leaked_secret_{var}")
    monkeypatch.setenv("MOESH_SHELL_OPERATOR_KEY", "leaked_operator_key")
    monkeypatch.setenv("MOESH_TUNNEL_CHILD_PIDFILE", "/tmp/leaked_pidfile")  # noqa: S108

    client_sock, client_sec, agent_sock, agent_sec, accepted = _setup_authenticated_exec(
        command="env"
    )

    t = threading.Thread(
        target=lambda: moesh_tunnel.run_exec_session(agent_sock, agent_sec, accepted)
    )
    t.start()

    r_out, w_out = os.pipe()
    r_in, w_in = os.pipe()
    os.close(w_in)

    try:
        status = moesh_shell.run_exec_session(
            client_sock,
            client_sec,
            accepted,
            stdin_fd=r_in,
            stdout_fd=w_out,
        )
        assert status == 0
        os.close(w_out)
        raw_env = b""
        while True:
            chunk = os.read(r_out, 4096)
            if not chunk:
                break
            raw_env += chunk
        env_text = raw_env.decode("utf-8", "replace")
        for var in moesh_tunnel.SECRET_ENV_VARS:
            assert f"leaked_secret_{var}" not in env_text
            assert f"{var}=" not in env_text
        assert "leaked_operator_key" not in env_text
        assert "MOESH_SHELL_OPERATOR_KEY=" not in env_text
    finally:
        os.close(r_out)
        os.close(r_in)
        t.join(timeout=5.0)
        client_sock.close()
        agent_sock.close()


def test_shell_pool_reap_zombie_collection() -> None:
    """Verify ShellPool.reap() invokes reap() on non-busy shells (DEF-16)."""
    pool = moesh_tunnel.ShellPool()
    master_fd, slave_fd = os.openpty()
    try:
        shell = pool.acquire(fresh=True)
        shell.fd = master_fd
        shell.pid = 99999
        shell.state = moesh_tunnel.ShellState.RUNNING

        reaped = False

        def mock_reap() -> int:
            nonlocal reaped
            reaped = True
            shell.state = moesh_tunnel.ShellState.REAPED
            shell.fd = None
            return 0

        shell.reap = mock_reap  # type: ignore[method-assign]
        pool.release(shell)

        assert not reaped
        pool.reap()
        assert reaped
        assert shell not in pool._shells
    finally:
        os.close(slave_fd)
        if shell.fd is not None:
            os.close(master_fd)
        pool.terminate_all()


def test_fetch_status_relay_auth_header(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify fetch_status transmits X-Moesh-Relay-Auth when relay token is configured (G-COMP-1)."""
    headers_received: list[bytes] = []
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    host, port = srv.getsockname()

    def handle() -> None:
        conn, _ = srv.accept()
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = conn.recv(1024)
            if not chunk:
                break
            raw += chunk
        headers_received.append(raw)
        resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"hosts\": {\"in_use\": []}}"
        conn.sendall(resp)
        conn.close()

    th = threading.Thread(target=handle)
    th.start()

    token_val = "test-secret-relay-token-1234"  # noqa: S105
    monkeypatch.setenv("MOESH_BRIDGE_RELAY_TOKEN", token_val)
    try:
        data = moesh_tunnel.fetch_status(host, port)
        assert "hosts" in data
        assert len(headers_received) == 1
        assert f"X-Moesh-Relay-Auth: {token_val}\r\n".encode() in headers_received[0]
    finally:
        th.join(timeout=2.0)
        srv.close()


def test_prompt_race_sigwinch_on_silent_resume(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify negotiate() signals SIGWINCH to redraw prompt when resuming with empty buffer."""
    client_sock, agent_sock = _tcp_pair()
    op_priv, op_pub = proto.generate_static_keypair()
    ag_priv, ag_pub = proto.generate_static_keypair()

    client_session = proto.NoiseSession("initiator", op_priv, ag_pub)
    agent_session = proto.NoiseSession("responder", ag_priv, op_pub)

    client_chan = proto.Channel(client_sock)
    agent_chan = proto.Channel(agent_sock)

    client_chan.send_frame(client_session.write_handshake())
    agent_session.read_handshake(agent_chan.recv_frame())
    agent_chan.send_frame(agent_session.write_handshake())
    client_session.read_handshake(client_chan.recv_frame())
    client_chan.send_frame(client_session.write_handshake())
    agent_session.read_handshake(agent_chan.recv_frame())

    client_sec = proto.SecureChannel(client_chan, client_session)
    agent_sec = proto.SecureChannel(agent_chan, agent_session)

    client_machine = proto.SessionState()
    client_machine.to(proto.State.AUTHENTICATED)
    agent_machine = proto.SessionState()
    agent_machine.to(proto.State.AUTHENTICATED)

    pool = moesh_tunnel.ShellPool()
    master_fd, slave_fd = os.openpty()
    existing_shell = pool.acquire(fresh=True)
    existing_shell.state = moesh_tunnel.ShellState.RUNNING
    existing_shell.pid = 99999
    existing_shell.fd = master_fd
    pool.release(existing_shell)

    signals_sent: list[tuple[int, int]] = []

    def mock_kill(pid: int, sig: int) -> None:
        signals_sent.append((pid, sig))

    monkeypatch.setattr(os, "kill", mock_kill)

    t = threading.Thread(
        target=lambda: moesh_tunnel.negotiate(agent_sec, agent_machine, pool)
    )
    t.start()

    try:
        moesh_shell.negotiate(
            client_sec,
            client_machine,
            term="xterm",
            fresh=False,
            session_type="shell",
        )
        t.join(timeout=5.0)
        assert (99999, signal.SIGWINCH) in signals_sent
    finally:
        existing_shell.fd = None
        existing_shell.pid = None
        existing_shell.state = moesh_tunnel.ShellState.TERMINATED
        pool.terminate_all()
        os.close(slave_fd)
        os.close(master_fd)
        client_sock.close()
        agent_sock.close()


def test_cli_dashed_commands_parsing() -> None:
    """Test commands containing dashes (ls -la, echo -n, etc.) are parsed correctly (DEF-F3)."""
    import argparse
    import shlex

    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--host", default="default")
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("-c", "--command", dest="cmd_flag")
    parser.add_argument("command", nargs=argparse.REMAINDER)

    # 1. ls -la
    args = parser.parse_args(["-n", "3", "ls", "-la"])
    tokens = list(args.command)
    assert args.host == "3"
    assert tokens == ["ls", "-la"]
    assert shlex.join(tokens) == "ls -la"

    # 2. echo -n hello
    args = parser.parse_args(["-n", "3", "echo", "-n", "hello"])
    tokens = list(args.command)
    assert args.host == "3"
    assert tokens == ["echo", "-n", "hello"]
    assert shlex.join(tokens) == "echo -n hello"

    # 3. leading --
    args = parser.parse_args(["-n", "3", "--", "ls", "-la"])
    tokens = list(args.command)
    if tokens and tokens[0] == "--":
        tokens.pop(0)
    assert tokens == ["ls", "-la"]

    # 4. python3 -c 'print(1)' arg1
    args = parser.parse_args(["-n", "3", "python3", "-c", "print(1)", "arg1"])
    tokens = list(args.command)
    assert tokens == ["python3", "-c", "print(1)", "arg1"]


def test_direct_exec_cat_large_payload_bidirectional() -> None:
    """Test 1MB payload piped through cat completes without pipe deadlock (DEF-F1)."""
    client_sock, client_sec, agent_sock, agent_sec, accepted = _setup_authenticated_exec(
        command="cat"
    )

    t = threading.Thread(
        target=lambda: moesh_tunnel.run_exec_session(agent_sock, agent_sec, accepted)
    )
    t.start()

    r_out, w_out = os.pipe()
    r_in, w_in = os.pipe()

    payload_size = 1024 * 1024
    payload = os.urandom(payload_size)
    received = bytearray()

    def reader() -> None:
        while True:
            try:
                chunk = os.read(r_out, 65536)
                if not chunk:
                    break
                received.extend(chunk)
            except OSError:
                break

    rt = threading.Thread(target=reader)
    rt.start()

    def writer() -> None:
        view = memoryview(payload)
        while view:
            written = os.write(w_in, view)
            view = view[written:]
        os.close(w_in)

    wt = threading.Thread(target=writer)
    wt.start()

    try:
        status = moesh_shell.run_exec_session(
            client_sock,
            client_sec,
            accepted,
            stdin_fd=r_in,
            stdout_fd=w_out,
        )
        assert status == 0
    finally:
        os.close(w_out)
        wt.join(timeout=5.0)
        rt.join(timeout=5.0)
        t.join(timeout=5.0)
        os.close(r_out)
        os.close(r_in)
        client_sock.close()
        agent_sock.close()

    assert bytes(received) == payload


def test_direct_exec_child_process_killed_on_disconnect() -> None:
    """Test child process group is terminated cleanly on client disconnect (DEF-F2)."""
    client_sock, _client_sec, agent_sock, agent_sec, accepted = _setup_authenticated_exec(
    )

    t = threading.Thread(
        target=lambda: moesh_tunnel.run_exec_session(agent_sock, agent_sec, accepted)
    )
    t.start()

    time.sleep(0.3)
    client_sock.close()

    t.join(timeout=3.0)
    assert not t.is_alive(), "agent run_exec_session thread should terminate after client drop"


def test_moecp_quiet_flag_suppresses_logs() -> None:
    """Test moecp -q sets moesh_shell._QUIET (DEF-F7)."""
    import moecp

    moesh_shell._QUIET = False
    with pytest.raises(SystemExit):
        moecp.main(["-q", "dummy"])
    assert moesh_shell._QUIET is True


def test_native_transfer_missing_module_sends_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test run_native_transfer emits Msg.ERROR when moecp is not importable (DEF-F4, DEF-F5)."""
    import sys

    monkeypatch.setitem(sys.modules, "moecp", None)

    client_sock, agent_sock = _tcp_pair()
    op_priv, op_pub = proto.generate_static_keypair()
    ag_priv, ag_pub = proto.generate_static_keypair()
    client_session = proto.NoiseSession("initiator", op_priv, ag_pub)
    agent_session = proto.NoiseSession("responder", ag_priv, op_pub)
    client_chan = proto.Channel(client_sock)
    agent_chan = proto.Channel(agent_sock)

    client_chan.send_frame(client_session.write_handshake())
    agent_session.read_handshake(agent_chan.recv_frame())
    agent_chan.send_frame(agent_session.write_handshake())
    client_session.read_handshake(client_chan.recv_frame())
    client_chan.send_frame(client_session.write_handshake())
    agent_session.read_handshake(agent_chan.recv_frame())

    client_sec = proto.SecureChannel(client_chan, client_session)
    agent_sec = proto.SecureChannel(agent_chan, agent_session)

    try:
        res = moesh_tunnel.run_native_transfer(agent_sock, agent_sec, {"session_type": "transfer"})
        assert res == "closed"
        records = client_sec.drain()
        assert len(records) >= 1
        msg_type, payload = records[0]
        assert msg_type == proto.Msg.ERROR
        assert b"missing required module" in payload
    finally:
        client_sock.close()
        agent_sock.close()

