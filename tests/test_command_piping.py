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
    log_file = open(tmp_path / f"agent-{_ALPHA}.log", "wb")  # noqa: SIM115
    agent = subprocess.Popen(
        [AGENT_PYTHON, os.path.join(TUNNEL_DIR, "moesh_tunnel.py")],
        stdout=log_file,
        stderr=subprocess.STDOUT,
        env=env,
    )
    time.sleep(2.0)

    def client_env(host: str) -> dict[str, str]:
        cenv = dict(os.environ)
        cenv.update(
            {
                "MOESH_SHELL_ADDR": f"127.0.0.1:{operator_v2_port}",
                "MOESH_SHELL_KEYFILE": str(operator_keyfile),
                "MOESH_SHELL_HOSTS_FILE": str(pins),
                "MOESH_SHELL_HANDSHAKE_TIMEOUT": "10",
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
        timeout=15,
        check=False,
    )
    assert res.returncode == 0
    assert res.stdout.strip() == "e2e_piping_success"

    # Command 2: non-zero exit code
    res_fail = subprocess.run(
        [AGENT_PYTHON, client_bin, "-q", "-n", _ALPHA, "exit 77"],
        env=env,
        capture_output=True,
        timeout=15,
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
        timeout=15,
        check=False,
    )
    assert res.returncode == 0
    assert res.stdout == "beta\nbeta\n"
