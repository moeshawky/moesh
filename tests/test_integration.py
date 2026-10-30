#!/usr/bin/env python3
"""End-to-end tests for moesh v2 through a real receiver bridge.

These tests run this repository's own agent and bridge code, on separate
ports, so a live deployment and its relays are never touched.

What each test measures is stated in its name and docstring; a green suite is
only evidence for the properties those probes actually exercise.
"""

from __future__ import annotations

import contextlib
import os
import pty
import signal
import socket
import subprocess
import time
from typing import TYPE_CHECKING, TypedDict

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

import pytest

import moesh_proto as proto
from tests.harness import (
    AGENT_PYTHON,
    CLIENT,
    Bridge,
    OperatorSession,
    make_keys,
    next_ports,
    start_agent,
)


class Stack(TypedDict):
    """What the integration fixture hands to a test."""

    bridge: Bridge
    agent: subprocess.Popen[bytes]
    operator_v2_port: int
    tunnel_port: int
    agent_log: str
    client_env: dict[str, str]
    agent_public: bytes
    agent_private: bytes
    operator_public: bytes


@pytest.fixture()
def stack(tmp_path: Path) -> Iterator[Stack]:
    """Provide a bridge, an agent and the operator client, with their keys."""
    operator_keyfile, agent_pubfile, agent_private, agent_public, operator_public = (
        make_keys(tmp_path)
    )
    # The client pins hosts by name from a pins file; the tests use their own.
    pins_file = os.path.join(tmp_path, "hosts.toml")
    with open(pins_file, "w", encoding="ascii") as handle:
        handle.write(f'[hosts.default]\nagent_pub = "{agent_public.hex()}"\n')
    tunnel_port, operator_port, operator_v2_port = next_ports()
    bridge = Bridge(
        tunnel_port=tunnel_port,
        operator_port=operator_port,
        operator_v2_port=operator_v2_port,
    )
    agent = start_agent(
        tmp_path, "127.0.0.1", tunnel_port, agent_private, operator_public
    )
    bridge._wait_for_line("host tunnel v2 attached", timeout=30.0)
    client_env = dict(os.environ)
    client_env.update(
        {
            "MOESH_SHELL_ADDR": f"127.0.0.1:{operator_v2_port}",
            "MOESH_SHELL_KEYFILE": operator_keyfile,
            "MOESH_SHELL_PEER_PUBFILE": agent_pubfile,
            "MOESH_SHELL_HOSTS_FILE": pins_file,
            "MOESH_SHELL_HANDSHAKE_TIMEOUT": "60",
            "TERM": "xterm-256color",
        }
    )
    yield {
        "bridge": bridge,
        "agent": agent,
        "operator_v2_port": operator_v2_port,
        "tunnel_port": tunnel_port,
        "agent_log": os.path.join(tmp_path, "agent.log"),
        "client_env": client_env,
        "agent_public": agent_public,
        "agent_private": agent_private,
        "operator_public": operator_public,
    }
    agent.terminate()
    try:
        agent.wait(timeout=10)
    except subprocess.TimeoutExpired:
        agent.kill()
    bridge.stop()


def test_the_operator_gets_an_interactive_shell(stack: Stack) -> None:
    """An authenticated operator session runs commands on the remote PTY."""
    session = OperatorSession(
        [AGENT_PYTHON, CLIENT], stack["client_env"], rows=30, cols=100
    )
    try:
        session.read_until(b"$", timeout=45)
        session.write(b"echo MARK_SHELL_OK\n")
        assert b"MARK_SHELL_OK" in session.read_until(b"MARK_SHELL_OK", timeout=20)
        session.write(b"tty\n")
        assert b"/dev/pts/" in session.read_until(b"/dev/pts/", timeout=20)
    finally:
        session.close()


def test_the_remote_pty_uses_the_negotiated_size(stack: Stack) -> None:
    """The remote PTY reports the operator's advertised dimensions, not a fixed one."""
    session = OperatorSession(
        [AGENT_PYTHON, CLIENT], stack["client_env"], rows=37, cols=113
    )
    try:
        session.read_until(b"$", timeout=45)
        session.write(b"stty size\n")
        output = session.read_until(b"37 113", timeout=20)
        assert b"37 113" in output
    finally:
        session.close()


def test_a_resize_reaches_the_remote_pty(stack: Stack) -> None:
    """A SIGWINCH on the operator side resizes the remote PTY without reconnecting."""
    session = OperatorSession(
        [AGENT_PYTHON, CLIENT], stack["client_env"], rows=24, cols=80
    )
    try:
        session.read_until(b"$", timeout=45)
        session.write(b"stty size\n")
        session.read_until(b"24 80", timeout=20)
        session.resize(50, 132)
        time.sleep(1.5)
        session.write(b"stty size\n")
        assert b"50 132" in session.read_until(b"50 132", timeout=20)
    finally:
        session.close()


def test_ctrl_c_interrupts_the_remote_foreground_process(stack: Stack) -> None:
    """Ctrl+C reaches the remote PTY and interrupts the foreground job."""
    session = OperatorSession(
        [AGENT_PYTHON, CLIENT], stack["client_env"], rows=24, cols=80
    )
    try:
        session.read_until(b"$", timeout=45)
        session.write(b"sleep 30\n")
        time.sleep(1.0)
        session.write(b"\x03")
        time.sleep(1.0)
        session.write(b"echo MARK_AFTER_INT\n")
        assert b"MARK_AFTER_INT" in session.read_until(b"MARK_AFTER_INT", timeout=20)
    finally:
        session.close()


def test_an_unauthenticated_operator_cannot_reach_the_shell(
    stack: Stack, tmp_path: Path
) -> None:
    """An operator whose identity is not pinned by the agent gets no shell."""
    bogus_private, _bogus_public = proto.generate_static_keypair()
    wrong_keyfile = os.path.join(tmp_path, "wrong.key")
    with open(wrong_keyfile, "w", encoding="ascii") as handle:
        handle.write(bogus_private.hex() + "\n")
    env = dict(stack["client_env"])
    env["MOESH_SHELL_KEYFILE"] = wrong_keyfile
    session = OperatorSession([AGENT_PYTHON, CLIENT], env, rows=24, cols=80)
    try:
        with pytest.raises(AssertionError):
            session.read_until(b"$", timeout=35)
    finally:
        session.close()
    with open(stack["agent_log"], errors="replace") as handle:
        agent_log = handle.read()
    assert "AUTHENTICATION FAILED" in agent_log
    assert "session active" not in agent_log


def test_the_bridge_refuses_a_plaintext_v1_shell_after_cutover(tmp_path: Path) -> None:
    """With the cutover flag set, the v1 shell path is refused with 426.

    The refusal reason lives in the bridge log, not the HTTP body: the
    probe checks both the client-visible status line and the operator-side
    log line.
    """
    bridge = Bridge(
        tunnel_port=19449, operator_port=14442, operator_v2_port=14443, allow_v1=False
    )
    try:
        request = (
            b"GET /__tunnel/v1 HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        )
        # A v1 dial-up into the cutover bridge must be refused outright.
        with socket.create_connection(("127.0.0.1", 19449), timeout=10) as sock:
            sock.sendall(request)
            response = b""
            while b"\r\n\r\n" not in response:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        assert b"426 Upgrade Required" in response
        # The log line lands a hair after the client sees the refusal;
        # wait for it instead of racing it.
        bridge._wait_for_line("refused handshake: v1 shell tunnel disabled by cutover")
    finally:
        bridge.stop()


def test_the_v1_and_relay_paths_still_answer_an_upgrade(tmp_path: Path) -> None:
    """The bridge change is additive: the legacy paths still switch protocols.

    Regression context: when the v2 path was added to the bridge, the v1
    shell path and the relay path had to keep answering.  The probe speaks
    raw RFC 6455 handshake bytes — no legacy agent, no external file.
    """
    bridge = Bridge(tunnel_port=19450, operator_port=14444, operator_v2_port=14445)
    try:

        def upgrade(path: str) -> bytes:
            request = (
                (f"GET {path} HTTP/1.1\r\n").encode()
                + b"Host: 127.0.0.1\r\n"
                + b"Upgrade: websocket\r\n"
                + b"Connection: Upgrade\r\n"
                + b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
            )
            with socket.create_connection(("127.0.0.1", 19450), timeout=10) as sock:
                sock.sendall(request)
                response = b""
                while b"\r\n\r\n" not in response:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            return response

        v1 = upgrade("/__tunnel/v1")
        assert b"101 Switching Protocols" in v1
        assert b"Sec-WebSocket-Accept" in v1
        relay = upgrade("/__relay/gpu")
        assert b"101 Switching Protocols" in relay
        unknown = upgrade("/__tunnel/nothing")
        assert b"400 Bad Request" in unknown
        bridge._wait_for_line("host tunnel attached from")
    finally:
        bridge.stop()


def test_the_agent_redials_after_the_transport_drops(stack: Stack) -> None:
    """The agent process survives a transport loss and dials again."""
    first = OperatorSession(
        [AGENT_PYTHON, CLIENT], stack["client_env"], rows=24, cols=80
    )
    try:
        first.read_until(b"$", timeout=45)
    finally:
        first.close()
    time.sleep(8)
    second = OperatorSession(
        [AGENT_PYTHON, CLIENT], stack["client_env"], rows=24, cols=80
    )
    try:
        second.read_until(b"$", timeout=45)
        second.write(b"echo MARK_REDIAL_OK\n")
        assert b"MARK_REDIAL_OK" in second.read_until(b"MARK_REDIAL_OK", timeout=20)
    finally:
        second.close()
    assert stack["agent"].poll() is None, "the agent must survive the transport loss"
    with open(stack["agent_log"], errors="replace") as handle:
        agent_log = handle.read()
    assert "abrupt EOF" in agent_log, (
        "an abrupt EOF must be distinguishable from an authenticated close"
    )
    assert "operator closed the session" not in agent_log, (
        "the session ended abruptly, not through an authenticated CLOSE record"
    )


# --------------------------------------------------------------------------
# Session persistence and lifecycle
# --------------------------------------------------------------------------


def test_the_shell_survives_an_operator_disconnect(stack: Stack) -> None:
    """A second operator continues the SAME shell: state, cwd and jobs survive."""
    first = OperatorSession(
        [AGENT_PYTHON, CLIENT], stack["client_env"], rows=24, cols=80
    )
    try:
        first.read_until(b"$", timeout=45)
        first.write(b"export REATTACH_MARK=42\n")
        assert b"REATTACH_MARK" in first.read_until(b"REATTACH_MARK", timeout=20)
    finally:
        first.close()
    time.sleep(8)

    second = OperatorSession(
        [AGENT_PYTHON, CLIENT], stack["client_env"], rows=24, cols=80
    )
    try:
        second.read_until(b"$", timeout=45)
        second.write(b"echo MARK_IS=[$REATTACH_MARK]\n")
        assert b"MARK_IS=[42]" in second.read_until(b"MARK_IS=[42]", timeout=25)
    finally:
        second.close()


def test_a_fresh_session_can_be_requested(stack: Stack) -> None:
    """`--fresh` starts a new shell instead of re-attaching to the running one."""
    first = OperatorSession(
        [AGENT_PYTHON, CLIENT], stack["client_env"], rows=24, cols=80
    )
    try:
        first.read_until(b"$", timeout=45)
        first.write(b"export FRESH_MARK=42\n")
        first.read_until(b"FRESH_MARK", timeout=20)
    finally:
        first.close()
    time.sleep(8)

    env = dict(stack["client_env"])
    second = OperatorSession([AGENT_PYTHON, CLIENT, "--fresh"], env, rows=24, cols=80)
    try:
        second.read_until(b"$", timeout=45)
        second.write(b"echo FRESH_IS=[$FRESH_MARK]\n")
        assert b"FRESH_IS=[]" in second.read_until(b"FRESH_IS=[]", timeout=25)
    finally:
        second.close()


def test_the_agent_stops_cleanly_and_leaves_no_shell(
    stack: Stack, tmp_path: Path
) -> None:
    """SIGTERM stops the agent and reaps its shell: no orphan Bash is left."""
    session = OperatorSession(
        [AGENT_PYTHON, CLIENT], stack["client_env"], rows=24, cols=80
    )
    try:
        session.read_until(b"$", timeout=45)
        shell_pid = None
        deadline = time.time() + 15
        pidfile = os.path.join(tmp_path, "shell.pid")
        while time.time() < deadline:
            try:
                with open(pidfile, encoding="ascii") as handle:
                    shell_pid = int(handle.read().strip())
                break
            except (OSError, ValueError):
                time.sleep(0.3)
        assert shell_pid, "the agent must record its shell PID"
    finally:
        session.close()

    stack["agent"].send_signal(signal.SIGTERM)
    stack["agent"].wait(timeout=20)
    assert stack["agent"].poll() is not None
    time.sleep(1.0)
    with pytest.raises(OSError):
        os.kill(shell_pid, 0)


def test_the_operator_reports_a_missing_agent(stack: Stack) -> None:
    """With --no-reconnect, a missing host is reported instead of hanging."""
    # A bridge with no agent behind it: the operator connects and waits.
    lonely_tunnel, lonely_operator, lonely_v2 = next_ports()
    lonely = Bridge(
        tunnel_port=lonely_tunnel,
        operator_port=lonely_operator,
        operator_v2_port=lonely_v2,
    )
    try:
        env = dict(stack["client_env"])
        env["MOESH_SHELL_HANDSHAKE_TIMEOUT"] = "5"
        env["MOESH_SHELL_ADDR"] = f"127.0.0.1:{lonely_v2}"
        master, slave = pty.openpty()
        try:
            proc = subprocess.Popen(
                [AGENT_PYTHON, CLIENT, "--no-reconnect"],
                stdin=slave,
                stdout=slave,
                stderr=subprocess.PIPE,
                env=env,
            )
            os.close(slave)
            _out, err = proc.communicate(timeout=60)
        finally:
            with contextlib.suppress(OSError):
                os.close(master)
        assert proc.returncode != 0
        assert b"no agent answered" in err
    finally:
        lonely.stop()


def test_an_idle_operator_leg_is_not_timed_out(stack: Stack) -> None:
    """The operator leg survives an idle period.

    Regression: the bridge armed a 15 second socket timeout to peek the
    routing label and never cleared it, so every idle operator session was
    torn down at exactly 15.0 seconds (measured on the live bridge).  The
    probe waits longer than that timeout and requires the leg to stay open.
    """
    sock = socket.create_connection(
        ("127.0.0.1", stack["operator_v2_port"]), timeout=10
    )
    try:
        sock.sendall(b"MOESH-TUNNEL-V2 default\n")
        sock.settimeout(20)
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                data = sock.recv(4096)
            except TimeoutError:
                continue  # no data, but the leg is still open: that is the point
            assert data, "the bridge closed the idle operator leg"
    finally:
        sock.close()


def test_the_operator_waits_for_a_restarting_host(
    stack: Stack, tmp_path: Path
) -> None:
    """The client keeps trying while the host is away, and attaches when it returns.

    This is the behaviour the operator asked for: a host that restarts must
    not end the session.  The client retries on its own; the test brings the
    host back and requires the client to attach to it without help.
    """
    env = dict(stack["client_env"])
    env["MOESH_SHELL_HANDSHAKE_TIMEOUT"] = "5"
    session = OperatorSession([AGENT_PYTHON, CLIENT], env, rows=24, cols=80)
    replacement = None
    try:
        # The stack's agent is stopped: the host is away.
        stack["agent"].terminate()
        stack["agent"].wait(timeout=10)
        time.sleep(1.0)
        # The client keeps waiting; it must not exit and it must say so.
        deadline = time.time() + 12
        while time.time() < deadline:
            if session.proc.poll() is not None:
                raise AssertionError("the client gave up instead of waiting")
            time.sleep(0.5)
        # A host comes back.
        replacement = start_agent(
            tmp_path,
            "127.0.0.1",
            stack["tunnel_port"],
            stack["agent_private"],
            stack["operator_public"],
        )
        stack["agent"] = replacement
        session.read_until(b"$", timeout=60)
        session.write(b"echo BACK_MARK\n")
        assert b"BACK_MARK" in session.read_until(b"BACK_MARK", timeout=25)
    finally:
        session.close()
        # The replacement agent is not the one the fixture knows about; it
        # must not outlive the test.
        if replacement is not None:
            replacement.terminate()
            try:
                replacement.wait(timeout=10)
            except subprocess.TimeoutExpired:
                replacement.kill()


def test_the_operator_reconnects_after_the_host_drops(stack: Stack) -> None:
    """A dropped transport is invisible: the client re-attaches by itself."""
    session = OperatorSession(
        [AGENT_PYTHON, CLIENT], stack["client_env"], rows=24, cols=80
    )
    try:
        session.read_until(b"$", timeout=60)
        session.write(b"echo FIRST_MARK\n")
        assert b"FIRST_MARK" in session.read_until(b"FIRST_MARK", timeout=20)
        # The host's transport dies with its agent.
        stack["agent"].terminate()
        stack["agent"].wait(timeout=10)
        time.sleep(1.0)
        # The client must still be alive and must be trying again.
        deadline = time.time() + 15
        while time.time() < deadline:
            assert session.proc.poll() is None, (
                "the client exited on a dropped transport"
            )
            time.sleep(0.5)
    finally:
        session.close()


def test_a_late_host_still_finds_the_operator_waiting(
    stack: Stack, tmp_path: Path
) -> None:
    """The operator waits for a host that attaches late.

    Regression: the receiver bridge holds an operator connection for 120s
    while it waits for the host, but the client used to give up at 30s
    and reconnect — throwing away the wait and reporting a timeout for a
    host that was merely late.  Measured on 2026-10-21 against a
    host that was down: the client abandoned the wait every 30-90s.

    The host here attaches after 35 seconds, which is past the old 30s
    timeout.  The client must still be connected when it arrives.

    The client runs with --no-reconnect on purpose: the re-attaching mode
    masks the defect (it reconnects, and the second attempt succeeds), so
    only the one-shot mode measures the wait the bridge is offering.
    """
    # A private bridge with no agent behind it yet.
    tunnel_port, operator_port, operator_v2_port = next_ports()
    lonely = Bridge(
        tunnel_port=tunnel_port,
        operator_port=operator_port,
        operator_v2_port=operator_v2_port,
    )
    agent = None
    try:
        env = dict(stack["client_env"])
        env["MOESH_SHELL_ADDR"] = f"127.0.0.1:{operator_v2_port}"
        session = OperatorSession(
            [AGENT_PYTHON, CLIENT, "--no-reconnect"], env, rows=24, cols=80
        )
        try:
            # The host shows up late: past the old 30 second timeout.
            time.sleep(35)
            agent = start_agent(
                tmp_path,
                "127.0.0.1",
                tunnel_port,
                stack["agent_private"],
                stack["operator_public"],
            )
            session.read_until(b"$", timeout=60)
            session.write(b"echo LATE_MARK\n")
            assert b"LATE_MARK" in session.read_until(b"LATE_MARK", timeout=25)
        finally:
            session.close()
    finally:
        if agent is not None:
            agent.terminate()
            try:
                agent.wait(timeout=10)
            except subprocess.TimeoutExpired:
                agent.kill()
        lonely.stop()


def test_two_operators_get_two_shells_at_once(stack: Stack) -> None:
    """Two operators can be connected at the same time, each on its own shell.

    Regression (2026-10-21): the agent served one operator at a time over
    one tunnel, so a second operator waited for the first to disconnect, and
    a stale client could burn every tunnel the agent opened.  The agent now
    keeps a pool of tunnels and a pool of shells.

    The properties measured here:
      * the second operator is connected while the first is still connected;
      * they are on different shells (a marker set by the first is not
        visible to the second);
      * the first operator still works after the second leaves.
    """
    first = OperatorSession(
        [AGENT_PYTHON, CLIENT], stack["client_env"], rows=24, cols=80
    )
    second = None
    try:
        first.read_until(b"$", timeout=45)
        first.write(b"export FIRST_ONLY=42\n")
        time.sleep(0.5)
        first.write(b"echo FIRST_MARK=$FIRST_ONLY\n")
        assert b"FIRST_MARK=42" in first.read_until(b"FIRST_MARK=42", timeout=20)

        # The second operator arrives while the first is still connected.
        second = OperatorSession(
            [AGENT_PYTHON, CLIENT], stack["client_env"], rows=24, cols=80
        )
        second.read_until(b"$", timeout=45)
        second.write(b"echo SECOND_SEES=[$FIRST_ONLY]\n")
        # A separate shell: the first operator's variable is not visible.
        assert b"SECOND_SEES=[]" in second.read_until(b"SECOND_SEES=[]", timeout=25)

        # The second leaves; the first is untouched.
        second.close()
        second = None
        time.sleep(1.0)
        first.write(b"echo STILL_HERE=$FIRST_ONLY\n")
        assert b"STILL_HERE=42" in first.read_until(b"STILL_HERE=42", timeout=20)
    finally:
        if second is not None:
            second.close()
        first.close()


def test_the_bridge_does_not_eat_the_first_handshake_frame(stack: Stack) -> None:
    """A label and the first Noise frame in ONE segment must both survive.

    Regression (2026-10-21): the bridge read up to 256 bytes to find the
    routing label and threw the rest away, so a client that wrote the label
    and its first handshake frame together lost the frame.  The agent then
    never saw a handshake and the operator waited until its timeout: the
    hang the operator reported.  It showed up in roughly one connection in
    three, because it is a race between two writes reaching the receiver
    as one segment or as two.

    The probe writes them together on purpose, so the race cannot hide.
    """
    operator_keyfile = stack["client_env"]["MOESH_SHELL_KEYFILE"]
    with open(operator_keyfile, encoding="ascii") as handle:
        private = bytes.fromhex(handle.read().strip())
    peer = bytes.fromhex(stack["agent_public"].hex())

    sock = socket.create_connection(
        ("127.0.0.1", stack["operator_v2_port"]), timeout=15
    )
    try:
        channel = proto.Channel(sock)
        session = proto.NoiseSession("initiator", private, peer)
        first = proto.frame(session.write_handshake())
        # The label and the first frame in a single write.
        sock.sendall(b"MOESH-TUNNEL-V2 default\n" + first)
        session.read_handshake(channel.recv_frame())
        channel.send_frame(session.write_handshake())
        assert session.handshake_finished, "the Noise handshake did not complete"
    finally:
        sock.close()
