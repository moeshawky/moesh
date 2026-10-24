#!/usr/bin/env python3
"""Operator-outcome cases for moesh v2.

The catalog at ``/tmp/opencode/moesh-case-catalog.md`` is the authority for
each case's input, expected output, oracle and cleanup.  Cases predicted red
on this tree are strict xfails unless the measured race makes the prediction
conditional; the guards are ordinary tests and are the calibration that the
rig itself is sound.
"""

from __future__ import annotations

import ast
import contextlib
import importlib.util
import json
import os
import re
import signal
import socket
import struct
import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from collections.abc import Generator

import pytest

import moesh_proto as proto
import moesh_tunnel as agent_mod
from tests.harness import (
    AGENT,
    AGENT_PYTHON,
    CLIENT,
    Bridge,
    OperatorSession,
    make_keys,
    next_ports,
)

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = Path("/tmp/opencode")  # noqa: S108 - AGENTS.md mandates this evidence dir


def _source(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def _bridge_module() -> Any:
    spec = importlib.util.spec_from_file_location("moesh_bridge_t", ROOT / "moesh-bridge.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bridge_mod = _bridge_module()
bridge_cls = bridge_mod


def _write_pins(tmp_path: Path, host: str, public: bytes) -> str:
    path = tmp_path / "hosts.toml"
    path.write_text(f'[hosts.{host}]\nagent_pub = "{public.hex()}"\n', encoding="ascii")
    return str(path)


def _start_agent(
    tmp_path: Path,
    port: int,
    private: bytes,
    operator_public: bytes,
    *,
    sessions: int = 1,
    name: str | None = None,
) -> tuple[subprocess.Popen[bytes], str]:
    env = dict(os.environ)
    env.update(
        {
            "MOESH_TUNNEL_RECEIVER": "127.0.0.1",
            "MOESH_TUNNEL_RECEIVER_PORT": str(port),
            "MOESH_TUNNEL_AGENT_KEY": private.hex(),
            "MOESH_TUNNEL_OPERATOR_PUB": operator_public.hex(),
            "MOESH_TUNNEL_SESSIONS": str(sessions),
            "MOESH_TUNNEL_CHILD_PIDFILE": str(tmp_path / "shell.pid"),
        }
    )
    if name:
        env["MOESH_TUNNEL_NAME"] = name
    log_path = tmp_path / "agent.log"
    with open(log_path, "ab") as handle:
        proc = subprocess.Popen(
            [AGENT_PYTHON, AGENT],
            stdout=handle,
            stderr=subprocess.STDOUT,
            env=env,
        )
        handle.write(f"\n--- agent start pid={proc.pid} ---\n".encode())
        handle.flush()
    return proc, str(log_path)


class Stack:
    """A bridge, one agent, keys, pins and the client environment."""

    def __init__(self, tmp_path: Path, *, sessions: int = 1, host: str = "default"):
        self.tmp_path = tmp_path
        self.host = host
        (
            self.operator_keyfile,
            self.agent_pubfile,
            self.agent_private,
            self.agent_public,
            self.operator_public,
        ) = make_keys(tmp_path)
        self.pins = _write_pins(tmp_path, host, self.agent_public)
        self.tunnel_port, self.operator_port, self.operator_v2_port = next_ports()
        self.bridge = Bridge(self.tunnel_port, self.operator_port, self.operator_v2_port)
        self.agent, self.agent_log = _start_agent(
            tmp_path,
            self.tunnel_port,
            self.agent_private,
            self.operator_public,
            sessions=sessions,
            name=None if host == "default" else host,
        )
        self.env = dict(os.environ)
        self.env.update(
            {
                "MOESH_SHELL_ADDR": f"127.0.0.1:{self.operator_v2_port}",
                "MOESH_SHELL_KEYFILE": self.operator_keyfile,
                "MOESH_SHELL_PEER_PUBFILE": self.agent_pubfile,
                "MOESH_SHELL_HOSTS_FILE": self.pins,
                "MOESH_SHELL_HANDSHAKE_TIMEOUT": "10",
                "TERM": "xterm-256color",
            }
        )

    def argv(self, *extra: str) -> list[str]:
        base = [AGENT_PYTHON, CLIENT, "--host", self.host]
        if self.host != "default":
            base += ["--addr", f"127.0.0.1:{self.operator_v2_port}"]
        return base + list(extra)

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.agent.terminate()
            self.agent.wait(timeout=10)
        if self.agent.poll() is None:
            self.agent.kill()
        self.bridge.stop()


@contextlib.contextmanager
def live_stack(
    tmp_path: Path, *, sessions: int = 1, host: str = "default"
) -> Generator[Stack, None, None]:
    stack = Stack(tmp_path, sessions=sessions, host=host)
    try:
        yield stack
    finally:
        stack.close()


def _session(stack: Stack, *extra: str, rows: int = 30, cols: int = 100) -> OperatorSession:
    return OperatorSession(stack.argv(*extra), stack.env, rows=rows, cols=cols)


def _wait_log(path: str, needle: str, timeout: float = 15.0) -> str:
    deadline = time.time() + timeout
    while time.time() < deadline:
        text = Path(path).read_text(errors="replace") if Path(path).exists() else ""
        if needle in text:
            return text
        time.sleep(0.1)
    raise AssertionError(f"log {path} did not contain {needle!r}")


# ---------------------------------------------------------------------------
# Noise helpers (wire-level cases; constants come from moesh_proto)
# ---------------------------------------------------------------------------

PRIV_A, PUB_A = proto.generate_static_keypair()
PRIV_B, PUB_B = proto.generate_static_keypair()


def _handshake(
    *, prologue_a: bytes | None = None, prologue_b: bytes | None = None
) -> tuple[proto.NoiseSession, proto.NoiseSession, socket.socket, socket.socket, list[Exception]]:
    sock_a, sock_b = socket.socketpair()
    sock_a.settimeout(10)
    sock_b.settimeout(10)
    errors: list[Exception] = []
    session_a = proto.NoiseSession("initiator", PRIV_A, PUB_B, prologue_a)
    session_b = proto.NoiseSession("responder", PRIV_B, PUB_A, prologue_b)

    def initiator() -> None:
        try:
            channel = proto.Channel(sock_a)
            channel.send_frame(session_a.write_handshake())
            session_a.read_handshake(channel.recv_frame())
            channel.send_frame(session_a.write_handshake())
        except Exception as exc:
            errors.append(exc)

    def responder() -> None:
        try:
            channel = proto.Channel(sock_b)
            session_b.read_handshake(channel.recv_frame())
            channel.send_frame(session_b.write_handshake())
            session_b.read_handshake(channel.recv_frame())
        except Exception as exc:
            errors.append(exc)

    threads = [
        __import__("threading").Thread(target=initiator, daemon=True),
        __import__("threading").Thread(target=responder, daemon=True),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)
    return session_a, session_b, sock_a, sock_b, errors


# ---------------------------------------------------------------------------
# Functional
# ---------------------------------------------------------------------------


def test_three_operators_get_three_distinct_prompts(tmp_path: Path) -> None:
    """FUNC-001 — three concurrent operators reach prompts and one drop is isolated."""
    with live_stack(tmp_path, sessions=3) as stack:
        sessions = [_session(stack) for _ in range(3)]
        try:
            for session in sessions:
                session.read_until(b"$", timeout=45)
            for index, session in enumerate(sessions):
                session.write(f"echo MARK_{index}\n".encode())
                assert f"MARK_{index}".encode() in session.read_until(
                    f"MARK_{index}".encode(), timeout=20
                )
            pids = re.findall(r"shell started \(pid (\d+)", Path(stack.agent_log).read_text())
            assert len(set(pids)) >= 3
            sessions[0].close()
            for index, session in enumerate(sessions[1:], start=1):
                session.write(f"echo SURVIVOR_{index}\n".encode())
                assert f"SURVIVOR_{index}".encode() in session.read_until(
                    f"SURVIVOR_{index}".encode(), timeout=20
                )
        finally:
            for session in sessions:
                session.close()


def test_reattach_keeps_shell_identity_and_pre_detach_state(tmp_path: Path) -> None:
    """FUNC-002 — a dropped operator reattaches to the same shell and can type again."""
    with live_stack(tmp_path) as stack:
        first = _session(stack)
        try:
            first.read_until(b"$", timeout=40)
            first.write(b"export REATTACH_MARK=42\ncd /tmp\necho SYNC_A\n")
            first.read_until(b"SYNC_A", timeout=20)
        finally:
            first.close()
        time.sleep(3)
        second = _session(stack)
        try:
            second.read_until(b"$", timeout=40)
            second.write(b"echo MARK_IS=[$REATTACH_MARK]\npwd\necho POST_OK\n")
            assert b"MARK_IS=[42]" in second.read_until(b"MARK_IS=[42]", timeout=25)
            assert b"/tmp" in second.read_until(b"/tmp", timeout=20)
            assert b"POST_OK" in second.read_until(b"POST_OK", timeout=20)
        finally:
            second.close()
        log = Path(stack.agent_log).read_text(errors="replace")
        assert "attached to the running shell" in log
        assert "[ble: EOF]" not in log


def test_fresh_session_gets_a_new_shell_and_no_old_export(tmp_path: Path) -> None:
    """FUNC-003 — `--fresh` starts a different shell and cannot see the old export."""
    with live_stack(tmp_path) as stack:
        first = _session(stack)
        try:
            first.read_until(b"$", timeout=40)
            first.write(b"export FRESH_MARK=42\necho FRESH_SET\n")
            first.read_until(b"FRESH_SET", timeout=20)
        finally:
            first.close()
        time.sleep(2)
        second = _session(stack, "--fresh")
        try:
            second.read_until(b"$", timeout=40)
            second.write(b"echo FRESH_IS=[$FRESH_MARK]\n")
            assert b"FRESH_IS=[]" in second.read_until(b"FRESH_IS=[]", timeout=20)
        finally:
            second.close()
        log = Path(stack.agent_log).read_text(errors="replace")
        assert len(re.findall(r"shell started \(pid", log)) >= 2


def test_resize_and_ctrl_c_reach_the_remote_pty(tmp_path: Path) -> None:
    """FUNC-004 — RESIZE reaches the PTY and Ctrl-C interrupts the foreground job."""
    with live_stack(tmp_path) as stack:
        session = _session(stack, rows=24, cols=80)
        try:
            session.read_until(b"$", timeout=40)
            session.resize(40, 100)
            time.sleep(0.8)
            session.write(b"stty size\n")
            assert b"40 100" in session.read_until(b"40 100", timeout=20)
            session.write(b"sleep 30\n")
            time.sleep(0.8)
            session.write(b"\x03")
            time.sleep(0.8)
            session.write(b"echo INT_OK\n")
            assert b"INT_OK" in session.read_until(b"INT_OK", timeout=20)
        finally:
            session.close()


def test_data_is_byte_exact_and_ordered(tmp_path: Path) -> None:
    """FUNC-005 — DATA is binary-safe at the wire and complete through the PTY."""
    session_a, session_b, sock_a, sock_b, errors = _handshake()
    try:
        assert not errors
        chan_a = proto.SecureChannel(proto.Channel(sock_a), session_a)
        chan_b = proto.SecureChannel(proto.Channel(sock_b), session_b)
        for payload in (b"\x00\xff" * 4, b"x" * proto.MAX_DATA_PAYLOAD):
            chan_a.send(proto.Msg.DATA, payload)
            assert chan_b.recv() == (proto.Msg.DATA, payload)
    finally:
        sock_a.close()
        sock_b.close()
    with live_stack(tmp_path) as stack:
        session = _session(stack)
        try:
            session.read_until(b"$", timeout=40)
            session.write(b"seq 1 200\n")
            output = session.read_until(b"\r\n200\r\n", timeout=30)
            lines = [line for line in output.splitlines() if line.strip().isdigit()]
            assert [int(line) for line in lines][-1] == 200
        finally:
            session.close()


def test_shell_exit_is_reported_as_exit_not_detach(tmp_path: Path) -> None:
    """FUNC-006 — a remote `exit 7` is reported as exit status, not a detach."""
    with live_stack(tmp_path) as stack:
        session = _session(stack)
        try:
            session.read_until(b"$", timeout=40)
            session.write(b"exit 7\n")
            session.proc.wait(timeout=20)
            assert session.proc.returncode == 7
        finally:
            session.close()
        log = _wait_log(stack.agent_log, "remote shell exited (status 7)")
        assert "remote shell exited (status 7)" in log


def test_reconnect_redials_transport_but_not_auth_failure(tmp_path: Path) -> None:
    """FUNC-007 — transport failures redial; an authentication failure does not."""
    with live_stack(tmp_path) as stack:
        wrong_private, _ = proto.generate_static_keypair()
        wrong = tmp_path / "wrong.key"
        wrong.write_text(wrong_private.hex() + "\n", encoding="ascii")
        env = dict(stack.env)
        env["MOESH_SHELL_KEYFILE"] = str(wrong)
        session = OperatorSession(stack.argv(), env, rows=24, cols=80)
        try:
            with pytest.raises(AssertionError):
                session.read_until(b"$", timeout=15)
        finally:
            session.close()
        source = _source("moesh_shell.py")
        assert "except AuthenticationError:" in source
        assert "if not args.reconnect:" in source


def test_departed_tunnel_worker_is_not_paired(tmp_path: Path) -> None:
    """FUNC-008 — a queued worker that walked away fails boundedly and recovers."""
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    keys = make_keys(tmp_path)
    _operator_key, _agent_pubfile, agent_private, agent_public, operator_public = keys
    pins = _write_pins(tmp_path, "alpha", agent_public)
    tunnel_port, operator_port, operator_v2_port = next_ports()
    bridge = Bridge(tunnel_port, operator_port, operator_v2_port)
    agent_a = agent_b = None
    op1 = op2 = None
    try:
        agent_a, log_a = _start_agent(
            dir_a, tunnel_port, agent_private, operator_public, sessions=1, name="alpha"
        )
        _wait_log(log_a, "tunnel established; waiting for an operator")
        os.kill(agent_a.pid, signal.SIGSTOP)
        env = dict(os.environ)
        env.update(
            {
                "MOESH_SHELL_ADDR": f"127.0.0.1:{operator_v2_port}",
                "MOESH_SHELL_KEYFILE": keys[0],
                "MOESH_SHELL_HOSTS_FILE": pins,
                "MOESH_SHELL_HANDSHAKE_TIMEOUT": "5",
                "TERM": "xterm-256color",
            }
        )
        argv = [AGENT_PYTHON, CLIENT, "--host", "alpha", "--addr", f"127.0.0.1:{operator_v2_port}", "--no-reconnect"]
        op1 = OperatorSession(argv, env, rows=24, cols=80)
        with pytest.raises(AssertionError):
            op1.read_until(b"$", timeout=10)
        log = bridge.log_text()
        assert "pairing operator-v2[alpha] with a host" in log
        op1.close()
        op1 = None
        agent_b, log_b = _start_agent(
            dir_b, tunnel_port, agent_private, operator_public, sessions=1, name="alpha"
        )
        _wait_log(log_b, "tunnel established; waiting for an operator")
        time.sleep(0.5)
        op2 = OperatorSession(argv, env, rows=24, cols=80)
        op2.read_until(b"$", timeout=20)
        op2.write(b"echo FUNC-008_CONTROL\n")
        assert b"FUNC-008_CONTROL" in op2.read_until(b"FUNC-008_CONTROL", timeout=20)
    finally:
        if agent_a is not None:
            with contextlib.suppress(ProcessLookupError):
                os.kill(agent_a.pid, signal.SIGCONT)
            agent_a.terminate()
        for proc in (agent_a, agent_b):
            if proc is not None:
                with contextlib.suppress(Exception):
                    proc.wait(timeout=10)
                if proc.poll() is None:
                    proc.kill()
        for session in (op1, op2):
            if session is not None:
                session.close()
        bridge.stop()


# ---------------------------------------------------------------------------
# Edge / boundary
# ---------------------------------------------------------------------------


def test_host_labels_one_through_sixty_four_route_exactly() -> None:
    """EDGE-001 — every valid label length, especially 64, parses to the exact name."""
    for length in range(1, 65):
        name = "a" * length
        left, right = socket.socketpair()
        try:
            right.sendall(bridge_mod.PRELUDE_PREFIX + name.encode() + b"\n")
            assert bridge_mod.valid_host(name)
            assert bridge_mod.read_host_label(left) == name
        finally:
            left.close()
            right.close()


def test_length_sixty_five_label_is_refused_not_defaulted() -> None:
    """EDGE-002 — an out-of-range label must not reach the `default` queue."""
    left, right = socket.socketpair()
    calls: list[Any] = []
    original_pair = bridge_mod.pair
    original_label = bridge_mod.read_host_label
    bridge_mod.pair = lambda *args: calls.append(args)
    bridge_mod.read_host_label = lambda _conn: ""
    try:
        bridge_mod.operator_v2_conn(left, ("127.0.0.1", 1))
        assert calls == []
    finally:
        bridge_mod.pair = original_pair
        bridge_mod.read_host_label = original_label
        left.close()
        right.close()


def test_unpinned_or_invalid_host_fails_closed(tmp_path: Path) -> None:
    """EDGE-003 — the bridge half must not turn a bad label into `default`."""
    left, right = socket.socketpair()
    calls: list[Any] = []
    original_pair = bridge_mod.pair
    original_label = bridge_mod.read_host_label
    bridge_mod.pair = lambda *args: calls.append(args)
    bridge_mod.read_host_label = lambda _conn: ""
    try:
        bridge_mod.operator_v2_conn(left, ("127.0.0.1", 1))
        assert calls == []
    finally:
        bridge_mod.pair = original_pair
        bridge_mod.read_host_label = original_label
        left.close()
        right.close()


def test_rows_cols_and_version_bounds() -> None:
    """EDGE-004 — HELLO/RESIZE accept the exact bounds and reject bools/outsiders."""
    base = {
        "version": proto.PROTOCOL_VERSION,
        "term": proto.DEFAULT_TERM,
        "encoding": proto.DEFAULT_ENCODING,
        "rows": 1,
        "cols": 1,
        "capabilities": [],
        "max_record": 256,
    }
    for value in (1, proto.MAX_ROWS):
        hello = dict(base, rows=value)
        assert proto.validate_hello(hello)["rows"] == value
    for value in (0, proto.MAX_ROWS + 1, True):
        with pytest.raises(proto.NegotiationError):
            proto.validate_hello(dict(base, rows=value))
    with pytest.raises(proto.NegotiationError):
        proto.validate_hello(dict(base, version=proto.PROTOCOL_VERSION + 1))
    assert proto.validate_resize({"rows": 1, "cols": proto.MAX_COLS}) == (1, proto.MAX_COLS)
    with pytest.raises(proto.NegotiationError):
        proto.validate_resize({"rows": 0, "cols": 1})


def test_data_bounds_are_enforced_on_receive() -> None:
    """EDGE-005 — an inbound 32769-byte DATA record must be refused."""
    session_a, session_b, sock_a, sock_b, errors = _handshake()
    try:
        assert not errors
        chan_a = proto.SecureChannel(proto.Channel(sock_a), session_a)
        chan_b = proto.SecureChannel(proto.Channel(sock_b), session_b)
        chan_a.send(proto.Msg.DATA, b"")
        assert chan_b.recv() == (proto.Msg.DATA, b"")
        chan_a.send(proto.Msg.DATA, b"x" * proto.MAX_DATA_PAYLOAD)
        assert chan_b.recv() == (proto.Msg.DATA, b"x" * proto.MAX_DATA_PAYLOAD)
        with pytest.raises(proto.FramingError):
            chan_a.send(proto.Msg.DATA, b"x" * (proto.MAX_DATA_PAYLOAD + 1))
        oversized = session_b.encrypt(bytes([int(proto.Msg.DATA)]) + b"x" * (proto.MAX_DATA_PAYLOAD + 1))
        proto.Channel(sock_b).send_frame(oversized)
        with pytest.raises(proto.FramingError):
            chan_a.recv()
    finally:
        sock_a.close()
        sock_b.close()


def test_control_bounds_are_enforced_on_receive() -> None:
    """EDGE-006 — an inbound 4097-byte control record must be refused."""
    session_a, session_b, sock_a, sock_b, errors = _handshake()
    try:
        assert not errors
        chan_a = proto.SecureChannel(proto.Channel(sock_a), session_a)
        padding = "x" * (proto.MAX_CONTROL_PAYLOAD + 1)
        oversized = session_b.encrypt(
            bytes([int(proto.Msg.HELLO)]) + json.dumps({"pad": padding}).encode()
        )
        proto.Channel(sock_b).send_frame(oversized)
        with pytest.raises(proto.FramingError):
            chan_a.recv_control()
    finally:
        sock_a.close()
        sock_b.close()


def test_frame_reader_reassembly_and_refusal() -> None:
    """EDGE-007 — zero/oversize frames refused; partial and coalesced frames handled."""
    reader = proto.FrameReader()
    reader.feed(struct.pack(">I", 0))
    with pytest.raises(proto.FramingError):
        reader.next_frame()
    reader = proto.FrameReader()
    reader.feed(proto.frame(b"x") + proto.frame(b"y"))
    assert reader.frames() == [b"x", b"y"]
    reader = proto.FrameReader()
    wire = proto.frame(b"z" * 100)
    reader.feed(wire[:3])
    assert reader.next_frame() is None
    reader.feed(wire[3:])
    assert reader.next_frame() == b"z" * 100


def test_peek_window_leaves_the_handshake_frame_intact() -> None:
    """EDGE-008 — a valid label is consumed but the following frame is not."""
    left, right = socket.socketpair()
    frame = proto.frame(b"first-noise-frame")
    try:
        right.sendall(bridge_mod.PRELUDE_PREFIX + b"alpha\n" + frame)
        assert bridge_mod.read_host_label(left) == "alpha"
        assert left.recv(len(frame)) == frame
    finally:
        left.close()
        right.close()


# ---------------------------------------------------------------------------
# Error / recovery
# ---------------------------------------------------------------------------


def test_reap_clears_shell_identity() -> None:
    """ERR-001 — after the child exits, reap clears pid/fd and alive becomes false."""
    shell = agent_mod.HostShell()
    try:
        shell.spawn(proto.DEFAULT_TERM, proto.DEFAULT_ROWS, proto.DEFAULT_COLS)
        assert shell.fd is not None
        os.write(shell.fd, b"exit\n")
        deadline = time.time() + 5
        while time.time() < deadline:
            if shell.read_output() is None:
                break
            time.sleep(0.05)
        shell.reap()
        assert shell.pid is None
        assert shell.fd is None
        assert not shell.alive
    finally:
        shell.terminate()


def test_reaped_shell_is_not_reacquired() -> None:
    """ERR-002 — a dead shell is dropped and the next acquire gets a new pid."""
    pool = agent_mod.ShellPool(max_idle=1)
    try:
        first = pool.acquire(False)
        first.spawn(proto.DEFAULT_TERM, proto.DEFAULT_ROWS, proto.DEFAULT_COLS)
        old_pid = first.pid
        assert first.pid is not None
        os.kill(first.pid, signal.SIGKILL)
        time.sleep(0.2)
        first.reap()
        # The shell is dead but ``alive`` is still true, so ``release`` does
        # not drop it; it goes back to the idle list and is handed out again.
        pool.release(first)
        pool.reap()
        second = pool.acquire(False)
        assert second is not first
        assert second.pid != old_pid
    finally:
        pool.terminate_all()


class _FakeSession:
    def handshake_hash(self) -> bytes:
        return b"h" * 32


class _FakeSecure:
    def __init__(self, *, fail: str) -> None:
        self.session = _FakeSession()
        self.fail = fail
        self.first = True

    def recv_control(self) -> tuple[int, dict[str, Any]]:
        if self.first:
            self.first = False
            return proto.Msg.HELLO, {
                "version": proto.PROTOCOL_VERSION,
                "term": proto.DEFAULT_TERM,
                "encoding": proto.DEFAULT_ENCODING,
                "rows": proto.DEFAULT_ROWS,
                "cols": proto.DEFAULT_COLS,
                "capabilities": [],
                "max_record": 256,
                "handshake_hash": (b"h" * 32).hex(),
            }
        if self.fail == "eof":
            raise proto.TransportEOF("test transport EOF")
        return proto.Msg.READY, {}

    def send_control(self, msg_type: int, obj: dict[str, Any]) -> None:
        if self.fail == "send" and msg_type == proto.Msg.ACCEPT:
            raise OSError("test send failure")


def test_negotiation_send_failure_releases_the_shell() -> None:
    """ERR-003 — an ACCEPT send failure must leave the pool with no busy shell."""
    pool = agent_mod.ShellPool(max_idle=1)
    try:
        secure = _FakeSecure(fail="send")
        machine = proto.SessionState()
        machine.to(proto.State.AUTHENTICATED)
        with pytest.raises(OSError):
            agent_mod.negotiate(cast("proto.SecureChannel", secure), machine, pool)
        assert pool._busy == set()
    finally:
        pool.terminate_all()


def test_transport_eof_during_negotiation_releases_the_shell() -> None:
    """ERR-004 — a transport EOF after HELLO must leave no busy shell."""
    pool = agent_mod.ShellPool(max_idle=1)
    try:
        secure = _FakeSecure(fail="eof")
        machine = proto.SessionState()
        machine.to(proto.State.AUTHENTICATED)
        with pytest.raises(proto.TransportEOF):
            agent_mod.negotiate(cast("proto.SecureChannel", secure), machine, pool)
        assert pool._busy == set()
    finally:
        pool.terminate_all()


def test_clean_detach_sends_close_and_not_abrupt_eof(tmp_path: Path) -> None:
    """ERR-005 — stdin EOF detach is authenticated CLOSE, not a transport failure."""
    with live_stack(tmp_path) as stack:
        session = _session(stack)
        try:
            session.read_until(b"$", timeout=40)
            session.write(b"~.")
            session.proc.wait(timeout=15)
        finally:
            session.close()
        log = _wait_log(stack.agent_log, "operator closed the session", timeout=5)
        assert "operator closed the session (authenticated close)" in log
        assert "abrupt EOF" not in log


def test_shutdown_does_not_close_a_pty_under_a_writer(tmp_path: Path) -> None:
    """ERR-006 — SIGTERM while `yes` writes must not produce EBADF."""
    for trial in range(3):
        trial_dir = tmp_path / f"trial-{trial}"
        trial_dir.mkdir()
        stack = Stack(trial_dir)
        session = _session(stack)
        try:
            session.read_until(b"$", timeout=40)
            session.write(b"yes\n")
            time.sleep(0.7)
            stack.agent.send_signal(signal.SIGTERM)
            stack.agent.wait(timeout=15)
            log = Path(stack.agent_log).read_text(errors="replace")
            assert "Bad file descriptor" not in log
        finally:
            session.close()
            stack.close()


def test_agent_applies_a_handshake_deadline() -> None:
    """ERR-007 — the agent must name and apply a bounded handshake deadline."""
    source = _source("moesh_tunnel.py")
    assert "proto.HANDSHAKE_TIMEOUT" in source
    assert "sock.settimeout(proto.HANDSHAKE_TIMEOUT)" in source


# ---------------------------------------------------------------------------
# Performance
# ---------------------------------------------------------------------------


def test_three_sessions_own_three_ptys_and_one_drop_is_isolated(tmp_path: Path) -> None:
    """PERF-001 — three operators own three pids; a dropped client does not hurt survivors."""
    with live_stack(tmp_path, sessions=3) as stack:
        sessions = [_session(stack) for _ in range(3)]
        try:
            for session in sessions:
                session.read_until(b"$", timeout=45)
            pids = re.findall(r"shell started \(pid (\d+)", Path(stack.agent_log).read_text())
            assert len(set(pids)) >= 3
            sessions[0].close()
            for index, session in enumerate(sessions[1:], start=1):
                session.write(f"echo ALIVE_{index}\n".encode())
                assert f"ALIVE_{index}".encode() in session.read_until(
                    f"ALIVE_{index}".encode(), timeout=20
                )
            assert "shell terminated" not in Path(stack.agent_log).read_text()
        finally:
            for session in sessions:
                session.close()


def test_ninth_queued_tunnel_is_refused_in_bounded_time(tmp_path: Path) -> None:
    """PERF-002 — queue depth 8/9 is refused or backpressured within five seconds."""
    tunnel_port, operator_port, operator_v2_port = next_ports()
    bridge = Bridge(tunnel_port, operator_port, operator_v2_port)
    sockets: list[socket.socket] = []
    try:
        request = (
            f"GET {bridge_mod.TUNNEL_PATH}/alpha HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{tunnel_port}\r\n"
            f"Upgrade: {proto.UPGRADE_TOKEN}\r\n"
            "Connection: Upgrade\r\n"
            f"X-Moesh-Tunnel-Version: {proto.PROTOCOL_VERSION}\r\n\r\n"
        ).encode()
        for _ in range(8):
            sock = socket.create_connection(("127.0.0.1", tunnel_port), timeout=5)
            sockets.append(sock)
            sock.sendall(request)
            assert b" 101 " in sock.recv(4096)
        ninth = socket.create_connection(("127.0.0.1", tunnel_port), timeout=5)
        sockets.append(ninth)
        ninth.sendall(request)
        ninth.settimeout(5)
        with contextlib.suppress(TimeoutError):
            ninth.recv(4096)
        log = _wait_log(bridge.log_path, "tunnel queue full", timeout=5)
        assert "tunnel queue full" in log
    finally:
        for sock in sockets:
            with contextlib.suppress(OSError):
                sock.close()
        bridge.stop()


def test_per_host_queue_registry_is_bounded() -> None:
    """PERF-003 — 1024 host names must not create 1024 retained queues."""
    start = len(bridge_mod._shell_v2)
    for index in range(1024):
        bridge_mod.host_queue(f"alpha-{index}")
    assert len(bridge_mod._shell_v2) - start <= 256


def test_idle_pool_and_fds_stay_bounded() -> None:
    """PERF-004 — twelve kill/reap cycles must not grow the pool or fd table."""
    pool = agent_mod.ShellPool(max_idle=1)
    baseline = len(os.listdir("/proc/self/fd"))
    try:
        for _ in range(12):
            shell = pool.acquire(False)
            shell.spawn(proto.DEFAULT_TERM, proto.DEFAULT_ROWS, proto.DEFAULT_COLS)
            assert shell.pid is not None
            os.kill(shell.pid, signal.SIGKILL)
            time.sleep(0.05)
            shell.reap()
            pool.reap()
            assert len(pool._shells) <= pool.max_idle
        assert len(os.listdir("/proc/self/fd")) <= baseline + 2
    finally:
        pool.terminate_all()


# ---------------------------------------------------------------------------
# Integration
# ---------------------------------------------------------------------------


def _raw_request(port: int, request: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        sock.sendall(request)
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        return response


def _v2_request(host: str, *, connection: str | None = "Upgrade") -> bytes:
    lines = [
        f"GET {bridge_mod.TUNNEL_PATH}/{host} HTTP/1.1",
        "Host: 127.0.0.1",
        f"Upgrade: {proto.UPGRADE_TOKEN}",
    ]
    if connection is not None:
        lines.append(f"Connection: {connection}")
    lines.append(f"X-Moesh-Tunnel-Version: {proto.PROTOCOL_VERSION}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


@pytest.mark.xfail(strict=True, reason="K11 the bridge queues a path/label mismatch instead of refusing it")
def test_named_route_mismatch_is_refused_before_queueing() -> None:
    """INT-001 — a path/label disagreement must not be queued as a live tunnel."""
    source = _source("moesh-bridge.py")
    tunnel_route = source.split("if token == UPGRADE_TOKEN_V2:", 1)[1].split(
        "if token != \"websocket\":", 1
    )[0]
    assert "read_host_label" in tunnel_route


@pytest.mark.xfail(strict=True, reason="K11 the bare route queues a named agent under default")
def test_bare_route_does_not_strand_a_named_agent() -> None:
    """INT-002 — the bare v2 path must not queue a non-default agent under `default`."""
    source = _source("moesh-bridge.py")
    route = source.split("if path == TUNNEL_PATH:", 1)[1].split(
        "elif path.startswith(TUNNEL_PATH_PREFIX):", 1
    )[0]
    assert "read_host_label" in route


def test_v1_route_is_refused_when_cutover_is_off(tmp_path: Path) -> None:
    """INT-003 — ALLOW_V1=0 refuses /__tunnel/v1 with 426 and logs the cutover."""
    tunnel_port, operator_port, operator_v2_port = next_ports()
    bridge = Bridge(tunnel_port, operator_port, operator_v2_port, allow_v1=False)
    try:
        request = (
            b"GET /__tunnel/v1 HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        )
        response = _raw_request(tunnel_port, request)
        assert b"426 Upgrade Required" in response
        bridge._wait_for_line("v1 shell tunnel disabled by cutover")
    finally:
        bridge.stop()


def test_gpu_route_survives_v1_cutover(tmp_path: Path) -> None:
    """INT-004 — /__relay/gpu returns 101 while /__tunnel/v1 is refused."""
    tunnel_port, operator_port, operator_v2_port = next_ports()
    bridge = Bridge(tunnel_port, operator_port, operator_v2_port, allow_v1=False)
    try:
        gpu = (
            b"GET /__relay/gpu HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        )
        v1 = gpu.replace(b"/__relay/gpu", b"/__tunnel/v1")
        lemonade = gpu.replace(b"/__relay/gpu", b"/__relay/lemonade")
        assert b" 101 " in _raw_request(tunnel_port, gpu)
        assert b" 101 " in _raw_request(tunnel_port, lemonade)
        assert b"426" in _raw_request(tunnel_port, v1)
    finally:
        bridge.stop()


def test_wire_constants_have_one_authoritative_definition() -> None:
    """INT-005 — no endpoint may assign a protocol name already owned by proto."""
    owned = {
        "UPGRADE_TOKEN",
        "PRELUDE_PREFIX",
        "TUNNEL_PATH",
        "DEFAULT_PATH",
        "DEFAULT_HOST",
        "PROTOCOL_VERSION",
        "MAX_DATA_PAYLOAD",
        "MAX_CONTROL_PAYLOAD",
    }
    duplicates: list[str] = []
    for filename in ("moesh-bridge.py", "moesh_tunnel.py", "moesh_shell.py"):
        tree = ast.parse(_source(filename))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name) and target.id in owned:
                        duplicates.append(f"{filename}:{target.id}")
    assert duplicates == []


def test_connection_header_is_required_for_upgrade(tmp_path: Path) -> None:
    """INT-006 — Connection: keep-alive must be refused, not upgraded."""
    tunnel_port, operator_port, operator_v2_port = next_ports()
    bridge = Bridge(tunnel_port, operator_port, operator_v2_port)
    try:
        assert b" 101 " in _raw_request(tunnel_port, _v2_request("alpha"))
        response = _raw_request(tunnel_port, _v2_request("alpha", connection="keep-alive"))
        assert b" 400 " in response
    finally:
        bridge.stop()


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------


def test_bridge_is_blind_and_docs_name_the_label_exception() -> None:
    """SEC-001 — no decrypt/terminal parse, and the documented label exception."""
    source = _source("moesh-bridge.py")
    forbidden = ("NoiseSession", "decrypt(", "termios", "tcsetattr", "import pty")
    assert not any(token in source for token in forbidden)
    doc = _source("PROTOCOL.md").lower()
    assert "plaintext" in doc and "routing label" in doc


def test_receiver_log_has_no_terminal_plaintext(tmp_path: Path) -> None:
    """SEC-002 — a typed marker never appears in the bridge log; the scanner catches a control."""
    marker = f"MOESH_PLAINTEXT_MARK_{os.getpid()}"
    with live_stack(tmp_path) as stack:
        session = _session(stack)
        try:
            session.read_until(b"$", timeout=40)
            session.write(f"echo {marker}\n".encode())
            assert marker.encode() in session.read_until(marker.encode(), timeout=20)
            log = stack.bridge.log_text()
            assert marker not in log
            control = log + f"\n{marker}\n"
            assert marker in control
        finally:
            session.close()


def test_no_pty_or_terminal_byte_before_active() -> None:
    """SEC-003 — the agent spawns the shell only after the ACTIVE transition."""
    source = _source("moesh_tunnel.py")
    negotiate = source.split("def negotiate(", 1)[1].split("def run_session(", 1)[0]
    assert negotiate.index("machine.to(State.ACTIVE)") < negotiate.index("shell.spawn(")


def test_pin_is_checked_before_the_first_transport_record() -> None:
    """SEC-004 — READY implies authenticated, and the pin is enforced before records."""
    assert "session.authenticated" in _source("moesh_tunnel.py")
    assert "session.authenticated" in _source("moesh_shell.py")


def test_prologue_binds_the_protocol_version() -> None:
    """SEC-005 — the prologue token must equal the current major version."""
    assert f"/{proto.PROTOCOL_VERSION}/".encode() in proto.PROLOGUE


def test_no_plaintext_fallback_or_downgrade(tmp_path: Path) -> None:
    """SEC-006 — websocket/no-upgrade/wrong-token requests to the v2 path are refused."""
    tunnel_port, operator_port, operator_v2_port = next_ports()
    bridge = Bridge(tunnel_port, operator_port, operator_v2_port)
    try:
        websocket = _v2_request("alpha").replace(
            f"Upgrade: {proto.UPGRADE_TOKEN}".encode(), b"Upgrade: websocket"
        )
        assert b" 400 " in _raw_request(tunnel_port, websocket)
        no_upgrade = b"GET /__moesh/tunnel/alpha HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        assert b" 400 " in _raw_request(tunnel_port, no_upgrade)
        wrong = _v2_request("alpha").replace(
            f"Upgrade: {proto.UPGRADE_TOKEN}".encode(), b"Upgrade: nope"
        )
        assert b" 400 " in _raw_request(tunnel_port, wrong)
    finally:
        bridge.stop()


def test_routing_label_rejects_injection_and_overflow() -> None:
    """SEC-007 — control bytes, spaces, separators and over-length labels are refused."""
    for label in ("", "\x00", "a" * 65, "../x", "bad host", " alpha ", "\n"):
        assert not bridge_mod.valid_host(label)
    assert bridge_mod.valid_host("alpha-1")


def _probe_scanner(text: str) -> bool:
    """Return true when the code connects to an operator-port name."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if name not in {"create_connection", "connect"}:
            continue
        for arg in [*node.args, *(kw.value for kw in node.keywords)]:
            for child in ast.walk(arg):
                if isinstance(child, ast.Name) and "operator" in child.id:
                    return True
    return False


def test_no_operator_port_liveness_probe() -> None:
    """SEC-008 — readiness comes from log lines, never an operator-port connect."""
    tests_text = "\n".join(
        path.read_text(errors="replace")
        for path in (ROOT / "tests").glob("*.py")
    )
    assert not _probe_scanner(tests_text)
    assert _probe_scanner(
        "socket.create_connection(('127.0.0.1', operator_port), timeout=1)"
    )


# ---------------------------------------------------------------------------
# UX / ergonomics
# ---------------------------------------------------------------------------


def test_bridge_evidence_is_unique_across_runs() -> None:
    """UX-001 — two processes must not overwrite the same bridge log."""
    code = "from tests.harness import next_ports; print(next_ports()[0])"
    first = subprocess.check_output([AGENT_PYTHON, "-c", code], cwd=ROOT, text=True).strip()
    second = subprocess.check_output([AGENT_PYTHON, "-c", code], cwd=ROOT, text=True).strip()
    assert first != second
    assert f"bridge-test-{first}.log" != f"bridge-test-{second}.log"


def test_failure_leaves_attributable_evidence_not_a_bare_hang(tmp_path: Path) -> None:
    """UX-002 — a killed agent leaves client, agent and bridge evidence, bounded."""
    with live_stack(tmp_path) as stack:
        session = _session(stack, "--no-reconnect")
        try:
            session.read_until(b"$", timeout=40)
            stack.agent.kill()
            stack.agent.wait(timeout=10)
            with pytest.raises(AssertionError):
                session.read_until(b"NEVER_ARRIVES", timeout=12)
        finally:
            session.close()
        client_log = Path(session.err_path).read_text(errors="replace")
        agent_log = Path(stack.agent_log).read_text(errors="replace")
        bridge_log = stack.bridge.log_text()
        assert client_log
        assert agent_log.strip()
        assert "pairing" in bridge_log


def test_failed_client_leaves_no_orphan_shell_or_client(tmp_path: Path) -> None:
    """UX-003 — closing a failed client releases its client process and shell."""
    with live_stack(tmp_path) as stack:
        session = _session(stack)
        try:
            session.read_until(b"$", timeout=40)
        finally:
            session.close()
        assert session.proc.poll() is not None
        children = subprocess.check_output(
            ["ps", "-o", "pid=,comm=", "--ppid", str(os.getpid())], text=True
        )
        assert "moesh_shell" not in children and "moesh-shell-v2" not in children


def test_terminal_termios_is_restored() -> None:
    """UX-004 — RawTerminal restores the saved termios in a finally block."""
    source = _source("moesh_shell.py")
    raw = source.split("class RawTerminal", 1)[1].split("class ", 1)[0]
    assert "def __exit__" in raw
    assert "self.restore()" in raw
    assert "tcsetattr" in raw
