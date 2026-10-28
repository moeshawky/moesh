#!/usr/bin/env python3
"""TCP lifecycle regressions for the relay and the bridge pump (MOESH-004/005).

MOESH-004: the backend connection must not depend on the peer transmitting
application data, so a greeting-first service works through the relay.
MOESH-005: a client may half-close its write direction and still receive the
complete response.  Both are measured over real sockets, and the bridge pump is
measured directly as well because the relay and the shell share its semantics.
"""

from __future__ import annotations

import contextlib
import socket
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

import moesh_relay
from tests.harness import Bridge, next_ports

if TYPE_CHECKING:
    from collections.abc import Callable


def free_port() -> int:
    """Reserve and release a loopback port number."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class Server:
    """A one-connection-at-a-time TCP server for a lifecycle scenario."""

    def __init__(self, behaviour: Callable[[socket.socket], None]) -> None:
        self.behaviour = behaviour
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = int(self.sock.getsockname()[1])
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.errors: list[BaseException] = []

    def _serve(self) -> None:
        while True:
            try:
                conn, _addr = self.sock.accept()
            except OSError:
                return
            try:
                self.behaviour(conn)
            except BaseException as err:  # surfaced by the test
                self.errors.append(err)
            finally:
                with contextlib.suppress(OSError):
                    conn.close()

    def start(self) -> Server:
        self.thread.start()
        return self

    def stop(self) -> None:
        with contextlib.suppress(OSError):
            self.sock.close()


def _start_relay(
    *,
    tunnel_port: int,
    relay_port: int,
    target_port: int,
    idle: int = 30,
    session_idle: int = 10,
    workers: int = 1,
) -> threading.Thread:
    """Run one relay carrier worker against a bridge."""

    def run() -> None:
        moesh_relay.worker(
            0,
            "127.0.0.1",
            tunnel_port,
            f"/__relay/{relay_port}",
            "127.0.0.1",
            target_port,
            idle,
            "test-carrier",
            None,
            0.0,
            relay_port,
            session_idle,
        )

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def _read_until(sock: socket.socket, needle: bytes, timeout: float = 5.0) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    deadline = time.time() + timeout
    while needle not in buf and time.time() < deadline:
        try:
            chunk = sock.recv(4096)
        except TimeoutError:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def _make_bridge(relay_port: int) -> tuple[Bridge, int, int, int]:
    tunnel_port, operator_port, operator_v2_port = next_ports()
    bridge = Bridge(
        tunnel_port,
        operator_port,
        operator_v2_port,
        env_extra={"MOESH_RELAY_PORTS": str(relay_port)},
    )
    bridge._wait_for_line(f"relay-{relay_port} listening")
    return bridge, tunnel_port, operator_port, operator_v2_port


# ---------------------------------------------------------------------------
# MOESH-004 — server-first protocols
# ---------------------------------------------------------------------------


def test_greeting_first_service_reaches_the_peer(tmp_path: Path) -> None:
    """An SMTP-style greeting arrives without the client sending anything."""
    greeting = b"220 test.invalid ESMTP ready\r\n"

    def greeting_first(conn: socket.socket) -> None:
        conn.sendall(greeting)
        while True:
            data = conn.recv(4096)
            if not data:
                return
            conn.sendall(data)

    server = Server(greeting_first).start()
    relay_port = free_port()
    bridge, tunnel_port, _o1, _o2 = _make_bridge(relay_port)
    _start_relay(
        tunnel_port=tunnel_port,
        relay_port=relay_port,
        target_port=server.port,
    )
    try:
        bridge._wait_for_line(f"path /__relay/{relay_port}")
        with socket.create_connection(("127.0.0.1", relay_port), timeout=5) as client:
            received = _read_until(client, greeting, timeout=5.0)
            assert received.startswith(greeting), received
            client.sendall(b"HELO test\r\n")
            assert b"HELO test" in _read_until(client, b"HELO test", timeout=5.0)
        assert server.errors == []
    finally:
        bridge.stop()
        server.stop()


def test_standby_capacity_survives_an_idle_refresh(tmp_path: Path) -> None:
    """An idle standby connection is refreshed, not leaked or exhausted."""
    greeting = b"+OK ready\r\n"

    def greeting_first(conn: socket.socket) -> None:
        conn.sendall(greeting)
        while conn.recv(4096):
            pass

    server = Server(greeting_first).start()
    relay_port = free_port()
    bridge, tunnel_port, _o1, _o2 = _make_bridge(relay_port)
    _start_relay(
        tunnel_port=tunnel_port,
        relay_port=relay_port,
        target_port=server.port,
        idle=1,
        session_idle=5,
    )
    try:
        bridge._wait_for_line(f"path /__relay/{relay_port}")
        # Let the standby dial age past the idle timeout twice; the carrier
        # must redial so the relay still pairs a fresh peer.
        time.sleep(2.5)
        with socket.create_connection(("127.0.0.1", relay_port), timeout=5) as client:
            assert greeting in _read_until(client, greeting, timeout=5.0)
    finally:
        bridge.stop()
        server.stop()


# ---------------------------------------------------------------------------
# MOESH-005 — half-close preserves the reverse direction
# ---------------------------------------------------------------------------


def test_half_close_then_response_through_relay(tmp_path: Path) -> None:
    """A client that write-EOF'd still receives the server's full response."""
    response_prefix = b"RESPONSE-AFTER-EOF:"

    def read_to_eof_then_reply(conn: socket.socket) -> None:
        received = b""
        while True:
            data = conn.recv(4096)
            if not data:
                break
            received += data
        conn.sendall(response_prefix + received)

    server = Server(read_to_eof_then_reply).start()
    relay_port = free_port()
    bridge, tunnel_port, _o1, _o2 = _make_bridge(relay_port)
    _start_relay(
        tunnel_port=tunnel_port,
        relay_port=relay_port,
        target_port=server.port,
        session_idle=10,
    )
    try:
        bridge._wait_for_line(f"path /__relay/{relay_port}")
        with socket.create_connection(("127.0.0.1", relay_port), timeout=5) as client:
            client.sendall(b"payload-before-half-close")
            client.shutdown(socket.SHUT_WR)
            received = _read_until(client, response_prefix, timeout=5.0)
        assert received == response_prefix + b"payload-before-half-close", received
    finally:
        bridge.stop()
        server.stop()


def test_bridge_pump_preserves_half_close() -> None:
    """The shared pump must forward a write-EOF and keep the other direction open."""
    import importlib.util

    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location(
        "moesh_bridge_pump_tests", root / "moesh-bridge.py"
    )
    assert spec is not None and spec.loader is not None
    bridge_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge_mod)

    host_app, host_proxy = socket.socketpair()
    peer_app, peer_proxy = socket.socketpair()
    pump_done = threading.Event()

    def run_pump() -> None:
        try:
            bridge_mod.pump(host_proxy, peer_proxy)
        finally:
            pump_done.set()

    pump = threading.Thread(target=run_pump, daemon=True)
    pump.start()

    def server() -> None:
        received = b""
        while True:
            data = host_app.recv(4096)
            if not data:
                break
            received += data
        # A real backend closes (or half-closes) when its response is complete;
        # without that the client has no response EOF to read up to.
        host_app.sendall(b"LATE-RESPONSE:" + received)
        host_app.shutdown(socket.SHUT_WR)

    server_thread = threading.Thread(target=server, daemon=True)
    server_thread.start()

    try:
        peer_app.settimeout(5.0)
        peer_app.sendall(b"request")
        peer_app.shutdown(socket.SHUT_WR)
        received = b""
        while True:
            chunk = peer_app.recv(4096)
            if not chunk:
                break
            received += chunk
        assert received == b"LATE-RESPONSE:request", received
        assert pump_done.wait(5.0), "pump did not finish after both directions closed"
    finally:
        for sock in (host_app, peer_app):
            with contextlib.suppress(OSError):
                sock.close()
        server_thread.join(5)
        pump.join(5)


def test_bridge_pump_does_not_leak_a_blocked_thread() -> None:
    """A peer that never closes is reaped after the half-close linger."""
    import importlib.util

    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location(
        "moesh_bridge_linger_tests", root / "moesh-bridge.py"
    )
    assert spec is not None and spec.loader is not None
    bridge_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge_mod)

    host_app, host_proxy = socket.socketpair()
    peer_app, peer_proxy = socket.socketpair()
    done = threading.Event()

    def run_pump() -> None:
        try:
            bridge_mod.pump(host_proxy, peer_proxy, linger=0.5)
        finally:
            done.set()

    threading.Thread(target=run_pump, daemon=True).start()
    try:
        # The host side closes first; the peer never sends anything more.
        host_app.close()
        assert done.wait(6.0), "pump kept a forwarding thread after the linger"
    finally:
        for sock in (peer_app, host_proxy, peer_proxy):
            with contextlib.suppress(OSError):
                sock.close()

