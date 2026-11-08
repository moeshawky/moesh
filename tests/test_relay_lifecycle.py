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
import subprocess
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import moesh_relay
from tests.harness import AGENT_PYTHON, Bridge, next_ports

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


def test_dead_target_backs_off_instead_of_blackholing_standby_queue(
    tmp_path: Path,
) -> None:
    """When the local target refuses connections, the worker must back off instead of immediately re-queueing standby tunnels."""
    dead_target_port = free_port()
    relay_port = free_port()
    bridge, tunnel_port, _o1, _o2 = _make_bridge(relay_port)
    _start_relay(
        tunnel_port=tunnel_port,
        relay_port=relay_port,
        target_port=dead_target_port,
        session_idle=5,
    )
    try:
        bridge._wait_for_line(f"path /__relay/{relay_port}")
        # Trigger pairing against the dead local target.
        with socket.create_connection(("127.0.0.1", relay_port), timeout=5) as client:
            client.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            # The tunnel closes because the local target refused the connection.
            assert client.recv(1024) == b""

        # Wait briefly: a worker with a dead local target must be in backoff,
        # NOT immediately re-queued on the bridge where it would blackhole
        # the next peer and hold the lease busy.
        time.sleep(0.4)
        status = moesh_relay.fetch_status("127.0.0.1", tunnel_port)
        in_use = status["relay"]["ports_in_use"].get(str(relay_port), {})
        queued = in_use.get("queued", 0)
        assert queued == 0, (
            f"worker with dead target immediately re-queued {queued} standby tunnel(s)"
        )
    finally:
        bridge.stop()


def test_concurrent_relay_daemons_competing_for_same_port_e2e(
    tmp_path: Path,
) -> None:
    """Two relay daemons with distinct carrier IDs competing for the same port.

    The first daemon acquires port P and serves traffic. The second daemon receives
    HTTP 409 Conflict, logs the conflict, and backs off without evicting the first.
    When the first daemon terminates, the second daemon reconnects and acquires port P.
    """
    alpha_banner = b"CARRIER-ALPHA-ACTIVE\r\n"
    beta_banner = b"CARRIER-BETA-ACTIVE\r\n"

    def serve_alpha(conn: socket.socket) -> None:
        conn.sendall(alpha_banner)
        while conn.recv(4096):
            pass

    def serve_beta(conn: socket.socket) -> None:
        conn.sendall(beta_banner)
        while conn.recv(4096):
            pass

    server_alpha = Server(serve_alpha).start()
    server_beta = Server(serve_beta).start()
    relay_port = free_port()
    bridge, tunnel_port, _o1, _o2 = _make_bridge(relay_port)

    root = Path(__file__).resolve().parent.parent
    relay_py = root / "moesh_relay.py"

    log_alpha_path = tmp_path / "relay_alpha.log"
    log_beta_path = tmp_path / "relay_beta.log"

    with (
        open(log_alpha_path, "w+", encoding="utf-8") as log_alpha,
        open(log_beta_path, "w+", encoding="utf-8") as log_beta,
    ):
        proc_alpha = subprocess.Popen(
            [
                AGENT_PYTHON,
                str(relay_py),
                "--receiver",
                "127.0.0.1",
                "--port",
                str(tunnel_port),
                "-R",
                str(relay_port),
                "--target",
                f"127.0.0.1:{server_alpha.port}",
                "--id",
                "carrier-alpha",
                "--workers",
                "1",
            ],
            stdout=log_alpha,
            stderr=subprocess.STDOUT,
        )

        proc_beta: subprocess.Popen[bytes] | None = None
        try:
            bridge._wait_for_line(f"path /__relay/{relay_port}")

            # 1. Verify worker 1 (carrier-alpha) binds and serves.
            with socket.create_connection(("127.0.0.1", relay_port), timeout=5) as client:
                resp = _read_until(client, alpha_banner, timeout=5.0)
                assert alpha_banner in resp, f"expected alpha banner, got: {resp!r}"

            # 2. Launch worker 2 (carrier-beta) targeting the exact same port.
            proc_beta = subprocess.Popen(
                [
                    AGENT_PYTHON,
                    str(relay_py),
                    "--receiver",
                    "127.0.0.1",
                    "--port",
                    str(tunnel_port),
                    "-R",
                    str(relay_port),
                    "--target",
                    f"127.0.0.1:{server_beta.port}",
                    "--id",
                    "carrier-beta",
                    "--workers",
                    "1",
                    "--claim-wait",
                    "30.0",
                ],
                stdout=log_beta,
                stderr=subprocess.STDOUT,
            )

            # 3. Verify worker 2 receives 409 Conflict, logs it, and backs off without crashing.
            conflict_logged = False
            deadline = time.time() + 10.0
            while time.time() < deadline:
                log_beta.flush()
                content = log_beta_path.read_text(encoding="utf-8")
                if "409 Conflict" in content:
                    conflict_logged = True
                    break
                time.sleep(0.2)
            assert conflict_logged, (
                f"worker 2 did not log 409 Conflict within timeout: "
                f"{log_beta_path.read_text(encoding='utf-8')}"
            )
            assert proc_beta.poll() is None, "worker 2 crashed on 409 Conflict"

            # Verify worker 1 was NOT evicted and continues serving.
            with socket.create_connection(("127.0.0.1", relay_port), timeout=5) as client:
                resp = _read_until(client, alpha_banner, timeout=5.0)
                assert alpha_banner in resp, f"worker 1 was evicted: {resp!r}"

            # 4. Terminate worker 1.
            proc_alpha.terminate()
            proc_alpha.wait(timeout=5.0)

            # 5. Verify worker 2 reconnects, acquires port P lease, and serves cleanly.
            acquired = False
            deadline = time.time() + 10.0
            while time.time() < deadline:
                try:
                    with socket.create_connection(
                        ("127.0.0.1", relay_port), timeout=2.0
                    ) as client:
                        resp = _read_until(client, beta_banner, timeout=2.0)
                        if beta_banner in resp:
                            acquired = True
                            break
                except (OSError, TimeoutError):
                    pass
                time.sleep(0.5)

            assert acquired, (
                f"worker 2 failed to acquire port {relay_port} after worker 1 exit; "
                f"log: {log_beta_path.read_text(encoding='utf-8')}"
            )
        finally:
            if proc_alpha.poll() is None:
                proc_alpha.terminate()
                with contextlib.suppress(Exception):
                    proc_alpha.wait(timeout=2.0)
            if proc_beta is not None and proc_beta.poll() is None:
                proc_beta.terminate()
                with contextlib.suppress(Exception):
                    proc_beta.wait(timeout=2.0)
            bridge.stop()
            server_alpha.stop()
            server_beta.stop()


def test_relay_bare_domain_url_synthesizes_routing_path(monkeypatch: Any) -> None:
    """When --url has a bare domain (path is empty or '/'), path is synthesized from --service/--remote-port."""
    logs: list[str] = []
    monkeypatch.setattr(moesh_relay, "log", logs.append)
    monkeypatch.setattr(threading.Thread, "start", lambda self: None)
    monkeypatch.setattr(threading.Event, "wait", lambda self: True)

    # 1. Bare domain without trailing slash + --service
    moesh_relay.main(["--url", "http://127.0.0.1:8080", "--service", "web", "--workers", "1"])
    assert any("path=/__relay/web" in line for line in logs)

    # 2. Bare domain with trailing slash + --service
    logs.clear()
    moesh_relay.main(["--url", "http://127.0.0.1:8080/", "--service", "api", "--workers", "1"])
    assert any("path=/__relay/api" in line for line in logs)

    # 3. Bare domain with -R remote port
    logs.clear()
    moesh_relay.main(["--url", "http://127.0.0.1:8080", "-R", "26500", "--workers", "1"])
    assert any("path=/__relay/26500" in line for line in logs)

    # 4. Bare domain with neither -> /__relay/auto
    logs.clear()
    moesh_relay.main(["--url", "http://127.0.0.1:8080", "--workers", "1"])
    assert any("path=/__relay/auto" in line for line in logs)

    # 5. Explicit path preserved verbatim
    logs.clear()
    moesh_relay.main(["--url", "http://127.0.0.1:8080/__relay/custom", "--workers", "1"])
    assert any("path=/__relay/custom" in line for line in logs)


def test_relay_name_flags_and_env_set_service_label(monkeypatch: Any) -> None:
    """--name, -n, and MOESH_RELAY_NAME set the relay service label identically to --service."""
    logs: list[str] = []
    monkeypatch.setattr(moesh_relay, "log", logs.append)
    monkeypatch.setattr(threading.Thread, "start", lambda self: None)
    monkeypatch.setattr(threading.Event, "wait", lambda self: True)

    # 1. --name sets path=/__relay/<name>
    moesh_relay.main(["--url", "http://127.0.0.1:8080", "--name", "vllm-llama", "--workers", "1"])
    assert any("path=/__relay/vllm-llama" in line for line in logs)

    # 2. -n sets path=/__relay/<name>
    logs.clear()
    moesh_relay.main(["--url", "http://127.0.0.1:8080", "-n", "embed-svc", "--workers", "1"])
    assert any("path=/__relay/embed-svc" in line for line in logs)

    # 3. MOESH_RELAY_NAME env var sets label when flags omitted
    logs.clear()
    monkeypatch.setenv("MOESH_RELAY_NAME", "env-named-svc")
    moesh_relay.main(["--url", "http://127.0.0.1:8080", "--workers", "1"])
    assert any("path=/__relay/env-named-svc" in line for line in logs)

    # 4. Backward compatibility: --service still works
    logs.clear()
    monkeypatch.delenv("MOESH_RELAY_NAME", raising=False)
    moesh_relay.main(["--url", "http://127.0.0.1:8080", "--service", "legacy-svc", "--workers", "1"])
    assert any("path=/__relay/legacy-svc" in line for line in logs)

    # 5. Backward compatibility: MOESH_RELAY_SERVICE env var works
    logs.clear()
    monkeypatch.setenv("MOESH_RELAY_SERVICE", "legacy-env-svc")
    moesh_relay.main(["--url", "http://127.0.0.1:8080", "--workers", "1"])
    assert any("path=/__relay/legacy-env-svc" in line for line in logs)


def test_relay_registers_with_name_flag_and_bridge_status_reports_label_e2e(
    tmp_path: Path,
) -> None:
    """moesh-relay registering with --name or -n exposes the label in GET /__moesh/status."""
    def dummy_handler(conn: socket.socket) -> None:
        while conn.recv(4096):
            pass

    server = Server(dummy_handler).start()
    relay_port1 = free_port()
    relay_port2 = free_port()

    tunnel_port, operator_port, operator_v2_port = next_ports()
    bridge = Bridge(
        tunnel_port,
        operator_port,
        operator_v2_port,
        env_extra={"MOESH_RELAY_PORTS": f"{relay_port1},{relay_port2}"},
    )
    bridge._wait_for_line(f"relay-{relay_port1} listening")
    bridge._wait_for_line(f"relay-{relay_port2} listening")

    root = Path(__file__).resolve().parent.parent
    relay_py = root / "moesh_relay.py"

    log1_path = tmp_path / "relay_name1.log"
    log2_path = tmp_path / "relay_name2.log"

    proc1: subprocess.Popen[bytes] | None = None
    proc2: subprocess.Popen[bytes] | None = None
    try:
        with (
            open(log1_path, "w+", encoding="utf-8") as log1,
            open(log2_path, "w+", encoding="utf-8") as log2,
        ):
            # 1. Start worker 1 registering with --name
            proc1 = subprocess.Popen(
                [
                    AGENT_PYTHON,
                    str(relay_py),
                    "--receiver",
                    "127.0.0.1",
                    "--port",
                    str(tunnel_port),
                    "-R",
                    str(relay_port1),
                    "--name",
                    "vllm-llama3-svc",
                    "--target",
                    f"127.0.0.1:{server.port}",
                    "--id",
                    "carrier-name1",
                    "--workers",
                    "1",
                ],
                stdout=log1,
                stderr=subprocess.STDOUT,
            )

            # 2. Start worker 2 registering with -n
            proc2 = subprocess.Popen(
                [
                    AGENT_PYTHON,
                    str(relay_py),
                    "--receiver",
                    "127.0.0.1",
                    "--port",
                    str(tunnel_port),
                    "-R",
                    str(relay_port2),
                    "-n",
                    "embed-mini-svc",
                    "--target",
                    f"127.0.0.1:{server.port}",
                    "--id",
                    "carrier-name2",
                    "--workers",
                    "1",
                ],
                stdout=log2,
                stderr=subprocess.STDOUT,
            )

            bridge._wait_for_line(f"path /__relay/vllm-llama3-svc port {relay_port1}")
            bridge._wait_for_line(f"path /__relay/embed-mini-svc port {relay_port2}")

            # 3. Query bridge GET /__moesh/status over HTTP
            status = moesh_relay.fetch_status("127.0.0.1", tunnel_port)
            assert status["ok"] is True

            ports_in_use = status["relay"]["ports_in_use"]
            names_in_use = status["relay"]["names_in_use"]

            # Assert --name registered cleanly
            assert str(relay_port1) in ports_in_use, (
                f"port {relay_port1} missing from ports_in_use: {ports_in_use}"
            )
            assert ports_in_use[str(relay_port1)]["name"] == "vllm-llama3-svc"
            assert names_in_use.get("vllm-llama3-svc") == relay_port1

            # Assert -n registered cleanly
            assert str(relay_port2) in ports_in_use, (
                f"port {relay_port2} missing from ports_in_use: {ports_in_use}"
            )
            assert ports_in_use[str(relay_port2)]["name"] == "embed-mini-svc"
            assert names_in_use.get("embed-mini-svc") == relay_port2
    finally:
        if proc1 is not None and proc1.poll() is None:
            proc1.terminate()
            with contextlib.suppress(Exception):
                proc1.wait(timeout=2.0)
        if proc2 is not None and proc2.poll() is None:
            proc2.terminate()
            with contextlib.suppress(Exception):
                proc2.wait(timeout=2.0)
        bridge.stop()
        server.stop()

