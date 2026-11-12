"""Regression tests for relay standby refresh, queue continuity, and carrier age diagnostics."""

from __future__ import annotations

import contextlib
import datetime
import importlib.util
import ipaddress
import os
import queue
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import moesh_relay
from tests.harness import Bridge, next_ports

_ROOT = Path(__file__).resolve().parent.parent
RELAY_SCRIPT = str(_ROOT / "moesh_relay.py")
BRIDGE_SCRIPT = str(_ROOT / "moesh-bridge.py")


def _free_port() -> int:
    """Return an ephemeral loopback TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _load_bridge(name: str) -> Any:
    """Import moesh-bridge.py as an isolated module instance for unit checks."""
    spec = importlib.util.spec_from_file_location(name, BRIDGE_SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _generate_self_signed_cert(tmp_path: Path) -> tuple[Path, Path]:
    """Generate an ephemeral self-signed EC/RSA cert+key pair for localhost TLS tests."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def _start_relay_proc(
    tmp_path: Path,
    *,
    tunnel_port: int,
    relay_port: int,
    target_port: int,
    workers: int,
    idle: int,
    session_idle: int = 5,
    name: str = "test-svc",
) -> tuple[subprocess.Popen[bytes], Path, Any]:
    """Spawn moesh_relay.py writing stdout/stderr to a deterministic log file."""
    log_path = tmp_path / f"relay-{relay_port}.log"
    handle = open(log_path, "wb")  # noqa: SIM115
    proc = subprocess.Popen(
        [
            sys.executable,
            RELAY_SCRIPT,
            "--receiver",
            "127.0.0.1",
            "--port",
            str(tunnel_port),
            "--remote-port",
            str(relay_port),
            "--name",
            name,
            "--target",
            f"127.0.0.1:{target_port}",
            "--workers",
            str(workers),
            "--idle",
            str(idle),
            "--session-idle",
            str(session_idle),
        ],
        stdout=handle,
        stderr=subprocess.STDOUT,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    return proc, log_path, handle


def _stop_proc(proc: subprocess.Popen[bytes], handle: Any) -> None:
    """Terminate relay subprocess cleanly and close log handle."""
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
    with contextlib.suppress(OSError):
        handle.close()


class _FailOnSecondSendSocket:
    """Socket proxy whose ``sendall`` raises OSError during deferred 101 write."""

    def __init__(self, inner: socket.socket) -> None:
        """Wrap an open socket while tracking sendall failures."""
        self._inner = inner

    def fileno(self) -> int:
        """Expose underlying file descriptor for ``select.select``."""
        return self._inner.fileno()

    def recv(self, bufsize: int, flags: int = 0) -> bytes:
        """Delegate peek/recv calls to inner socket."""
        return self._inner.recv(bufsize, flags)

    def sendall(self, data: bytes) -> None:
        """Simulate mid-pair carrier death when sending deferred 101 headers."""
        raise BrokenPipeError("simulated carrier closed during 101 write")

    def settimeout(self, value: float | None) -> None:
        """Delegate timeout configuration."""
        self._inner.settimeout(value)

    def setsockopt(self, level: int, optname: int, value: int | bytes) -> None:
        """Delegate socket option calls."""
        self._inner.setsockopt(level, optname, value)

    def shutdown(self, how: int) -> None:
        """Delegate shutdown."""
        self._inner.shutdown(how)

    def close(self) -> None:
        """Close wrapped socket."""
        self._inner.close()


def test_connect_tunnel_closes_socket_and_enables_keepalive_on_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """connect_tunnel must set SO_KEEPALIVE and close its socket before raising TimeoutError."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = int(srv.getsockname()[1])

    accepted: list[socket.socket] = []
    header_keepalive: list[int] = []
    orig_read_headers = moesh_relay.read_headers

    def spy_read_headers(sock: socket.socket) -> bytes:
        header_keepalive.append(sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE))
        return orig_read_headers(sock)

    monkeypatch.setattr(moesh_relay, "read_headers", spy_read_headers)

    def accept_once() -> None:
        conn, _ = srv.accept()
        accepted.append(conn)
        with contextlib.suppress(OSError):
            conn.recv(4096)

    t = threading.Thread(target=accept_once, daemon=True)
    t.start()

    try:
        try:
            moesh_relay.connect_tunnel(
                "127.0.0.1",
                port,
                "/__relay/test",
                header_timeout=0.15,
            )
            pytest.fail("expected TimeoutError when receiver defers 101 past header_timeout")
        except TimeoutError:
            assert len(accepted) == 1
            # Verify INSIDE except block (before frame/traceback teardown) that FIN landed.
            accepted[0].settimeout(0.5)
            eof = accepted[0].recv(16)
            assert eof == b"", "connect_tunnel left socket open inside except TimeoutError"
        assert header_keepalive == [1], (
            f"carrier socket did not enable SO_KEEPALIVE: {header_keepalive}"
        )
    finally:
        for s in accepted:
            with contextlib.suppress(OSError):
                s.close()
        srv.close()


def test_standby_timeout_schedule_staggers_workers_and_respects_short_idle() -> None:
    """Standby timeout scheduling must stagger initial expiries and allow idle < 20s."""
    fn = getattr(moesh_relay, "_standby_wait_timeout", None)
    assert callable(fn), "moesh_relay._standby_wait_timeout helper is missing"

    cycle0 = [fn(900, i, 4, 0) for i in range(4)]
    assert all(val is not None and 0 < val <= 900.0 for val in cycle0)
    assert len(set(cycle0)) == 4, f"workers were not staggered on cycle 0: {cycle0}"
    assert max(cycle0) - min(cycle0) >= 400.0

    # Short idle values (< 20s) must NOT be clamped up to 20s.
    short_cycle0 = [fn(1, i, 4, 0) for i in range(4)]
    assert all(val is not None and 0 < val <= 1.0 for val in short_cycle0)
    assert fn(0, 0, 4, 0) is None


def test_standby_refresh_logs_and_keeps_queue_live_across_multiple_cycles(
    tmp_path: Path,
) -> None:
    """Single-worker relay at --idle 1 must log refreshes and keep queued >= 1 at every poll."""
    relay_port = _free_port()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    target_port = int(srv.getsockname()[1])
    stop_srv = threading.Event()

    def serve_greeting() -> None:
        srv.settimeout(0.2)
        while not stop_srv.is_set():
            try:
                conn, _ = srv.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            with conn:
                conn.sendall(b"+OK ready\r\n")

    threading.Thread(target=serve_greeting, daemon=True).start()
    tunnel_port, o1, o2 = next_ports()
    bridge = Bridge(
        tunnel_port, o1, o2, env_extra={"MOESH_RELAY_PORTS": str(relay_port)}
    )
    bridge._wait_for_line(f"relay-{relay_port} listening")
    proc, log_path, log_handle = _start_relay_proc(
        tmp_path,
        tunnel_port=tunnel_port,
        relay_port=relay_port,
        target_port=target_port,
        workers=1,
        idle=1,
    )
    try:
        bridge._wait_for_line(f"path /__relay/test-svc port {relay_port}")
        # Poll status across >3 expiry boundaries (idle=1s, watch 3.4s).
        queued_samples: list[int] = []
        end = time.monotonic() + 3.4
        while time.monotonic() < end:
            status = moesh_relay.fetch_status("127.0.0.1", tunnel_port)
            entry = status["relay"]["ports_in_use"].get(str(relay_port), {})
            queued_samples.append(int(entry.get("queued", 0)))
            time.sleep(0.05)

        assert all(q >= 1 for q in queued_samples), (
            f"standby queue dropped to 0 during refresh: min={min(queued_samples)} "
            f"samples={queued_samples[:20]}"
        )
        relay_log = log_path.read_text(encoding="utf-8", errors="replace")
        refresh_lines = [
            ln for ln in relay_log.splitlines() if "standby carrier" in ln
        ]
        assert len(refresh_lines) >= 2, (
            f"expected >=2 logged standby refreshes within 3.4s at --idle 1; log:\n{relay_log}"
        )

        # First external peer after multiple standby refreshes must succeed immediately.
        with socket.create_connection(("127.0.0.1", relay_port), timeout=3.0) as client:
            assert client.recv(1024).startswith(b"+OK ready\r\n")
    finally:
        stop_srv.set()
        _stop_proc(proc, log_handle)
        bridge.stop()
        srv.close()


def test_tls_first_request_succeeds_across_staggered_standby_refreshes(
    tmp_path: Path,
) -> None:
    """First-attempt TLS request must succeed after staggered standby refreshes across 4 workers."""
    cert_path, key_path = _generate_self_signed_cert(tmp_path)
    srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv_ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

    raw_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_srv.bind(("127.0.0.1", 0))
    raw_srv.listen(8)
    target_port = int(raw_srv.getsockname()[1])
    stop_srv = threading.Event()
    tls_errors: list[str] = []

    def serve_tls() -> None:
        raw_srv.settimeout(0.2)
        while not stop_srv.is_set():
            try:
                conn, _ = raw_srv.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                with srv_ctx.wrap_socket(conn, server_side=True) as tconn:
                    tconn.settimeout(3.0)
                    req = tconn.recv(4096)
                    if req:
                        tconn.sendall(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                        )
            except Exception as exc:
                tls_errors.append(repr(exc))
                with contextlib.suppress(OSError):
                    conn.close()

    threading.Thread(target=serve_tls, daemon=True).start()

    relay_port = _free_port()
    tunnel_port, o1, o2 = next_ports()
    bridge = Bridge(
        tunnel_port, o1, o2, env_extra={"MOESH_RELAY_PORTS": str(relay_port)}
    )
    bridge._wait_for_line(f"relay-{relay_port} listening")
    proc, log_path, log_handle = _start_relay_proc(
        tmp_path,
        tunnel_port=tunnel_port,
        relay_port=relay_port,
        target_port=target_port,
        workers=4,
        idle=1,
    )
    try:
        bridge._wait_for_line(f"path /__relay/test-svc port {relay_port}")
        # Wait past two full 1s idle boundaries across 4 staggered workers.
        time.sleep(2.4)
        relay_log = log_path.read_text(encoding="utf-8", errors="replace")
        refresh_lines = [
            ln for ln in relay_log.splitlines() if "standby carrier" in ln
        ]
        assert len(refresh_lines) >= 4, (
            f"expected staggered standby refreshes across 4 workers; log:\n{relay_log}"
        )

        cli_ctx = ssl.create_default_context(cafile=str(cert_path))
        cli_ctx.check_hostname = False
        # First-attempt HTTPS request (no retry allowed).
        with (
            socket.create_connection(("127.0.0.1", relay_port), timeout=3.0) as raw,
            cli_ctx.wrap_socket(raw, server_hostname="127.0.0.1") as tls_cli,
        ):
            tls_cli.settimeout(3.0)
            tls_cli.sendall(b"GET /v1/models HTTP/1.1\r\nHost: localhost\r\n\r\n")
            resp = tls_cli.recv(4096)
        assert b"HTTP/1.1 200 OK" in resp and resp.endswith(b"ok")
        assert not tls_errors, f"server-side TLS errors observed: {tls_errors}"
    finally:
        stop_srv.set()
        _stop_proc(proc, log_handle)
        bridge.stop()
        raw_srv.close()


def test_bridge_pair_retries_next_queued_carrier_when_first_fails_deferred_101() -> None:
    """pair() must fall back to the next live carrier in q when deferred 101 send raises OSError."""
    bridge = _load_bridge("moesh_bridge_pair_retry_test")
    q: queue.Queue[Any] = queue.Queue(maxsize=8)

    dead_a, dead_b = socket.socketpair()
    good_srv, good_cli = socket.socketpair()
    peer_srv, peer_cli = socket.socketpair()
    paired_calls = 0

    def on_pair() -> None:
        nonlocal paired_calls
        paired_calls += 1

    def serve_good() -> None:
        try:
            # Consume deferred 101 + MOESH_PAIRED_V1\n written by pair().
            buf = b""
            while b"MOESH_PAIRED_V1\n" not in buf:
                chunk = good_srv.recv(4096)
                if not chunk:
                    return
                buf += chunk
            good_srv.sendall(b"OK-SECOND-CARRIER")
            with contextlib.suppress(OSError):
                good_srv.shutdown(socket.SHUT_WR)
        finally:
            with contextlib.suppress(OSError):
                good_srv.close()

    threading.Thread(target=serve_good, daemon=True).start()

    try:
        failing_item = bridge.QueuedTunnel(
            sock=_FailOnSecondSendSocket(dead_a),
            response=b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
            pairing="event",
        )
        failing_item.ready.set()
        good_item = bridge.QueuedTunnel(
            sock=good_cli,
            response=b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
            pairing="event",
        )
        good_item.ready.set()
        q.put_nowait(failing_item)
        q.put_nowait(good_item)

        t = threading.Thread(
            target=bridge.pair,
            args=(peer_srv, q, "relay:26503", 2),
            kwargs={"on_pair": on_pair},
            daemon=True,
        )
        t.start()

        peer_cli.settimeout(3.0)
        got = peer_cli.recv(1024)
        t.join(timeout=3.0)
        assert got == b"OK-SECOND-CARRIER", (
            f"expected peer to fail over to second carrier, got {got!r}"
        )
        assert paired_calls == 1, f"on_pair ran {paired_calls} times instead of 1"
    finally:
        for s in (dead_a, dead_b, good_srv, good_cli, peer_srv, peer_cli):
            with contextlib.suppress(OSError):
                s.close()


def test_unleased_relay_port_closes_cleanly_without_20s_hang_and_status_reports_carrier_age() -> None:
    """Unleased relay ports must fail cleanly without 20s hang, and status reports oldest_queued_age."""
    relay_port = _free_port()
    tunnel_port, o1, o2 = next_ports()
    bridge = Bridge(
        tunnel_port, o1, o2, env_extra={"MOESH_RELAY_PORTS": str(relay_port)}
    )
    bridge._wait_for_line(f"relay-{relay_port} listening")
    try:
        # 1. Peer connecting to an unleased relay port must fail cleanly in < 1.5s,
        # never silent 20s hang and never framing-corrupting plaintext bytes (RC-05 / RC-07).
        t0 = time.monotonic()
        with socket.create_connection(("127.0.0.1", relay_port), timeout=2.0) as cli:
            cli.settimeout(2.0)
            assert cli.recv(1024) == b""
        elapsed = time.monotonic() - t0
        assert elapsed < 1.5, f"unleased relay port stalled {elapsed:.2f}s instead of fast-closing"

        # Verify a TLS-like ClientHello peer also fails fast with zero framing bytes.
        t1 = time.monotonic()
        with socket.create_connection(("127.0.0.1", relay_port), timeout=2.0) as tls_cli:
            tls_cli.settimeout(2.0)
            with contextlib.suppress(ConnectionResetError, BrokenPipeError):
                tls_cli.sendall(b"\x16\x03\x01\x00\x05hello")
                reply = tls_cli.recv(1024)
                assert reply == b"", f"unexpected plaintext marker on raw relay port: {reply!r}"
        assert (time.monotonic() - t1) < 1.5
        assert "no active carrier lease" in bridge.log_text()

        # 2. Verify bridge_status reports oldest_queued_age on admitted queued carrier.
        b_mod = _load_bridge("moesh_bridge_age_test")
        b_mod._bound_relay_ports.add(26503)
        q = b_mod.relay_queue("26503")
        assert q is not None
        s1, p1 = socket.socketpair()
        try:
            _port, reason, entry = b_mod.admit_relay(
                "ornith", "carrier-age", 26503, s1, pairing="event"
            )
            assert reason is None and entry is not None
            entry.ready.set()
            time.sleep(0.2)
            st = b_mod.bridge_status()
            info = st["relay"]["ports_in_use"]["26503"]
            assert "oldest_queued_age" in info, f"missing oldest_queued_age in {info!r}"
            assert isinstance(info["oldest_queued_age"], float)
            assert info["oldest_queued_age"] >= 0.15
        finally:
            s1.close()
            p1.close()
    finally:
        bridge.stop()
