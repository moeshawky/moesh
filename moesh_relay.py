#!/usr/bin/env python3
"""moesh_relay — Zero-dependency outbound TCP reverse port relay.

Exposes any local TCP port on a remote machine back to a public port on the
receiver machine without requiring frpc/frps, SSH, root privileges, or incoming
open firewall ports.

How it works:
1. Dials outbound to the receiver's HTTP port (default 80) with an HTTP/1.1
   Upgrade on ``/__relay/<port>`` (or ``/__relay/auto`` / ``/__relay/<name>``).
2. The receiver bridge (``moesh-bridge.py``) checks that no other carrier holds
   that port or name (returning ``409 Conflict`` if taken), answers ``101``, and
   queues the raw socket pipe.
3. When any peer connects to the bound port on the receiver (e.g. ``:26426``),
   the bridge pairs the incoming connection with the oldest standby socket.
4. As soon as peer bytes arrive, the worker hands the active session to a
   session thread, connects to the local target (``--target 127.0.0.1:8000``),
   and immediately redials a replacement standby socket so HTTP keep-alive
   connections never deplete the standby queue.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
import random
import selectors
import socket
import ssl
import threading
import time
from typing import Any
from urllib.parse import urlsplit

from moesh_wire import RELAY_PAIR_MARKER, RELAY_PAIRING_EVENT

# Reads MOESH_RELAY_RECEIVER from the environment and defaults to an empty string; supplies the default --receiver host for the relay CLI.
DEFAULT_RECEIVER = os.environ.get(
    "MOESH_RELAY_RECEIVER", os.environ.get("MOESH_TUNNEL_RECEIVER", "")
)


def _env_int(name: str, default: int, alt_name: str | None = None) -> int:
    """Safely parse an integer environment variable with fallback defaults.

    Args:
        name: Primary environment variable name to inspect.
        default: Fallback integer value returned when unset, empty, or unparseable.
        alt_name: Secondary environment variable name checked if primary is unset/empty.

    Returns:
        Parsed integer value or default fallback.

    Errors:
        Never raises ValueError; malformed or non-numeric inputs return default.
    """
    raw = os.environ.get(name, "")
    if not raw and alt_name:
        raw = os.environ.get(alt_name, "")
    raw = raw.strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


# Reads MOESH_RELAY_PORT and converts it to int with default 80; safely falls back to default on invalid values.
DEFAULT_RECEIVER_PORT = _env_int(
    "MOESH_RELAY_PORT", 80, alt_name="MOESH_TUNNEL_RECEIVER_PORT"
)
# Reads MOESH_RELAY_TARGET and defaults to 127.0.0.1:8000; used as the default upstream target address.
DEFAULT_TARGET = os.environ.get("MOESH_RELAY_TARGET", "127.0.0.1:8000")
# Reads MOESH_RELAY_WORKERS and converts it to int with default 4; safely falls back to default on invalid values.
DEFAULT_WORKERS = _env_int("MOESH_RELAY_WORKERS", 4)
# Reads MOESH_RELAY_IDLE and converts it to int with default 900 seconds; safely falls back to default on invalid values.
DEFAULT_IDLE = _env_int("MOESH_RELAY_IDLE", 900)
# Idle timeout in seconds for an active paired TCP session before closing half-open keep-alive sockets.
# Set to 0 or negative to disable timeout completely for long-running inference prefill or generation.
DEFAULT_SESSION_IDLE = _env_int("MOESH_RELAY_SESSION_IDLE", 120)
# Default TLS configuration read from environment.
DEFAULT_TLS = os.environ.get("MOESH_RELAY_TLS", "").lower() in ("1", "true", "yes")
DEFAULT_TLS_INSECURE = os.environ.get(
    "MOESH_RELAY_TLS_INSECURE", os.environ.get("MOESH_RELAY_INSECURE", "")
).lower() in ("1", "true", "yes")
DEFAULT_TLS_CA_CERT = os.environ.get("MOESH_RELAY_TLS_CA_CERT", "")
DEFAULT_TLS_PIN = os.environ.get("MOESH_RELAY_TLS_PIN", "")

_log_lock = threading.Lock()
_port_logged = False
_target_lock = threading.Lock()
_target_failures: dict[tuple[str, int], int] = {}
_target_backoff_until: dict[tuple[str, int], float] = {}


def derive_carrier_id(explicit_id: str = "", scope: str = "") -> str:
    """Return a persistent carrier ID from explicit argument, env, or host identity.

    When neither explicit argument nor ``MOESH_RELAY_ID`` is provided, derives a
    stable 16-hex identity from the host's machine-id, kernel ``boot_id``,
    hostname, and optional ``scope`` (measured 2026-11-02: hashing only
    ``/etc/machine-id`` caused cloned VM images and multiple relay instances on
    the same host to emit identical ``X-Moesh-Relay-Id`` values).

    Preconditions:
        ``explicit_id`` is an optional string passed from CLI arguments.
        ``scope`` is an optional target/service discriminator string.
    Postconditions:
        Returns a non-empty hex or explicit carrier ID string.
    Failure Modes:
        If no host identity markers are readable, falls back to os.urandom(8).hex().
    """
    explicit = explicit_id.strip() or os.environ.get("MOESH_RELAY_ID", "").strip()
    if explicit:
        return explicit
    machine_id_parts: list[str] = []
    for path in (
        "/etc/machine-id",
        "/var/lib/dbus/machine-id",
    ):
        try:
            with open(path, encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    machine_id_parts.append(content)
        except OSError:
            pass
    if machine_id_parts:
        parts = list(machine_id_parts)
        try:
            with open("/proc/sys/kernel/random/boot_id", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    parts.append(content)
        except OSError:
            pass
        with contextlib.suppress(OSError):
            host = socket.gethostname().strip()
            if host:
                parts.append(host)
        if scope:
            parts.append(scope)
        raw = "|".join(parts).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:16]
    return os.urandom(8).hex()


def mask_token(token: str) -> str:
    """Return a masked representation of a secret token for safe logging."""
    if not token:
        return ""
    if len(token) <= 6:
        return "***"
    return f"{token[:3]}...{token[-3:]}"


def create_ssl_context(
    insecure: bool = False,
    ca_cert: str = "",
) -> ssl.SSLContext:
    """Create a configured SSLContext for carrier TLS connections."""
    if insecure:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        if ca_cert:
            ctx = ssl.create_default_context(cafile=ca_cert)
        else:
            ctx = ssl.create_default_context()
    return ctx


def verify_tls_pin(sock: socket.socket, pin: str) -> None:
    """Verify peer TLS certificate SHA-256 fingerprint against an expected pin."""
    if not isinstance(sock, ssl.SSLSocket):
        raise ssl.SSLCertVerificationError("cannot verify TLS pin on non-SSL socket")
    expected = pin.replace(":", "").replace(" ", "").lower()
    cert_der = sock.getpeercert(binary_form=True)
    if not cert_der:
        raise ssl.SSLCertVerificationError(
            "peer did not present a certificate for TLS pin verification"
        )
    actual = hashlib.sha256(cert_der).hexdigest().lower()
    if actual != expected:
        raise ssl.SSLCertVerificationError(
            f"TLS certificate fingerprint mismatch: expected {expected}, got {actual}"
        )


def log(msg: str) -> None:
    """Write timestamped log message to stdout."""
    with _log_lock:
        print(f"{time.strftime('%H:%M:%S')} [relay] {msg}", flush=True)


def read_headers(sock: socket.socket) -> bytes:
    """Read bytes through the end of the HTTP header block."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("closed during upgrade handshake")
        buf += chunk
        if len(buf) > 65536:
            raise ConnectionError("header block exceeded 64KB")
    return buf


def splice(a: socket.socket, b: socket.socket, idle_timeout: int = 0) -> None:
    """Pump bytes bidirectionally, preserving TCP half-close semantics.

    A direction that reaches EOF forwards it as ``SHUT_WR`` and leaves the
    reverse direction open long enough to deliver its response.  The previous
    implementation shut the *read* side of the surviving direction, so a client
    that half-closed after its request never saw the reply.

    Half-close linger is harmonized to 60s matching the receiver bridge
    (MOESH_BRIDGE_HALFCLOSE_LINGER, October 2026). On any OSError (e.g. connection
    reset, broken pipe, target abort), SHUT_RDWR is issued immediately on both
    sockets to tear down the session without lingering.

    ``idle_timeout`` bounds an otherwise idle session; when either direction
    times out the session is torn down rather than parked in CLOSE_WAIT.
    If ``idle_timeout <= 0``, socket timeouts are disabled (set to None), allowing
    indefinite pauses for long-running inference prefill or generation.
    """
    if idle_timeout > 0:
        a.settimeout(float(idle_timeout))
        b.settimeout(float(idle_timeout))
    else:
        a.settimeout(None)
        b.settimeout(None)
    done = threading.Event()
    error_occurred = threading.Event()

    def copy(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                try:
                    data = src.recv(65536)
                except ssl.SSLZeroReturnError:
                    break
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            error_occurred.set()
            for s in (a, b):
                with contextlib.suppress(OSError):
                    s.shutdown(socket.SHUT_RDWR)
        finally:
            with contextlib.suppress(OSError):
                dst.shutdown(socket.SHUT_WR)
            done.set()

    workers = [
        threading.Thread(target=copy, args=(a, b), daemon=True),
        threading.Thread(target=copy, args=(b, a), daemon=True),
    ]
    for worker_thread in workers:
        worker_thread.start()
    done.wait()
    linger = 0.0 if error_occurred.is_set() else 60.0
    deadline = time.time() + linger
    for worker_thread in workers:
        worker_thread.join(max(0.0, deadline - time.time()))
    for s in (a, b):
        with contextlib.suppress(OSError):
            s.shutdown(socket.SHUT_RDWR)
    for worker_thread in workers:
        worker_thread.join(1.0)
    for s in (a, b):
        with contextlib.suppress(OSError):
            s.close()


class RelayRefused(Exception):
    """The receiver refused this carrier (e.g. 409: another carrier holds the port or name)."""


def fetch_status(
    host: str,
    port: int,
    auth_token: str = "",
    *,
    tls: bool = False,
    tls_insecure: bool = False,
    tls_ca_cert: str = "",
    tls_pin: str = "",
    ssl_context: ssl.SSLContext | None = None,
) -> dict[str, Any]:
    """Query ``GET /__moesh/status`` on the receiver and return the parsed JSON."""
    auth = f"X-Moesh-Relay-Auth: {auth_token}\r\n" if auth_token else ""
    raw_sock = socket.create_connection((host, port), timeout=10)
    try:
        if tls or ssl_context is not None:
            ctx = ssl_context or create_ssl_context(
                insecure=tls_insecure, ca_cert=tls_ca_cert
            )
            sock: socket.socket = ctx.wrap_socket(raw_sock, server_hostname=host)
            if tls_pin:
                verify_tls_pin(sock, tls_pin)
        else:
            sock = raw_sock
    except Exception:
        raw_sock.close()
        raise

    with sock:
        req = (
            f"GET /__moesh/status HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"{auth}"
            "Connection: close\r\n\r\n"
        ).encode()
        sock.sendall(req)
        raw = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
    if b"\r\n\r\n" not in raw:
        raise ConnectionError("invalid HTTP response from /__moesh/status")
    head, body = raw.split(b"\r\n\r\n", 1)
    status_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    if " 200" not in status_line:
        raise ConnectionError(f"status probe failed: {status_line}")
    result: dict[str, Any] = json.loads(body.decode("utf-8", "replace"))
    return result


def print_probe(
    host: str,
    port: int,
    auth_token: str = "",
    *,
    tls: bool = False,
    tls_insecure: bool = False,
    tls_ca_cert: str = "",
    tls_pin: str = "",
    ssl_context: ssl.SSLContext | None = None,
) -> int:
    """Fetch and print receiver port and host status."""
    try:
        data = fetch_status(
            host,
            port,
            auth_token,
            tls=tls,
            tls_insecure=tls_insecure,
            tls_ca_cert=tls_ca_cert,
            tls_pin=tls_pin,
            ssl_context=ssl_context,
        )
    except Exception as exc:
        masked = f" (token: {mask_token(auth_token)})" if auth_token else ""
        log(f"probe failed against {host}:{port}{masked}: {exc}")
        return 1
    print(json.dumps(data, indent=2))
    return 0


def _set_tcp_keepalive(sock: socket.socket) -> None:
    """Enable TCP keepalive probes on standby relay sockets.

    Keeps NAT/firewall conntrack mappings active across idle windows and lets the
    client detect ungraceful proxy/receiver drops within ~30s instead of holding
    ghost ESTABLISHED sockets.
    """
    with contextlib.suppress(OSError):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    for opt_name, val in (
        ("TCP_KEEPIDLE", 15),
        ("TCP_KEEPINTVL", 5),
        ("TCP_KEEPCNT", 3),
    ):
        opt = getattr(socket, opt_name, None)
        if opt is not None:
            with contextlib.suppress(OSError):
                sock.setsockopt(socket.IPPROTO_TCP, opt, val)


def _standby_wait_timeout(
    idle: int, index: int, workers: int, cycle: int
) -> float | None:
    """Compute staggered standby refresh deadlines across workers.

    Cycle 0 spreads initial deadlines evenly across ``(0, idle]`` so a fresh
    worker pool never expires in lockstep; later cycles retain per-worker phase
    separation plus small jitter so traffic bursts cannot re-synchronize them.
    """
    if idle <= 0:
        return None
    w = max(1, workers)
    i = max(0, min(index, w - 1))
    if w == 1:
        return float(idle)
    if cycle == 0:
        step = float(idle) / float(w)
        floor = 0.25 if idle <= 2 else min(float(idle), max(0.5, step * 0.5))
        return min(float(idle), max(floor, float(idle) - i * step))
    phase = float(i) / float(w)
    jitter = random.uniform(-0.05, 0.05)  # noqa: S311 - scheduling jitter, not cryptographic
    return min(
        float(idle), max(0.25, float(idle) * (0.85 + 0.10 * (1.0 - phase) + jitter))
    )


def _wait_readable(
    socks: list[socket.socket], timeout: float | None
) -> list[socket.socket]:
    """Return subset of ``socks`` ready to read without missing TLS-buffered bytes."""
    buffered: list[socket.socket] = [
        s for s in socks if isinstance(s, ssl.SSLSocket) and s.pending() > 0
    ]
    if buffered:
        return buffered
    sel = selectors.DefaultSelector()
    try:
        for sock in socks:
            sel.register(sock, selectors.EVENT_READ)
        events = sel.select(timeout=timeout)
        return [s for s in socks if any(key.fileobj is s for key, _ in events)]
    finally:
        sel.close()


def _dial_relay_upgrade(
    host: str,
    port: int,
    path: str,
    carrier_id: str = "",
    remote_port: int = 0,
    *,
    auth_token: str = "",
    pairing_event: bool = True,
    connect_timeout: float = 20.0,
    tls: bool = False,
    tls_insecure: bool = False,
    tls_ca_cert: str = "",
    tls_pin: str = "",
    ssl_context: ssl.SSLContext | None = None,
) -> socket.socket:
    """Open TCP/TLS socket to receiver, apply keepalive, and send HTTP/1.1 Upgrade GET."""
    raw_sock = socket.create_connection((host, port), timeout=connect_timeout)
    _set_tcp_keepalive(raw_sock)
    try:
        if tls or ssl_context is not None:
            ctx = ssl_context or create_ssl_context(
                insecure=tls_insecure, ca_cert=tls_ca_cert
            )
            sock: socket.socket = ctx.wrap_socket(raw_sock, server_hostname=host)
            if tls_pin:
                verify_tls_pin(sock, tls_pin)
        else:
            sock = raw_sock
    except Exception:
        raw_sock.close()
        raise
    key = base64.b64encode(os.urandom(16)).decode()
    port_hdr = f"X-Moesh-Relay-Port: {remote_port}\r\n" if remote_port > 0 else ""
    pairing_hdr = "X-Moesh-Relay-Pairing: event\r\n" if pairing_event else ""
    auth_hdr = f"X-Moesh-Relay-Auth: {auth_token}\r\n" if auth_token else ""
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"X-Moesh-Relay-Id: {carrier_id}\r\n"
        f"{port_hdr}{pairing_hdr}{auth_hdr}\r\n"
    ).encode()
    try:
        sock.settimeout(connect_timeout)
        sock.sendall(req)
    except Exception:
        with contextlib.suppress(OSError):
            sock.close()
        raise
    return sock


def _read_upgrade_response(
    sock: socket.socket, remote_port: int
) -> tuple[int, bytes, bool]:
    """Read and validate receiver's HTTP/1.1 101 Upgrade headers, closing on error."""
    try:
        headers = read_headers(sock)
        head, leftover = headers.split(b"\r\n\r\n", 1)
        if not head.startswith(b"HTTP/1.1 101"):
            first_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            body = leftover.decode("latin-1", "replace").strip()
            sock.settimeout(1.0)
            with contextlib.suppress(OSError):
                more = sock.recv(4096)
                if more:
                    body = (leftover + more).decode("latin-1", "replace").strip()
            if b" 409 " in head.split(b"\r\n", 1)[0] + b" ":
                raise RelayRefused(body or first_line)
            raise ConnectionError(f"upgrade refused by receiver: {body or first_line}")
        assigned = remote_port
        event_mode = False
        for line in head.split(b"\r\n")[1:]:
            low = line.lower()
            if low.startswith(b"x-moesh-relay-port:"):
                val = line.split(b":", 1)[1].strip().decode("latin-1", "replace")
                if val.isdigit():
                    assigned = int(val)
            elif low.startswith(b"x-moesh-relay-pairing:"):
                value = line.split(b":", 1)[1].strip().decode("latin-1", "replace")
                event_mode = value == RELAY_PAIRING_EVENT
        return assigned, leftover, event_mode
    except Exception:
        with contextlib.suppress(OSError):
            sock.close()
        raise


def connect_tunnel(
    host: str,
    port: int,
    path: str,
    carrier_id: str = "",
    remote_port: int = 0,
    *,
    auth_token: str = "",
    pairing_event: bool = True,
    header_timeout: float = 20.0,
    tls: bool = False,
    tls_insecure: bool = False,
    tls_ca_cert: str = "",
    tls_pin: str = "",
    ssl_context: ssl.SSLContext | None = None,
) -> tuple[socket.socket, int, bytes, bool]:
    """Dial receiver and perform HTTP/1.1 Upgrade to enter raw pipe mode.

    With ``pairing_event`` the carrier asks the bridge to defer the 101 until a
    peer is paired and to announce the pairing with a marker.  That lets the
    backend connection be opened on pairing instead of on first peer byte,
    which server-first protocols (SMTP, MySQL, some TLS servers) require.

    Returns ``(sock, assigned_remote_port, leftover_bytes, event_mode)``.
    ``event_mode`` is True only when the receiver acknowledged the mode; an
    older receiver keeps the legacy data-driven pairing.
    """
    sock = _dial_relay_upgrade(
        host,
        port,
        path,
        carrier_id,
        remote_port=remote_port,
        auth_token=auth_token,
        pairing_event=pairing_event,
        tls=tls,
        tls_insecure=tls_insecure,
        tls_ca_cert=tls_ca_cert,
        tls_pin=tls_pin,
        ssl_context=ssl_context,
    )
    try:
        sock.settimeout(header_timeout)
        assigned, leftover, event_mode = _read_upgrade_response(sock, remote_port)
        return sock, assigned, leftover, event_mode
    except Exception:
        with contextlib.suppress(OSError):
            sock.close()
        raise


_ORIG_CONNECT_TUNNEL = connect_tunnel


def _serve_session(
    index: int,
    sock: socket.socket,
    first: bytes,
    target_host: str,
    target_port: int,
    session_idle: int,
    target: socket.socket | None = None,
) -> None:
    """Connect to local target (if not already connected), forward initial bytes, and splice."""
    if target is None:
        try:
            target = socket.create_connection((target_host, target_port), timeout=10)
        except OSError as err:
            log(f"worker {index}: target {target_host}:{target_port} refused: {err}")
            with contextlib.suppress(OSError):
                sock.close()
            return
    try:
        target.sendall(first)
        splice(sock, target, idle_timeout=session_idle)
    except OSError:
        with contextlib.suppress(OSError):
            sock.close()
        with contextlib.suppress(OSError):
            target.close()


def worker(
    index: int,
    host: str,
    port: int,
    path: str,
    target_host: str,
    target_port: int,
    idle: int,
    carrier_id: str = "",
    refused: threading.Event | None = None,
    claim_deadline: float = 0.0,
    remote_port: int = 0,
    session_idle: int = DEFAULT_SESSION_IDLE,
    token: str = "",
    tls: bool = False,
    tls_insecure: bool = False,
    tls_ca_cert: str = "",
    tls_pin: str = "",
    ssl_context: ssl.SSLContext | None = None,
    workers: int = 1,
) -> None:
    """Worker maintaining one queued standby tunnel with make-before-break refresh.

    Staggers standby expiry lifetimes across ``workers`` and dials each
    replacement standby carrier before closing the retiring socket so the
    receiver queue never dips empty during refresh and peers paired in flight
    complete cleanly without a handshake reset.

    As soon as a standby tunnel is paired and receives its first peer bytes,
    the local target connection is verified before handing the active session
    off to a background thread and dialing a replacement standby tunnel.
    This prevents HTTP keep-alive pools from exhausting the standby tunnel
    queue (measured 2026-10-26: 4 keep-alive sockets previously parked all 4
    workers) while ensuring a dead local target backs off instead of
    continuously queueing blackhole standby tunnels on the receiver (measured
    2026-11-02: an unreachable local backend previously re-queued within ms,
    dropping every incoming peer with EOF and holding the bridge lease busy).

    Resets the 409 conflict deadline per incident so transient conflicts during
    steady-state operation retry properly instead of aborting the relay daemon.

    Preconditions:
        ``host`` and ``port`` identify the receiver bridge.
        ``path`` is the relay path (e.g. /__relay/<port>).
        ``target_host`` and ``target_port`` identify the local target service.
        ``idle`` is the idle standby timeout in seconds.
        ``claim_deadline`` specifies the retry duration or deadline for conflict resolution.
    Postconditions:
        Runs the standby tunnel maintenance loop until interrupted or refused.
    Failure Modes:
        Signals ``refused`` if a RelayRefused error persists beyond the incident
        retry deadline.
    """
    global _port_logged
    incident_deadline: float | None = None
    target_key = (target_host, target_port)
    standby_sock: socket.socket | None = None
    standby_dialed_at = 0.0
    upgraded_meta: tuple[int, bytes, bool] | None = None
    cycle = 0

    def _close_quiet(s: socket.socket | None) -> None:
        if s is not None:
            with contextlib.suppress(OSError):
                s.close()

    while True:
        with _target_lock:
            wait_sec = _target_backoff_until.get(target_key, 0.0) - time.time()
        if wait_sec > 0:
            _close_quiet(standby_sock)
            standby_sock = None
            upgraded_meta = None
            time.sleep(wait_sec)
        sock: socket.socket | None = None
        wait_timeout = _standby_wait_timeout(idle, index, workers, cycle)
        try:
            if connect_tunnel is not _ORIG_CONNECT_TUNNEL:
                hdr_timeout = float(wait_timeout) if wait_timeout is not None else 20.0
                sock, assigned_port, leftover, event_mode = connect_tunnel(
                    host,
                    port,
                    path,
                    carrier_id,
                    remote_port=remote_port,
                    auth_token=token,
                    header_timeout=hdr_timeout,
                    tls=tls,
                    tls_insecure=tls_insecure,
                    tls_ca_cert=tls_ca_cert,
                    tls_pin=tls_pin,
                    ssl_context=ssl_context,
                )
            else:
                if standby_sock is None:
                    standby_sock = _dial_relay_upgrade(
                        host,
                        port,
                        path,
                        carrier_id,
                        remote_port=remote_port,
                        auth_token=token,
                        tls=tls,
                        tls_insecure=tls_insecure,
                        tls_ca_cert=tls_ca_cert,
                        tls_pin=tls_pin,
                        ssl_context=ssl_context,
                    )
                    standby_dialed_at = time.monotonic()
                    upgraded_meta = None

                remaining_wait = (
                    None
                    if wait_timeout is None
                    else max(0.05, wait_timeout - (time.monotonic() - standby_dialed_at))
                )
                ready = _wait_readable([standby_sock], remaining_wait)
                if not ready:
                    elapsed = time.monotonic() - standby_dialed_at
                    log(
                        f"worker {index}: standby carrier idle for {elapsed:.1f}s; "
                        "dialing replacement"
                    )
                    repl_sock = _dial_relay_upgrade(
                        host,
                        port,
                        path,
                        carrier_id,
                        remote_port=remote_port,
                        auth_token=token,
                        tls=tls,
                        tls_insecure=tls_insecure,
                        tls_ca_cert=tls_ca_cert,
                        tls_pin=tls_pin,
                        ssl_context=ssl_context,
                    )
                    repl_dialed_at = time.monotonic()
                    handoff_grace = min(0.25, max(0.05, (wait_timeout or 1.0) * 0.1))
                    grace_ready = _wait_readable(
                        [standby_sock, repl_sock], handoff_grace
                    )
                    if standby_sock in grace_ready:
                        if upgraded_meta is None:
                            try:
                                standby_sock.settimeout(20.0)
                                assigned_port, leftover, event_mode = (
                                    _read_upgrade_response(standby_sock, remote_port)
                                )
                            except RelayRefused:
                                _close_quiet(repl_sock)
                                raise
                            except ConnectionError:
                                standby_sock = repl_sock
                                standby_dialed_at = repl_dialed_at
                                upgraded_meta = None
                                cycle += 1
                                incident_deadline = None
                                continue
                        else:
                            assigned_port, leftover, event_mode = upgraded_meta
                        sock = standby_sock
                        standby_sock = repl_sock
                        standby_dialed_at = repl_dialed_at
                        upgraded_meta = None
                    elif repl_sock in grace_ready:
                        try:
                            repl_sock.settimeout(20.0)
                            r_assigned, r_leftover, r_event = _read_upgrade_response(
                                repl_sock, remote_port
                            )
                        except RelayRefused:
                            _close_quiet(standby_sock)
                            standby_sock = None
                            upgraded_meta = None
                            raise
                        except ConnectionError as err:
                            log(
                                f"worker {index}: replacement standby dial rejected ({err}); "
                                "retaining current standby carrier"
                            )
                            standby_dialed_at = time.monotonic()
                            time.sleep(0.5)
                            continue
                        _close_quiet(standby_sock)
                        standby_sock = None
                        upgraded_meta = None
                        if r_event or r_leftover:
                            sock = repl_sock
                            assigned_port = r_assigned
                            leftover = r_leftover
                            event_mode = r_event
                        else:
                            standby_sock = repl_sock
                            standby_dialed_at = repl_dialed_at
                            upgraded_meta = (r_assigned, r_leftover, False)
                            cycle += 1
                            incident_deadline = None
                            continue
                    else:
                        _close_quiet(standby_sock)
                        standby_sock = repl_sock
                        standby_dialed_at = repl_dialed_at
                        upgraded_meta = None
                        cycle += 1
                        incident_deadline = None
                        continue
                else:
                    sock = standby_sock
                    standby_sock = None
                    if upgraded_meta is None:
                        sock.settimeout(20.0)
                        assigned_port, leftover, event_mode = _read_upgrade_response(
                            sock, remote_port
                        )
                        if not event_mode and not leftover:
                            standby_sock = sock
                            standby_dialed_at = time.monotonic()
                            upgraded_meta = (assigned_port, leftover, False)
                            incident_deadline = None
                            continue
                    else:
                        assigned_port, leftover, event_mode = upgraded_meta
                        upgraded_meta = None

            incident_deadline = None
            if not _port_logged and assigned_port > 0:
                _port_logged = True
                log(
                    f"bound receiver port {host}:{assigned_port} -> "
                    f"local {target_host}:{target_port}"
                )
            sock.settimeout(float(idle) if idle > 0 else None)
            if event_mode:
                # The bridge sends the 101 only when a peer is paired, then a
                # fixed marker.  On that signal the backend is connected before
                # any peer byte exists, so greeting-first services work.
                preamble = leftover
                while len(preamble) < len(RELAY_PAIR_MARKER):
                    chunk = sock.recv(65536)
                    if not chunk:
                        raise ConnectionError("receiver closed before pairing")
                    preamble += chunk
                if not preamble.startswith(RELAY_PAIR_MARKER):
                    raise ConnectionError("unexpected pairing preamble from receiver")
                first = preamble[len(RELAY_PAIR_MARKER) :]
            else:
                first = leftover or sock.recv(65536)
                if not first:
                    raise ConnectionError("paired then immediately closed before data")
            sock.settimeout(None)
            try:
                target = socket.create_connection((target_host, target_port), timeout=10)
            except OSError as err:
                log(f"worker {index}: target {target_host}:{target_port} refused: {err}")
                _close_quiet(sock)
                sock = None
                _close_quiet(standby_sock)
                standby_sock = None
                upgraded_meta = None
                with _target_lock:
                    streak = _target_failures.get(target_key, 0) + 1
                    _target_failures[target_key] = streak
                    delay = min(30.0, 2.0 * (2 ** min(streak - 1, 4)))
                    _target_backoff_until[target_key] = max(
                        _target_backoff_until.get(target_key, 0.0),
                        time.time() + delay,
                    )
                time.sleep(delay)
                continue
            with _target_lock:
                _target_failures.pop(target_key, None)
                _target_backoff_until.pop(target_key, None)
            cycle += 1
            threading.Thread(
                target=_serve_session,
                args=(index, sock, first, target_host, target_port, session_idle, target),
                daemon=True,
            ).start()
            sock = None
        except TimeoutError:
            # Fallback idle path when connect_tunnel is externally mocked or read timed out.
            log(f"worker {index}: standby carrier idle after {idle}s; redialing")
            _close_quiet(sock)
            _close_quiet(standby_sock)
            standby_sock = None
            upgraded_meta = None
            cycle += 1
        except RelayRefused as err:
            _close_quiet(sock)
            _close_quiet(standby_sock)
            standby_sock = None
            upgraded_meta = None
            log(f"ERROR: refused by receiver (409 Conflict): {err}")
            now = time.time()
            if incident_deadline is None:
                # Default retry window on 409 Conflict harmonized to 45.0s (October 2026,
                # matching docs/CONNECT.md:280 and docs/configuration.md:154).
                incident_wait = (
                    max(0.1, claim_deadline - now)
                    if claim_deadline > 1_000_000_000
                    else (claim_deadline if claim_deadline > 0 else 45.0)
                )
                incident_deadline = now + incident_wait
            if refused is not None and now >= incident_deadline:
                refused.set()
                return
            time.sleep(1.5)
        except Exception as err:
            incident_deadline = None
            log(f"worker {index}: {type(err).__name__}: {err}; redialing in 2s")
            _close_quiet(sock)
            _close_quiet(standby_sock)
            standby_sock = None
            upgraded_meta = None
            time.sleep(2)


def main(argv: list[str] | None = None) -> int:
    """Parse CLI arguments, configure outbound reverse TCP relay, and run workers.

    Args:
        argv: Optional command-line argument list; defaults to sys.argv[1:].

    Returns:
        Exit code (0 on clean shutdown, non-zero on configuration or runtime error).

    Invariants:
        When --url is passed with a bare host (empty or root path), synthesizes
        the HTTP upgrade route from --service and --remote-port (/__relay/<svc>
        or /__relay/auto), matching the --receiver fallback contract.
    """
    ap = argparse.ArgumentParser(
        description="moesh outbound TCP reverse port relay"
    )
    ap.add_argument(
        "--remote-port",
        "-R",
        default=os.environ.get("MOESH_RELAY_REMOTE_PORT", ""),
        help="Remote port on receiver to expose (e.g. 26426, or 'auto' for any free port)",
    )
    ap.add_argument(
        "--name",
        "-n",
        "--service",
        dest="service",
        default=(
            os.environ.get("MOESH_RELAY_NAME")
            or os.environ.get("MOESH_RELAY_SERVICE", "")
        ),
        help="Optional agent-defined name for the leased relay port (default: port number or auto)",
    )
    ap.add_argument(
        "--receiver",
        default=DEFAULT_RECEIVER,
        help="Receiver host (or set MOESH_RELAY_RECEIVER / MOESH_TUNNEL_RECEIVER)",
    )
    ap.add_argument(
        "--port",
        type=int,
        default=None,
        help="Receiver HTTP/HTTPS port (default 80, or 443 with TLS)",
    )
    ap.add_argument(
        "--url",
        default="",
        help="Full URL override (e.g. https://receiver.example.com/__relay/26426)",
    )
    ap.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help="Local target host:port to forward to (default 127.0.0.1:8000)",
    )
    ap.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help="Number of standby queued connections (default 4)",
    )
    ap.add_argument(
        "--id",
        default=os.environ.get("MOESH_RELAY_ID", ""),
        help="Carrier identity (default: random per process)",
    )
    ap.add_argument(
        "--token",
        default=os.environ.get(
            "MOESH_RELAY_TOKEN", os.environ.get("MOESH_BRIDGE_RELAY_TOKEN", "")
        ),
        help=(
            "Shared relay token required by the receiver when "
            "MOESH_BRIDGE_RELAY_TOKEN is set (or set MOESH_RELAY_TOKEN)"
        ),
    )
    ap.add_argument(
        "--claim-wait",
        type=float,
        default=45.0,
        help="Seconds to retry on 409 Conflict before exiting with status 3 (default 45.0)",
    )
    ap.add_argument(
        "--idle",
        type=int,
        default=DEFAULT_IDLE,
        help="Idle timeout in seconds before refreshing standby tunnel (default 900)",
    )
    ap.add_argument(
        "--session-idle",
        type=int,
        default=DEFAULT_SESSION_IDLE,
        help=(
            "Idle timeout in seconds for active paired TCP sessions (default 120; "
            "set to 0 or negative to disable timeout completely for long-running inference)"
        ),
    )
    ap.add_argument(
        "--probe",
        action="store_true",
        help="Query receiver /__moesh/status for open/free/in-use ports and active hosts",
    )
    ap.add_argument(
        "--tls",
        action="store_true",
        default=DEFAULT_TLS,
        help="Use TLS for carrier connection to receiver (default port 443)",
    )
    ap.add_argument(
        "--tls-insecure",
        action="store_true",
        default=DEFAULT_TLS_INSECURE,
        help="Disable TLS certificate verification for self-signed certificates in dev/test",
    )
    ap.add_argument(
        "--insecure",
        action="store_true",
        default=False,
        help="Alias for --tls-insecure",
    )
    ap.add_argument(
        "--tls-ca-cert",
        default=DEFAULT_TLS_CA_CERT,
        help="Path to custom CA certificate bundle for TLS verification",
    )
    ap.add_argument(
        "--tls-pin",
        default=DEFAULT_TLS_PIN,
        help="Expected SHA-256 fingerprint of the receiver TLS certificate (hex)",
    )

    args = ap.parse_args(argv)

    tls_insecure = bool(args.tls_insecure or args.insecure)
    tls_active = bool(args.tls)

    req_remote_port = 0
    if args.url:
        parts = urlsplit(args.url)
        if parts.scheme.lower() == "https":
            tls_active = True
        host = parts.hostname or DEFAULT_RECEIVER
        if parts.port is not None:
            port = parts.port
        elif args.port is not None:
            port = args.port
        else:
            port = 443 if tls_active else 80
        path = parts.path
        rem = str(args.remote_port).strip("/")
        svc = str(args.service).strip("/")
        if rem.isdigit():
            req_remote_port = int(rem)
        if not path or path == "/":
            if svc and rem:
                label = svc
                path = f"/__relay/{svc}"
            elif rem:
                label = rem
                path = f"/__relay/{rem}"
            elif svc:
                label = svc
                path = f"/__relay/{svc}"
            else:
                label = "auto"
                path = "/__relay/auto"
        else:
            label = path.rsplit("/", 1)[-1] or "auto"
    else:
        host = args.receiver
        if args.port is not None:
            port = args.port
        elif "MOESH_RELAY_PORT" in os.environ:
            port = int(os.environ["MOESH_RELAY_PORT"])
        elif "MOESH_TUNNEL_RECEIVER_PORT" in os.environ:
            port = int(os.environ["MOESH_TUNNEL_RECEIVER_PORT"])
        else:
            port = 443 if tls_active else 80
        rem = str(args.remote_port).strip("/")
        svc = str(args.service).strip("/")
        if rem.isdigit():
            req_remote_port = int(rem)
        if svc and rem:
            label = svc
            path = f"/__relay/{svc}"
        elif rem:
            label = rem
            path = f"/__relay/{rem}"
        elif svc:
            label = svc
            path = f"/__relay/{svc}"
        else:
            label = "auto"
            path = "/__relay/auto"

    if not host:
        ap.error("no receiver specified: provide --receiver or set MOESH_RELAY_RECEIVER")

    ssl_context = (
        create_ssl_context(insecure=tls_insecure, ca_cert=args.tls_ca_cert)
        if tls_active
        else None
    )

    if args.probe:
        return print_probe(
            host,
            port,
            args.token,
            tls=tls_active,
            tls_insecure=tls_insecure,
            tls_ca_cert=args.tls_ca_cert,
            tls_pin=args.tls_pin,
            ssl_context=ssl_context,
        )

    target_host, _, target_port_s = args.target.rpartition(":")
    if not target_host:
        target_host = "127.0.0.1"
    target_port = int(target_port_s)
    workers = max(1, args.workers)

    proto_str = " (TLS)" if tls_active else ""
    auth_str = f" [auth: {mask_token(args.token)}]" if args.token else ""
    log(
        f"starting relay: target={label!r} path={path} "
        f"-> local {target_host}:{target_port} ({workers} standby workers) via {host}:{port}{proto_str}{auth_str}"
    )

    carrier_id = derive_carrier_id(
        args.id, scope=f"{path}:{req_remote_port}:{target_host}:{target_port}"
    )
    refused = threading.Event()
    claim_wait = args.claim_wait
    for i in range(workers):
        threading.Thread(
            target=worker,
            args=(
                i,
                host,
                port,
                path,
                target_host,
                target_port,
                args.idle,
                carrier_id,
                refused,
                claim_wait,
                req_remote_port,
                args.session_idle,
                args.token,
                tls_active,
                tls_insecure,
                args.tls_ca_cert,
                args.tls_pin,
                ssl_context,
                workers,
            ),
            daemon=True,
        ).start()

    refused.wait()
    log("exiting: the receiver refused this relay (port or name already in use)")
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
