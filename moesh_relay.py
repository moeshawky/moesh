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
import socket
import threading
import time
from typing import Any
from urllib.parse import urlsplit

from moesh_wire import RELAY_PAIR_MARKER, RELAY_PAIRING_EVENT

# Reads MOESH_RELAY_RECEIVER from the environment and defaults to an empty string; supplies the default --receiver host for the relay CLI.
DEFAULT_RECEIVER = os.environ.get(
    "MOESH_RELAY_RECEIVER", os.environ.get("MOESH_TUNNEL_RECEIVER", "")
)
# Reads MOESH_RELAY_PORT and converts it to int with default 80; an invalid value raises ValueError during import.
DEFAULT_RECEIVER_PORT = int(
    os.environ.get(
        "MOESH_RELAY_PORT", os.environ.get("MOESH_TUNNEL_RECEIVER_PORT", "80")
    )
)
# Reads MOESH_RELAY_TARGET and defaults to 127.0.0.1:8000; used as the default upstream target address.
DEFAULT_TARGET = os.environ.get("MOESH_RELAY_TARGET", "127.0.0.1:8000")
# Reads MOESH_RELAY_WORKERS and converts it to int with default 4; invalid environment text raises ValueError at import.
DEFAULT_WORKERS = int(os.environ.get("MOESH_RELAY_WORKERS", "4"))
# Reads MOESH_RELAY_IDLE and converts it to int with default 900 seconds; invalid environment text raises ValueError at import.
DEFAULT_IDLE = int(os.environ.get("MOESH_RELAY_IDLE", "900"))
# Idle timeout in seconds for an active paired TCP session before closing half-open keep-alive sockets.
DEFAULT_SESSION_IDLE = int(os.environ.get("MOESH_RELAY_SESSION_IDLE", "120"))

_log_lock = threading.Lock()
_port_logged = False


def derive_carrier_id(explicit_id: str = "") -> str:
    """Return a persistent carrier ID from explicit argument, env, or stable host identity.

    When neither explicit argument nor ``MOESH_RELAY_ID`` is provided, derives a
    stable 16-hex identity from the machine ID (/etc/machine-id, /var/lib/dbus/machine-id)
    so restarts do not generate alien carrier IDs that collide with prior leases.

    Preconditions:
        ``explicit_id`` is an optional string passed from CLI arguments.
    Postconditions:
        Returns a non-empty hex carrier ID string.
    Failure Modes:
        If file access fails or machine-id is absent, falls back to os.urandom(8).hex().
    """
    explicit = explicit_id.strip() or os.environ.get("MOESH_RELAY_ID", "").strip()
    if explicit:
        return explicit
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(path, encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
        except OSError:
            pass
    return os.urandom(8).hex()


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
    """
    if idle_timeout > 0:
        a.settimeout(idle_timeout)
        b.settimeout(idle_timeout)
    done = threading.Event()
    error_occurred = threading.Event()

    def copy(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(65536)
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


def fetch_status(host: str, port: int, auth_token: str = "") -> dict[str, Any]:
    """Query ``GET /__moesh/status`` on the receiver and return the parsed JSON."""
    auth = f"X-Moesh-Relay-Auth: {auth_token}\r\n" if auth_token else ""
    with socket.create_connection((host, port), timeout=10) as sock:
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


def print_probe(host: str, port: int, auth_token: str = "") -> int:
    """Fetch and print receiver port and host status."""
    try:
        data = fetch_status(host, port, auth_token)
    except Exception as exc:
        log(f"probe failed against {host}:{port}: {exc}")
        return 1
    print(json.dumps(data, indent=2))
    return 0


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
    sock = socket.create_connection((host, port), timeout=20)
    sock.settimeout(header_timeout)
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
    sock.sendall(req)
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
        sock.close()
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
    return sock, assigned, leftover, event_mode


def _serve_session(
    index: int,
    sock: socket.socket,
    first: bytes,
    target_host: str,
    target_port: int,
    session_idle: int,
) -> None:
    """Connect to local target, forward initial bytes, and splice until closed."""
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
) -> None:
    """Worker maintaining one queued standby tunnel at a time.

    As soon as a standby tunnel is paired and receives its first peer bytes,
    the active session is handed off to a background thread and this worker
    immediately dials a replacement standby tunnel.  This prevents HTTP
    keep-alive pools from exhausting the standby tunnel queue (measured
    2026-10-26: 4 keep-alive sockets previously parked all 4 workers).

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
    while True:
        sock = None
        try:
            sock, assigned_port, leftover, event_mode = connect_tunnel(
                host,
                port,
                path,
                carrier_id,
                remote_port=remote_port,
                auth_token=token,
                header_timeout=float(max(idle, 20)),
            )
            incident_deadline = None
            if not _port_logged and assigned_port > 0:
                _port_logged = True
                log(
                    f"bound receiver port {host}:{assigned_port} -> "
                    f"local {target_host}:{target_port}"
                )
            sock.settimeout(idle)
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
            threading.Thread(
                target=_serve_session,
                args=(index, sock, first, target_host, target_port, session_idle),
                daemon=True,
            ).start()
            sock = None
        except TimeoutError:
            # Idle timeout without peer — redial fresh socket to keep queue alive
            if sock:
                with contextlib.suppress(OSError):
                    sock.close()
        except RelayRefused as err:
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
            if sock:
                with contextlib.suppress(OSError):
                    sock.close()
            time.sleep(2)


def main(argv: list[str] | None = None) -> int:
    """Parses argv with environment-backed defaults, configures the relay, runs its process loop, and returns an integer exit status."""
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
        "--service",
        default=os.environ.get("MOESH_RELAY_SERVICE", ""),
        help="Optional relay label/name (e.g. 'web' or port number; default: auto)",
    )
    ap.add_argument(
        "--receiver",
        default=DEFAULT_RECEIVER,
        help="Receiver host (or set MOESH_RELAY_RECEIVER / MOESH_TUNNEL_RECEIVER)",
    )
    ap.add_argument(
        "--port",
        type=int,
        default=DEFAULT_RECEIVER_PORT,
        help="Receiver HTTP port (default 80)",
    )
    ap.add_argument(
        "--url",
        default="",
        help="Full URL override (e.g. http://receiver.example.com/__relay/26426)",
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
        default=os.environ.get("MOESH_RELAY_TOKEN", ""),
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
        help="Idle timeout in seconds for active paired TCP sessions (default 120)",
    )
    ap.add_argument(
        "--probe",
        action="store_true",
        help="Query receiver /__moesh/status for open/free/in-use ports and active hosts",
    )

    args = ap.parse_args(argv)

    if args.probe:
        host = args.receiver
        port = args.port
        if args.url:
            parts = urlsplit(args.url)
            host = parts.hostname or host
            port = parts.port or port
        if not host:
            ap.error("no receiver specified: provide --receiver or set MOESH_RELAY_RECEIVER")
        return print_probe(host, port, args.token)

    req_remote_port = 0
    if args.url:
        parts = urlsplit(args.url)
        host = parts.hostname or DEFAULT_RECEIVER
        port = parts.port or 80
        path = parts.path
        label = path.rsplit("/", 1)[-1]
    else:
        host = args.receiver
        port = args.port
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

    target_host, _, target_port_s = args.target.rpartition(":")
    if not target_host:
        target_host = "127.0.0.1"
    target_port = int(target_port_s)
    workers = max(1, args.workers)

    log(
        f"starting relay: target={label!r} path={path} "
        f"-> local {target_host}:{target_port} ({workers} standby workers) via {host}:{port}"
    )

    carrier_id = derive_carrier_id(args.id)
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
            ),
            daemon=True,
        ).start()

    refused.wait()
    log("exiting: the receiver refused this relay (port or name already in use)")
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
