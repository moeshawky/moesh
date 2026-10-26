#!/usr/bin/env python3
"""HTTP-Upgrade bridge: the host shell tunnel — legacy plaintext (v1) and
encrypted (v2) — plus a public relay.

Preconditions:
    * A listener in front of the receiver (reverse proxy or direct) forwards
      one HTTP/1.1 route to the tunnel listen address (default
      ``127.0.0.1:9447``).  The v2 path is ``/__moesh/tunnel`` on that route.
    * A host dials in with an HTTP Upgrade handshake on ``/__moesh/tunnel``
      (shell) or ``/__relay/<service>`` (relay).  The v1 shell path
      ``/__tunnel/v1`` is the legacy plaintext product's path and is kept
      for rollback; it can be refused with ``MOESH_BRIDGE_ALLOW_V1=0`` and
      there is no automatic downgrade.
Postconditions:
    Once a 101 is sent, the connection becomes a raw byte pipe and is queued
    by path.  The operator socket on 127.0.0.1:44440 pops only the v1 shell
    queue; the operator socket on 127.0.0.1:44441 pops only the v2 shell
    queue; each connection on a public port named in ``MOESH_RELAYS`` only
    sees the ``/__relay/<service>`` queue mapped to that port and is spliced
    to it.  A second carrier dialing a service that a live carrier holds is
    refused with ``409 Conflict`` and a reason.  Bytes are relayed both ways
    until either side closes.
Side effects:
    Listens on 127.0.0.1:9447 (tunnel), 127.0.0.1:44440 (operator v1),
    127.0.0.1:44441 (operator v2) and the public ports named in
    ``MOESH_RELAYS`` (relay; none by default).  Writes one log line per
    transition.  A port that is already bound is logged and skipped; the
    remaining listeners stay up.
Notes:
    No SSH, no TLS, no frpc, no third-party daemon.  The 101 is the only HTTP
    spoken; after it the protocol is opaque bytes.  TLS for the relayed
    service terminates on the host behind the relay — the relay never sees
    plaintext.

    The v2 shell tunnel is the encrypted one (``moesh-tunnel-v2``): the bridge
    stays a blind byte broker, so it never holds plaintext terminal data.  The
    v1 (``websocket``) shell path is kept for rollback and can be refused with
    ``MOESH_BRIDGE_ALLOW_V1=0``.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import queue
import socket
import sys
import threading
import time
from typing import TYPE_CHECKING, Any

from moesh_wire import (
    DEFAULT_HOST,
    PRELUDE_PREFIX,
    TUNNEL_PATH,
    UPGRADE_TOKEN,
)

if TYPE_CHECKING:
    from collections.abc import Callable

_TUNNEL_LISTEN = os.environ.get("MOESH_BRIDGE_TUNNEL_LISTEN", "127.0.0.1:9447")
_OPERATOR_LISTEN = os.environ.get("MOESH_BRIDGE_OPERATOR_LISTEN", "127.0.0.1:44440")
_OPERATOR_V2_LISTEN = os.environ.get(
    "MOESH_BRIDGE_OPERATOR_V2_LISTEN", "127.0.0.1:44441"
)
# The relay is meant to be reachable from outside the receiver host: it is
# the public side of a /__relay/<service> path, and the operator firewall is
# what limits it.
RELAY_HOST = "0.0.0.0"  # noqa: S104
# True unless MOESH_BRIDGE_ALLOW_V1 is set to 0; controls whether V1 tunnel and relay paths are accepted.
ALLOW_V1 = os.environ.get("MOESH_BRIDGE_ALLOW_V1", "1") != "0"

# Constant prefix /__relay/ used to classify relay HTTP paths.
RELAY_PATH_PREFIX = "/__relay/"
# Constant path /__tunnel/v1 used for the V1 WebSocket tunnel endpoint.
V1_TUNNEL_PATH = "/__tunnel/v1"
# Prefix string formed as the base tunnel path plus a slash; used to classify tunnel request paths.
TUNNEL_PATH_PREFIX = TUNNEL_PATH + "/"
# WebSocket GUID bytes combined with the client key to compute Sec-WebSocket-Accept.
GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_shell: queue.Queue[socket.socket] = queue.Queue(maxsize=8)
_shell_v2: dict[str, queue.Queue[socket.socket]] = {}
_registry_lock = threading.Lock()
# Hard cap of 256 entries in _shell_v2; host_queue returns None instead of creating another queue at the cap.
MAX_HOST_QUEUES = 256

_listeners_up = 0
_listeners_lock = threading.Lock()


def host_queue(name: str) -> queue.Queue[socket.socket] | None:
    """Return the queue of one host, creating it on first use.

    Refuses new names when the map is at MAX_HOST_QUEUES: no eviction loops
    that orphan pair() waiters (RC-4/RC-5). Returns None when full so the
    caller can refuse without sending 101.
    """
    with _registry_lock:
        item = _shell_v2.get(name)
        if item is not None:
            return item
        if len(_shell_v2) >= MAX_HOST_QUEUES:
            return None
        item = queue.Queue(maxsize=8)
        _shell_v2[name] = item
        return item


def valid_host(name: str) -> bool:
    """Return True when the name is safe to use as a routing label."""
    if not name or len(name) > 64:
        return False
    return all(ch.isalnum() or ch in "._-" for ch in name)


_relays: dict[str, queue.Queue[socket.socket]] = {}
_relays_lock = threading.Lock()
_bound_relay_ports: set[int] = set()
_unavailable_ports: dict[int, str] = {}
DEFAULT_RELAY_PORTS = "26420-26430"


def relay_queue(name: str) -> queue.Queue[socket.socket]:
    """Return the queue for one relay key (port or service), creating it on first use."""
    with _relays_lock:
        item = _relays.get(name)
        if item is not None:
            return item
        item = queue.Queue(maxsize=64)
        _relays[name] = item
        return item


# One carrier owns one relay port/name and one shell host slot at a time, the
# way frps refuses a second client for a proxy name or remote_port that is
# taken.  Measured 2026-10-26 on a live deployment: two carriers dialing one
# path shared the oldest-first queue, the public peer landed on whichever
# tunnel was oldest (often the dead one), and neither carrier was told.  The
# bridge stays blind, and refuses a conflicting carrier with HTTP 409 Conflict.
RELAY_ID_HEADER = b"x-moesh-relay-id:"
CARRIER_ID_HEADER = b"x-moesh-carrier-id:"
RELAY_PORT_HEADER = b"x-moesh-relay-port:"
RELAY_LEASE_GRACE = float(os.environ.get("MOESH_BRIDGE_LEASE_GRACE", "1.5"))
_leases: dict[str, dict[str, Any]] = {}
_port_leases: dict[int, dict[str, Any]] = {}
_host_leases: dict[str, dict[str, Any]] = {}
_leases_lock = threading.Lock()
_relay_active: dict[str, int] = {}
_host_active: dict[str, int] = {}


def extract_carrier(hdrs: bytes, addr: tuple[str, int]) -> str:
    """Extract carrier identity from headers, falling back to forwarded client IP."""
    carrier = ""
    fwd = ""
    for line in hdrs.split(b"\r\n")[1:]:
        low = line.lower()
        if low.startswith((CARRIER_ID_HEADER, RELAY_ID_HEADER)):
            val = line.split(b":", 1)[1].strip().decode("latin-1", "replace")[:64]
            if val:
                carrier = val
        elif low.startswith((b"cf-connecting-ip:", b"x-real-ip:", b"x-forwarded-for:")):
            cand = (
                line.split(b":", 1)[1]
                .split(b",")[0]
                .strip()
                .decode("latin-1", "replace")
            )
            if cand and not fwd:
                fwd = cand
    if carrier:
        return carrier
    return "addr:" + (fwd or addr[0])


def live_queued(q: queue.Queue[socket.socket]) -> int:
    """Purge closed sockets from ``q`` and return the count of live queued tunnels."""
    with q.mutex:
        kept: list[socket.socket] = []
        dead: list[socket.socket] = []
        for s in list(q.queue):
            if alive(s):
                kept.append(s)
            else:
                dead.append(s)
        if dead:
            q.queue.clear()
            q.queue.extend(kept)
    for s in dead:
        with contextlib.suppress(OSError):
            s.close()
    return len(kept)


def _queue_busy(key: str, q: queue.Queue[socket.socket], lease: dict[str, Any] | None) -> bool:
    """Return True while ``key`` still has a live queued tunnel, active pairing, or grace."""
    if lease is None:
        return False
    with _leases_lock:
        active = _relay_active.get(key, 0)
    if active > 0 or live_queued(q) > 0:
        return True
    return time.time() - float(lease["seen"]) < RELAY_LEASE_GRACE


def free_relay_ports() -> list[int]:
    """Return sorted list of bound relay ports not currently held by any live carrier."""
    with _leases_lock:
        bound = sorted(_bound_relay_ports)
        port_leases_snap = {p: dict(v) for p, v in _port_leases.items()}
    free: list[int] = []
    for p in bound:
        q = relay_queue(str(p))
        if not _queue_busy(str(p), q, port_leases_snap.get(p)):
            free.append(p)
    return free


def _free_ports_summary() -> str:
    """Format free relay ports for conflict error messages."""
    free = free_relay_ports()
    if not free:
        return "none"
    return ", ".join(str(p) for p in free)


def claim_host(
    host: str, carrier: str, q: queue.Queue[socket.socket]
) -> str | None:
    """Grant or refuse v2 shell ``host`` to ``carrier``; return None on grant, else reason."""
    queued = live_queued(q)
    with _leases_lock:
        active = _host_active.get(host, 0)
        lease = _host_leases.get(host)
        if lease is not None and lease["id"] != carrier and (queued > 0 or active > 0):
            held = int(time.time() - float(lease["since"]))
            active_hosts = [
                h for h, hq in _shell_v2.items() if live_queued(hq) > 0 or _host_active.get(h, 0) > 0
            ]
            active_str = ", ".join(sorted(active_hosts)) or host
            return (
                f"host {host!r} is already in use by another tunnel "
                f"(held for {held}s, {queued} queued, {active} active); active hosts: {active_str}"
            )
        if lease is None or lease["id"] != carrier:
            _host_leases[host] = {"id": carrier, "since": time.time(), "seen": time.time()}
        else:
            lease["seen"] = time.time()
    return None


def touch_host(host: str, delta: int = 0) -> None:
    """Adjust the active operator pairing count for ``host``."""
    with _leases_lock:
        _host_active[host] = max(0, _host_active.get(host, 0) + delta)
        lease = _host_leases.get(host)
        if lease is not None:
            lease["seen"] = time.time()


def resolve_and_claim_relay(
    svc: str,
    carrier: str,
    requested_port: int,
) -> tuple[queue.Queue[socket.socket], int, str | None]:
    """Resolve relay target ``svc`` to a queue and port, checking carrier leases.

    Returns ``(queue, assigned_port, error_reason)``.
    """
    static_map = relay_services()
    with _leases_lock:
        bound = sorted(_bound_relay_ports)
        unavail = dict(_unavailable_ports)

    # Unit-test or unbound mode: no public relay listeners were bound.
    if not bound and not unavail:
        q = relay_queue(svc)
        reason = claim_relay(svc, carrier, q, port=0)
        return q, 0, reason

    port = 0
    if svc == "auto":
        with _leases_lock:
            for p in bound:
                pl = _port_leases.get(p)
                if pl is not None and pl["id"] == carrier:
                    port = p
                    break
        if port == 0:
            free = free_relay_ports()
            if not free:
                return (
                    relay_queue("auto"),
                    0,
                    f"no free relay ports available; open ports: {', '.join(str(p) for p in bound)}",
                )
            port = free[0]
        svc = str(port)
    elif svc.isdigit():
        port = int(svc)
    elif requested_port > 0:
        port = requested_port
    elif svc in static_map:
        port = static_map[svc]
    else:
        with _leases_lock:
            existing = _leases.get(svc)
            if existing is not None and int(existing.get("port", 0)) in bound:
                port = int(existing["port"])
        if port == 0:
            free = free_relay_ports()
            if not free:
                return (
                    relay_queue(svc),
                    0,
                    f"no free relay ports available for {svc!r}; open ports: {', '.join(str(p) for p in bound)}",
                )
            port = free[0]

    if port in unavail:
        return (
            relay_queue(str(port)),
            port,
            f"relay port {port} is unavailable on receiver ({unavail[port]}); "
            f"free ports: {_free_ports_summary()}",
        )
    if bound and port not in bound:
        return (
            relay_queue(str(port)),
            port,
            f"relay port {port} is not in the open relay port pool; "
            f"free ports: {_free_ports_summary()}",
        )

    q = relay_queue(str(port))
    reason = claim_relay(svc, carrier, q, port=port)
    return q, port, reason


def claim_relay(
    svc: str,
    carrier: str,
    q: queue.Queue[socket.socket],
    port: int = 0,
) -> str | None:
    """Grant or refuse ``svc`` (and ``port``) to ``carrier``; return None on grant, else reason."""
    key = str(port) if port > 0 else svc
    with _leases_lock:
        name_lease = _leases.get(svc)
        port_lease = _port_leases.get(port) if port > 0 else None

    if name_lease is not None and name_lease["id"] != carrier:
        prev_port = int(name_lease.get("port", 0))
        prev_key = str(prev_port) if prev_port > 0 else svc
        prev_q = relay_queue(prev_key)
        if _queue_busy(prev_key, prev_q, name_lease):
            held = int(time.time() - float(name_lease["since"]))
            port_note = f" on port {prev_port}" if prev_port > 0 else ""
            return (
                f"relay service {svc!r} is already held by another carrier"
                f"{port_note} (for {held}s); free ports: {_free_ports_summary()}"
            )

    if (
        port > 0
        and port_lease is not None
        and port_lease["id"] != carrier
        and _queue_busy(key, q, port_lease)
    ):
        held = int(time.time() - float(port_lease["since"]))
        owner_name = str(port_lease.get("name", port))
        return (
            f"relay port {port} is already in use by another carrier "
            f"(service {owner_name!r}, for {held}s); free ports: {_free_ports_summary()}"
        )

    now = time.time()
    with _leases_lock:
        if name_lease is None or name_lease["id"] != carrier:
            _leases[svc] = {"id": carrier, "port": port, "since": now, "seen": now}
        else:
            name_lease["seen"] = now
            name_lease["port"] = port
        if port > 0:
            if port_lease is None or port_lease["id"] != carrier:
                _port_leases[port] = {
                    "id": carrier,
                    "name": svc,
                    "since": now,
                    "seen": now,
                }
            else:
                port_lease["seen"] = now
                port_lease["name"] = svc
    return None


def touch_relay(svc: str, delta: int = 0) -> None:
    """Refresh the lease clock and adjust the active-pairing count for ``svc``."""
    with _leases_lock:
        _relay_active[svc] = max(0, _relay_active.get(svc, 0) + delta)
        lease = _leases.get(svc)
        if lease is not None:
            lease["seen"] = time.time()
        if svc.isdigit():
            pl = _port_leases.get(int(svc))
            if pl is not None:
                pl["seen"] = time.time()
                name = str(pl.get("name", ""))
                if name and name in _leases:
                    _leases[name]["seen"] = time.time()


def bridge_status() -> dict[str, Any]:
    """Return a JSON-serializable snapshot of active hosts and relay ports."""
    with _registry_lock:
        host_items = list(_shell_v2.items())
    hosts_in_use: list[str] = []
    host_details: dict[str, dict[str, int]] = {}
    for h_name, h_q in sorted(host_items):
        q_count = live_queued(h_q)
        a_count = _host_active.get(h_name, 0)
        if q_count > 0 or a_count > 0:
            hosts_in_use.append(h_name)
            host_details[h_name] = {"queued": q_count, "active": a_count}

    with _leases_lock:
        bound = sorted(_bound_relay_ports)
        unavail = {str(k): v for k, v in sorted(_unavailable_ports.items())}
        port_leases_snap = {p: dict(v) for p, v in _port_leases.items()}

    ports_free: list[int] = []
    ports_in_use: dict[str, dict[str, Any]] = {}
    names_in_use: dict[str, int] = {}
    for p in bound:
        q = relay_queue(str(p))
        pl = port_leases_snap.get(p)
        if _queue_busy(str(p), q, pl):
            q_cnt = live_queued(q)
            a_cnt = _relay_active.get(str(p), 0)
            svc_name = str(pl.get("name", p)) if pl else str(p)
            ports_in_use[str(p)] = {
                "name": svc_name,
                "queued": q_cnt,
                "active": a_cnt,
                "since": int(pl["since"]) if pl else 0,
            }
            names_in_use[svc_name] = p
        else:
            ports_free.append(p)

    return {
        "ok": True,
        "hosts": {
            "in_use": hosts_in_use,
            "details": host_details,
        },
        "relay": {
            "ports_open": bound,
            "ports_free": ports_free,
            "ports_in_use": ports_in_use,
            "ports_unavailable": unavail,
            "names_in_use": names_in_use,
        },
    }


def split_hostport(value: str, default_host: str = "127.0.0.1") -> tuple[str, int] | None:
    """Split ``host:port`` into a tuple, defaulting the host when absent.

    Returns None when the port is empty or non-numeric instead of raising
    ValueError, so a bad listen spec can be skipped at startup (G-ERR-1).
    """
    host, _, port = value.rpartition(":")
    if not host:
        host = default_host
    if not port or not port.isdigit():
        return None
    return host, int(port)


# Parsed (host, port) tuple for the tunnel listener from _TUNNEL_LISTEN, possibly None when unset; serve skips a None listener.
TUNNEL_LISTEN = split_hostport(_TUNNEL_LISTEN)
# Parsed (host, port) tuple for the operator listener from _OPERATOR_LISTEN, possibly None when unset; serve skips a None listener.
OPERATOR_LISTEN = split_hostport(_OPERATOR_LISTEN)
# Parsed (host, port) tuple for the operator v2 listener from _OPERATOR_V2_LISTEN, possibly None when unset; serve skips a None listener.
OPERATOR_V2_LISTEN = split_hostport(_OPERATOR_V2_LISTEN)


def log(msg: str) -> None:
    """Prints a timestamped message to stdout with flush enabled and performs no locking."""
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def read_headers(conn: socket.socket) -> bytes:
    """Read bytes through the end of the HTTP header block.

    Peeks with MSG_PEEK until ``\\r\\n\\r\\n`` is present without consuming,
    then consumes exactly the header bytes (through the delimiter) and leaves
    any tail on the socket for ``pump``.  Consuming past the delimiter drops
    bytes the peer expects to be relayed (RC-10).
    """
    buf = b""
    conn.settimeout(15)
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(65536, socket.MSG_PEEK)
        if not chunk:
            raise ConnectionError("closed during headers")
        # recv(MSG_PEEK) returns the cumulative available prefix without
        # consuming, so appending duplicates data on partial delivery
        # (measured 2026-10-23: a two-chunk send inflated `end` past the
        # bytes on the wire and conn.recv(end) hung until socket timeout,
        # dropping the upgraded connection before pump). Replace buf with
        # each peek so buf holds the full available prefix up to the 64KB
        # peek cap below; a header larger than the peek never exposes its
        # \r\n\r\n delimiter and hangs until socket timeout. The tail past
        # \r\n\r\n stays on the socket for pump.
        buf = chunk
        if len(buf) > 65536:
            raise ConnectionError("header block too large")
    end = buf.find(b"\r\n\r\n") + 4
    consumed = b""
    while len(consumed) < end:
        chunk = conn.recv(end - len(consumed))
        if not chunk:
            raise ConnectionError("closed during header consume")
        consumed += chunk
    return consumed


def request_path(headers: bytes) -> str:
    """Return the path from an HTTP request line, or ``/`` when malformed."""
    line = headers.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    parts = line.split()
    return parts[1] if len(parts) >= 2 else "/"


def upgrade_token(headers: bytes) -> str:
    """Return the lowercased protocol token from the Upgrade header."""
    for line in headers.split(b"\r\n")[1:]:
        if line.lower().startswith(b"upgrade:"):
            return line.split(b":", 1)[1].strip().decode("latin-1", "replace").lower()
    return ""


def refuse(
    conn: socket.socket, status: str, reason: str, detail: str = ""
) -> None:
    """Answer a handshake refusal and close the connection.

    ``detail`` is sent as a plain-text body so the dialer can show the operator
    why it was refused instead of retrying blind.
    """
    body = detail.encode("latin-1", "replace")
    with contextlib.suppress(OSError):
        conn.sendall(
            (
                f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\n"
                "Content-Type: text/plain\r\nConnection: close\r\n\r\n"
            ).encode()
            + body
        )
    with contextlib.suppress(OSError):
        conn.close()
    log(f"refused handshake: {reason}")


def tunnel_conn(conn: socket.socket, addr: tuple[str, int]) -> None:
    """Accept one host tunnel: answer the Upgrade, then queue it by path.

    Two upgrade tokens are accepted:

    ``moesh-tunnel-v2``
        The encrypted shell tunnel.  The connection carries a Noise session
        and framed records; the bridge relays the ciphertext opaquely and never
        terminates the session.
    ``websocket``
        The legacy v1 shell tunnel and the relay.  Kept for rollback;
        the v1 *shell* path can be refused with ``MOESH_BRIDGE_ALLOW_V1=0`` while
        relay paths stay available.
    """
    try:
        hdrs = read_headers(conn)
        path = request_path(hdrs)
        clean_path = path.split("?", 1)[0]
        if clean_path in ("/__moesh/status", "/__relay/status"):
            status_payload = bridge_status()
            body = json.dumps(status_payload, indent=2).encode("utf-8")
            with contextlib.suppress(OSError):
                conn.sendall(
                    (
                        f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                    ).encode()
                    + body
                )
            with contextlib.suppress(OSError):
                conn.close()
            return
        token = upgrade_token(hdrs)
        conn_hdr = ""
        for line in hdrs.split(b"\r\n")[1:]:
            if line.lower().startswith(b"connection:"):
                conn_hdr = (
                    line.split(b":", 1)[1]
                    .strip()
                    .decode("latin-1", "replace")
                    .lower()
                )
        tokens = [t.strip() for t in conn_hdr.split(",")]
        if "upgrade" not in tokens:
            refuse(conn, "400 Bad Request", "Connection header must contain Upgrade")
            return
        if token == UPGRADE_TOKEN:
            if path == TUNNEL_PATH:
                host = DEFAULT_HOST
            elif path.startswith(TUNNEL_PATH_PREFIX):
                host = path[len(TUNNEL_PATH_PREFIX) :]
            else:
                refuse(conn, "400 Bad Request", f"unknown v2 path {path}")
                return
            if not valid_host(host):
                refuse(conn, "400 Bad Request", f"invalid host name {host!r}")
                return
            q = host_queue(host)
            if q is None:
                refuse(conn, "503 Service Unavailable", "host queue full")
                return
            carrier = extract_carrier(hdrs, addr)
            reason = claim_host(host, carrier, q)
            if reason is not None:
                refuse(conn, "409 Conflict", reason, detail=reason)
                return
            try:
                q.put_nowait(conn)
            except queue.Full:
                log(f"tunnel queue full — dropping {addr}")
                with contextlib.suppress(OSError):
                    conn.close()
                return
            conn.sendall(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: " + UPGRADE_TOKEN.encode() + b"\r\n"
                b"Connection: Upgrade\r\n"
                b"X-Moesh-Tunnel-Version: 2\r\n"
                b"X-Moesh-Tunnel-Name: " + host.encode() + b"\r\n\r\n"
            )
            conn.settimeout(None)
            log(f"host tunnel v2 attached from {addr} host {host}")
            return
        if token != "websocket":  # noqa: S105 - a protocol identifier, not a secret
            refuse(conn, "400 Bad Request", f"unsupported upgrade token {token!r}")
            return
        # The v1 shell path and the relay path are the legacy product's
        # paths; only the v2 path is moesh's.
        assigned_port = 0
        svc = ""
        if path == V1_TUNNEL_PATH:
            if not ALLOW_V1:
                refuse(
                    conn, "426 Upgrade Required", "v1 shell tunnel disabled by cutover"
                )
                return
            q = _shell
        elif path.startswith(RELAY_PATH_PREFIX):
            svc = path[len(RELAY_PATH_PREFIX) :]
            if not valid_host(svc):
                refuse(conn, "400 Bad Request", f"invalid relay service {svc!r}")
                return
            carrier = extract_carrier(hdrs, addr)
            req_port = 0
            for line in hdrs.split(b"\r\n")[1:]:
                if line.lower().startswith(RELAY_PORT_HEADER):
                    port_txt = line.split(b":", 1)[1].strip().decode("latin-1", "replace")
                    if port_txt.isdigit():
                        req_port = int(port_txt)
            q, assigned_port, reason = resolve_and_claim_relay(svc, carrier, req_port)
            if reason is not None:
                refuse(conn, "409 Conflict", reason, detail=reason)
                return
        else:
            refuse(conn, "400 Bad Request", f"unknown v1 path {path}")
            return
        key = b""
        for line in hdrs.split(b"\r\n"):
            if line.lower().startswith(b"sec-websocket-key:"):
                key = line.split(b":", 1)[1].strip()
        if not key:
            refuse(conn, "400 Bad Request", "handshake without Sec-WebSocket-Key")
            return
        # SHA-1 is not a choice here: RFC 6455 specifies it for the
        # Sec-WebSocket-Accept value, and this path carries no secret.
        accept = base64.b64encode(hashlib.sha1(key + GUID).digest())  # noqa: S324
        extra_hdrs = b""
        if svc:
            extra_hdrs += b"X-Moesh-Relay-Name: " + svc.encode("latin-1", "replace") + b"\r\n"
        if assigned_port > 0:
            extra_hdrs += f"X-Moesh-Relay-Port: {assigned_port}\r\n".encode("latin-1")
        conn.sendall(
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: " + accept + b"\r\n"
            + extra_hdrs
            + b"\r\n"
        )
        conn.settimeout(None)
        port_log = f" port {assigned_port}" if assigned_port > 0 else ""
        log(f"host tunnel attached from {addr} path {path}{port_log}")
        q.put(conn, timeout=120)
    except queue.Full:
        log(f"tunnel queue full — dropping {addr}")
        with contextlib.suppress(OSError):
            conn.close()
    except Exception as exc:
        log(f"tunnel error: {exc!r}")
        with contextlib.suppress(OSError):
            conn.close()


def alive(sock: socket.socket) -> bool:
    """Return True if a queued tunnel is still open.

    A tunnel that received its 101 and then disconnected sits in the queue
    looking healthy; only a peek reveals the EOF. Leaving it there pairs the
    next peer with a corpse (observed: pump ended in the same second, peer
    bytes never delivered).
    """
    try:
        sock.setblocking(False)
        try:
            data = sock.recv(1, socket.MSG_PEEK)
        finally:
            sock.setblocking(True)
        return data != b""
    except BlockingIOError:
        return True
    except OSError:
        return False


def pump(a: socket.socket, b: socket.socket) -> None:
    """Relay bytes both ways until either side closes."""

    def copy(src: socket.socket, dst: socket.socket, name: str) -> None:
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                dst.shutdown(socket.SHUT_WR)
            # Symmetric read shutdown (measured 2026-10-26: when host->peer
            # ended first, peer->host stayed blocked in b.recv() on keep-alive
            # peers and leaked CLOSE-WAIT sockets forever because SHUT_RD only
            # ran after peer->host returned).
            with contextlib.suppress(OSError):
                dst.shutdown(socket.SHUT_RD)
            log(f"pump {name} ended")

    t = threading.Thread(target=copy, args=(a, b, "host->peer"), daemon=True)
    t.start()
    copy(b, a, "peer->host")
    # One direction EOF'd: force the surviving copy thread to EOF too so it
    # returns instead of blocking on recv() from a half-open peer.
    # shutdown(SHUT_RD) makes recv() return b'' on both sockets, so both
    # copy threads exit their loops and the join is unbounded — no 5s
    # deadline that can drop LATE/in-flight bytes (measured 2026-10-24:
    # t.join(timeout=5) dropped bytes on slow surviving directions;
    # shutdown + unbounded join returns promptly with bytes already
    # received preserved).
    for s in (a, b):
        with contextlib.suppress(OSError):
            s.shutdown(socket.SHUT_RD)
    t.join()
    for s in (a, b):
        with contextlib.suppress(OSError):
            s.close()
    log("pair closed")


def pair(
    conn: socket.socket,
    q: queue.Queue[socket.socket],
    label: str,
    wait: int,
) -> None:
    """Pair one incoming connection with the oldest live tunnel in ``q``."""
    try:
        log(f"{label} attached from {conn.getpeername()}")
        while True:
            nb = q.get(timeout=wait)
            if alive(nb):
                break
            log(f"discarding stale {label} tunnel")
            with contextlib.suppress(OSError):
                nb.close()
        log(f"pairing {label} with a host")
        # Both legs are unbounded once paired: a session may sit idle for
        # hours, and a socket timeout left armed on either side would tear
        # the pair down without anyone noticing.
        conn.settimeout(None)
        nb.settimeout(None)
        pump(nb, conn)
    except queue.Empty:
        log(f"{label} connected but no {label} tunnel within {wait}s")
        with contextlib.suppress(OSError):
            conn.close()


def operator_conn(conn: socket.socket, addr: tuple[str, int]) -> None:
    """Pair one operator connection with the oldest v1 shell tunnel."""
    pair(conn, _shell, "operator", 120)


def read_host_label(conn: socket.socket) -> str:
    """Return the host the operator asked for.

    The client sends ``MOESH-TUNNEL-V2 <name>\n`` before the encrypted session.
    The label is peeked, not consumed blindly: a client that sends no label
    (an older build) is treated as the default host and its first bytes
    are left untouched for the Noise handshake.

    The peek needs a timeout, but the session that follows is unbounded.  The
    timeout is therefore cleared before the socket leaves this function:
    leaving it armed made every idle operator session die after exactly 15
    seconds, because the pump's ``recv`` raised ``socket.timeout`` (an
    ``OSError``) and the pair was torn down.  Measured on the live bridge
    before the fix: EOF at t=15.0s with the pair established 15s earlier.
    """
    conn.settimeout(15)
    deadline = time.time() + 15
    try:
        # Peek only.  The bytes past the label belong to the Noise
        # handshake: a client that writes the label and its first frame in
        # one segment must not have that frame eaten here, or the agent
        # never sees a handshake and the operator waits forever.  Measured
        # 2026-10-21: the old reader consumed up to 256 bytes and dropped
        # the rest, which hung roughly one operator connection in three.
        window = b""
        while b"\n" not in window and len(window) < 256:
            if time.time() > deadline:
                return ""
            try:
                chunk = conn.recv(256, socket.MSG_PEEK)
            except OSError:
                return ""
            if not chunk:
                break
            if not PRELUDE_PREFIX.startswith(chunk[: len(PRELUDE_PREFIX)]):
                return ""
            if chunk == window:
                time.sleep(0.005)
                continue
            window = chunk
        if not window.startswith(PRELUDE_PREFIX):
            return ""
        index = window.find(b"\n")
        if index < 0:
            return ""
        # Consume exactly the label line, and nothing else.
        line = conn.recv(index + 1)
    finally:
        conn.settimeout(None)
    name = line[len(PRELUDE_PREFIX) :].decode("latin-1", "replace").strip()
    if not valid_host(name):
        return ""
    return name


def operator_v2_conn(conn: socket.socket, addr: tuple[str, int]) -> None:
    """Pair one operator connection with the host it asked for."""
    host = read_host_label(conn)
    if not host or not valid_host(host):
        log(f"operator from {addr[0]}:{addr[1]} sent invalid host label; refusing")
        with contextlib.suppress(OSError):
            conn.close()
        return
    q = host_queue(host)
    if q is None:
        with contextlib.suppress(OSError):
            conn.close()
        return
    touch_host(host, 1)
    try:
        pair(conn, q, f"operator-v2[{host}]", 120)
    finally:
        touch_host(host, -1)


def serve(
    listen: tuple[str, int] | None,
    handler: Callable[[socket.socket, tuple[str, int]], None],
    name: str,
    relay_port: int = 0,
) -> None:
    """Binds a TCP socket to listen with backlog 64, runs an accept loop, and invokes handler for each accepted connection; returns early if listen is None or bind fails."""
    global _listeners_up
    if listen is None:
        log(f"{name} listener not configured — skipping")
        return
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(listen)
        srv.listen(64)
    except OSError as exc:
        log(f"{name} bind {listen[0]}:{listen[1]} failed: {exc}")
        if relay_port > 0:
            with _leases_lock:
                _unavailable_ports[relay_port] = str(exc.strerror or exc)
        srv.close()
        return
    with _listeners_lock:
        _listeners_up += 1
    if relay_port > 0:
        with _leases_lock:
            _bound_relay_ports.add(relay_port)
    log(f"{name} listening on {listen[0]}:{listen[1]}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handler, args=(conn, addr), daemon=True).start()


def parse_port_spec(spec: str) -> list[int]:
    """Parse a comma-separated list of ports or ``start-end`` ranges."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, _, hi_s = part.partition("-")
            if lo_s.strip().isdigit() and hi_s.strip().isdigit():
                lo, hi = int(lo_s.strip()), int(hi_s.strip())
                if 0 < lo <= hi <= 65535 and (hi - lo) <= 1024:
                    ports.update(range(lo, hi + 1))
        elif part.isdigit():
            p = int(part)
            if 0 < p <= 65535:
                ports.add(p)
    return sorted(ports)


def relay_services() -> dict[str, int]:
    """Return optional static ``name:port`` aliases from ``MOESH_RELAYS``."""
    if os.environ.get("MOESH_BRIDGE_GPU_PORTS") == "" and "MOESH_RELAYS" not in os.environ:
        return {}
    raw = os.environ.get("MOESH_RELAYS", "")
    services: dict[str, int] = {}
    for item in raw.split(","):
        item = item.strip()
        if not item or ":" not in item:
            continue
        name, _, port_str = item.partition(":")
        try:
            services[name.strip()] = int(port_str.strip())
        except ValueError:
            continue
    return services


def gpu_ports() -> tuple[int, ...]:
    """Return the public relay ports configured for the bridge."""
    if "MOESH_RELAY_PORTS" in os.environ:
        raw = os.environ["MOESH_RELAY_PORTS"]
    elif "MOESH_BRIDGE_GPU_PORTS" in os.environ:
        raw = os.environ["MOESH_BRIDGE_GPU_PORTS"]
    else:
        raw = DEFAULT_RELAY_PORTS
    ports = set(parse_port_spec(raw))
    for p in relay_services().values():
        if 0 < p <= 65535:
            ports.add(p)
    return tuple(sorted(ports))


if __name__ == "__main__":
    threading.Thread(
        target=serve, args=(TUNNEL_LISTEN, tunnel_conn, "tunnel"), daemon=True
    ).start()
    threading.Thread(
        target=serve, args=(OPERATOR_LISTEN, operator_conn, "operator"), daemon=True
    ).start()
    threading.Thread(
        target=serve,
        args=(OPERATOR_V2_LISTEN, operator_v2_conn, "operator-v2"),
        daemon=True,
    ).start()
    for port in gpu_ports():
        if port <= 0:
            continue
        q = relay_queue(str(port))

        def make_relay_handler(
            queue_ref: queue.Queue[socket.socket], port_num: int
        ) -> Callable[[socket.socket, tuple[str, int]], None]:
            label = str(port_num)

            def handler(conn: socket.socket, addr: tuple[str, int]) -> None:
                touch_relay(label, 1)
                try:
                    pair(conn, queue_ref, f"relay:{port_num}", 20)
                finally:
                    touch_relay(label, -1)

            return handler

        threading.Thread(
            target=serve,
            args=(
                (RELAY_HOST, port),
                make_relay_handler(q, port),
                f"relay-{port}",
                port,
            ),
            daemon=True,
        ).start()
    # No listener owns the main thread: a bind conflict on one port must not
    # take down the other ten. SIGTERM still ends the process.
    time.sleep(0.25)
    with _listeners_lock:
        up = _listeners_up
    if up == 0:
        log("no listener came up — exiting so systemd Restart=always can run")
        sys.exit(1)
    threading.Event().wait()
