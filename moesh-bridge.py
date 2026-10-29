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
import hmac
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
    PAIR_DEAD_MARKER,
    PRELUDE_PREFIX,
    RELAY_PAIR_MARKER,
    RELAY_PAIRING_EVENT,
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


class QueuedTunnel:
    """One admitted tunnel waiting in a queue.

    ``gen`` fences the entry to the lease generation that admitted it: a
    socket left behind by an earlier owner is discarded at pairing instead of
    being spliced into the new owner's traffic.  ``ready`` closes the window
    between admission and the handshake response: the pairer will not use the
    socket until the admitting thread has finished writing its 101.
    """

    def __init__(
        self,
        sock: socket.socket,
        gen: int = 0,
        carrier: str = "",
        key: str = "",
        response: bytes = b"",
        pairing: str = "data",
    ) -> None:
        """Wrap an admitted socket with the lease and handshake state it owns."""
        self.sock = sock
        self.gen = gen
        self.carrier = carrier
        self.key = key
        self.response = response
        self.pairing = pairing
        self.ready = threading.Event()


def _sock_of(item: Any) -> socket.socket:
    """Return the socket held by a queue entry (raw or wrapped)."""
    return item.sock if isinstance(item, QueuedTunnel) else item


_relays: dict[str, queue.Queue[Any]] = {}
_relays_lock = threading.Lock()
_bound_relay_ports: set[int] = set()
_unavailable_ports: dict[int, str] = {}
DEFAULT_RELAY_PORTS = "26420-26430"

# A caller-controlled label must not be able to grow the registry without
# bound.  Queues are only created for admitted carriers and the cap is enforced
# before allocation, so a hostile loop gets a refusal, not memory.
MAX_RELAY_QUEUES = 128
# Longest a pairer waits for the admitting thread to finish its 101.
ADMISSION_READY_TIMEOUT = 10.0


def _relay_queue_locked(name: str) -> queue.Queue[Any] | None:
    """Return the queue for ``name``, creating it under the registry cap."""
    item = _relays.get(name)
    if item is not None:
        return item
    if len(_relays) >= MAX_RELAY_QUEUES:
        return None
    item = queue.Queue(maxsize=64)
    _relays[name] = item
    return item


def relay_queue(name: str) -> queue.Queue[Any] | None:
    """Return the queue for one relay key, or None when the registry is full."""
    with _relays_lock:
        return _relay_queue_locked(name)


def relay_entry(
    sock: socket.socket,
    gen: int,
    carrier: str,
    *,
    key: str = "",
    response: bytes = b"",
    pairing: str = "data",
) -> QueuedTunnel:
    """Build a queued relay entry carrying its lease generation and handshake."""
    return QueuedTunnel(
        sock=sock,
        gen=gen,
        carrier=carrier,
        key=key,
        response=response,
        pairing=pairing,
    )


# One carrier owns one relay port/name and one shell host slot at a time, the
# way frps refuses a second client for a proxy name or remote_port that is
# taken.  Measured 2026-10-26 on a live deployment: two carriers dialing one
# path shared the oldest-first queue, the public peer landed on whichever
# tunnel was oldest (often the dead one), and neither carrier was told.  The
# bridge stays blind, and refuses a conflicting carrier with HTTP 409 Conflict.
RELAY_ID_HEADER = b"x-moesh-relay-id:"
CARRIER_ID_HEADER = b"x-moesh-carrier-id:"
RELAY_PORT_HEADER = b"x-moesh-relay-port:"
RELAY_AUTH_HEADER = b"x-moesh-relay-auth:"
RELAY_PAIRING_HEADER = b"x-moesh-relay-pairing:"
RELAY_LEASE_GRACE = float(os.environ.get("MOESH_BRIDGE_LEASE_GRACE", "1.5"))

# Relay carriers are admitted by name, and until now any client that could
# reach the tunnel listener could claim one.  When this token is set, a relay
# handshake must present it and status probes must present it too.  Leaving it
# unset preserves the previous (unauthenticated) admission model, which the
# bridge now states explicitly in its status payload and startup log.
RELAY_TOKEN = os.environ.get("MOESH_BRIDGE_RELAY_TOKEN", "")
"""Shared secret required from relay carriers and status probes (empty = open)."""

PAIRING_EVENT = RELAY_PAIRING_EVENT
"""Pairing mode where the 101 is deferred until a peer is actually paired."""

PAIR_MARKER = RELAY_PAIR_MARKER
"""Marker the bridge writes before peer bytes in event-pairing mode."""

HALFCLOSE_LINGER = float(os.environ.get("MOESH_BRIDGE_HALFCLOSE_LINGER", "60"))
"""Seconds to keep one direction open after the other reaches EOF."""
_leases: dict[str, dict[str, Any]] = {}
_port_leases: dict[int, dict[str, Any]] = {}
_host_leases: dict[str, dict[str, Any]] = {}
# Monotonic per-key generations.  They survive lease release, so a socket
# queued by an earlier owner can never match a later owner's generation.
_lease_gens: dict[str, int] = {}
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


def relay_authorized(hdrs: bytes) -> bool:
    """Return True when the carrier presented the configured relay token."""
    if not RELAY_TOKEN:
        return True
    for line in hdrs.split(b"\r\n")[1:]:
        if line.lower().startswith(RELAY_AUTH_HEADER):
            presented = line.split(b":", 1)[1].strip().decode("latin-1", "replace")
            return hmac.compare_digest(presented, RELAY_TOKEN)
    return False


def live_queued(q: queue.Queue[Any]) -> int:
    """Purge closed sockets from ``q`` and return the count of live queued tunnels."""
    with q.mutex:
        kept: list[Any] = []
        dead: list[Any] = []
        for item in list(q.queue):
            if alive(_sock_of(item)):
                kept.append(item)
            else:
                dead.append(item)
        if dead:
            q.queue.clear()
            q.queue.extend(kept)
    for item in dead:
        with contextlib.suppress(OSError):
            _sock_of(item).close()
    return len(kept)


def _lease_gen_locked(key: str) -> int:
    """Return the current lease generation for ``key``; caller holds the lock."""
    return _lease_gens.get(key, 0)


def _next_gen_locked(key: str) -> int:
    """Advance and return the generation for ``key``; caller holds the lock."""
    _lease_gens[key] = _lease_gens.get(key, 0) + 1
    return _lease_gens[key]


def set_tcp_keepalive(sock: socket.socket) -> None:
    """Enable TCP keepalive and low-latency probing on a transport socket.

    Configures SO_KEEPALIVE along with aggressive probe intervals (5s idle,
    2s interval, 3 probes) where supported by the operating system, ensuring
    that dead or ungracefully severed peers (without TCP FIN/RST) are detected
    and torn down promptly rather than lingering as ghost sockets.

    Preconditions:
        ``sock`` is an initialized or connected ``socket.socket`` instance.
    Postconditions:
        TCP keepalive socket options are applied. Any unsupported platform options
        or socket errors are suppressed without raising exceptions.
    Failure Modes:
        Non-fatal OSError is caught and suppressed via ``contextlib.suppress``.
    """
    with contextlib.suppress(OSError):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    for _opt, _val in (
        (getattr(socket, "TCP_KEEPIDLE", None), 5),
        (getattr(socket, "TCP_KEEPINTVL", None), 2),
        (getattr(socket, "TCP_KEEPCNT", None), 3),
    ):
        if _opt is not None:
            with contextlib.suppress(OSError):
                sock.setsockopt(socket.IPPROTO_TCP, _opt, _val)


def lease_generation(key: str) -> int:
    """Return the generation that a new owner of ``key`` would receive."""
    with _leases_lock:
        return _lease_gen_locked(key)


def entry_is_current(entry: Any) -> bool:
    """Return True when a queued entry belongs to the current lease holder."""
    if not isinstance(entry, QueuedTunnel) or not entry.key:
        return True
    with _leases_lock:
        return entry.gen == _lease_gen_locked(entry.key)


def _busy_locked(
    key: str, q: queue.Queue[Any] | None, lease: dict[str, Any] | None
) -> bool:
    """Return True while ``key`` still has a live tunnel, pairing, or grace.

    The caller holds ``_leases_lock``: the liveness test and the lease
    decision must observe the same registry state.
    """
    if lease is None:
        return False
    if _relay_active.get(key, 0) > 0:
        return True
    if q is not None and live_queued(q) > 0:
        return True
    return time.time() - float(lease["seen"]) < RELAY_LEASE_GRACE


def _free_ports_locked(bound: list[int]) -> list[int]:
    """Return bound ports with no live owner; caller holds the lock."""
    free: list[int] = []
    for port in bound:
        key = str(port)
        if not _busy_locked(key, _relays.get(key), _port_leases.get(port)):
            free.append(port)
    return free


def free_relay_ports() -> list[int]:
    """Return sorted list of bound relay ports not currently held by any live carrier."""
    with _leases_lock:
        return _free_ports_locked(sorted(_bound_relay_ports))


def _free_ports_summary_locked(bound: list[int]) -> str:
    """Format free relay ports; caller holds the lease lock."""
    free = _free_ports_locked(bound)
    if not free:
        return "none"
    return ", ".join(str(p) for p in free)


def _free_ports_summary() -> str:
    """Format free relay ports for conflict error messages."""
    with _leases_lock:
        return _free_ports_summary_locked(sorted(_bound_relay_ports))


def admit_host(
    host: str, carrier: str, q: queue.Queue[Any], sock: socket.socket
) -> tuple[str | None, QueuedTunnel | None]:
    """Admit one v2 shell tunnel and enqueue it in the same critical section.

    The lease check, the grant, and the queue insertion observe one registry
    state, so two carriers cannot both be told they own ``host``.  The entry
    is returned un-ready: the caller sends its 101 and then marks it ready, and
    the pairer waits for that before using the socket. Enables TCP keepalive
    on the standby socket so half-open failures are reaped.

    Preconditions:
        ``host`` is a validated host label string.
        ``carrier`` is the non-empty carrier identifier string.
        ``q`` is the host's tunnel queue.
        ``sock`` is the connected carrier transport socket.
    Postconditions:
        Returns ``(None, entry)`` on successful admission with ``q`` receiving
        the entry and lease generation safely committed without drift.
        Returns ``(reason, None)`` when refused or queue is full.
    Failure Modes:
        Returns conflict reason if host is already leased to another carrier with
        queued tunnels or active pairings. Returns queue full reason without
        advancing the host generation counter if queue.Full is encountered.
    """
    with _leases_lock:
        queued = live_queued(q)
        active = _host_active.get(host, 0)
        lease = _host_leases.get(host)
        if lease is not None and lease["id"] != carrier and (queued > 0 or active > 0):
            held = int(time.time() - float(lease["since"]))
            active_hosts = [
                h
                for h, hq in _shell_v2.items()
                if live_queued(hq) > 0 or _host_active.get(h, 0) > 0
            ]
            active_str = ", ".join(sorted(active_hosts)) or host
            return (
                f"host {host!r} is already in use by another tunnel "
                f"(held for {held}s, {queued} queued, {active} active); "
                f"active hosts: {active_str}"
            ), None
        new_owner = lease is None or lease["id"] != carrier
        target_gen = _lease_gen_locked(host) + 1 if new_owner else _lease_gen_locked(host)
        set_tcp_keepalive(sock)
        entry = QueuedTunnel(
            sock=sock,
            gen=target_gen,
            carrier=carrier,
            # The key fences this entry to the host lease, so a socket queued
            # by an earlier owner is discarded instead of being paired with
            # the new owner's operator.
            key=host,
        )
        try:
            q.put_nowait(entry)
        except queue.Full:
            return "tunnel queue full", None
        now = time.time()
        if new_owner:
            _lease_gens[host] = target_gen
            _host_leases[host] = {
                "id": carrier,
                "since": now,
                "seen": now,
                "gen": entry.gen,
            }
        elif lease is not None:
            lease["seen"] = now
        return None, entry


def touch_host(host: str, delta: int = 0) -> None:
    """Adjust the active operator pairing count for ``host``."""
    with _leases_lock:
        _host_active[host] = max(0, _host_active.get(host, 0) + delta)
        lease = _host_leases.get(host)
        if lease is not None:
            lease["seen"] = time.time()


def _resolve_relay_locked(
    svc: str,
    carrier: str,
    requested_port: int,
    bound: list[int],
    unavail: dict[int, str],
    static_map: dict[str, int],
) -> tuple[int, str, str | None]:
    """Resolve a relay request to ``(port, lease_name, reason)`` under the lock."""
    if not bound and not unavail:
        # Unit-test or unbound mode: no public relay listeners were bound.
        return 0, svc, None

    port = 0
    lease_name = svc
    if svc == "auto":
        for candidate in bound:
            port_lease = _port_leases.get(candidate)
            if port_lease is not None and port_lease["id"] == carrier:
                port = candidate
                break
        if port == 0:
            free = _free_ports_locked(bound)
            if not free:
                return (
                    0,
                    svc,
                    f"no free relay ports available; open ports: "
                    f"{', '.join(str(p) for p in bound)}",
                )
            port = free[0]
        lease_name = str(port)
    elif svc.isdigit():
        port = int(svc)
    elif requested_port > 0:
        port = requested_port
    elif svc in static_map:
        port = static_map[svc]
    else:
        existing = _leases.get(svc)
        if existing is not None and int(existing.get("port", 0)) in bound:
            port = int(existing["port"])
        if port == 0:
            free = _free_ports_locked(bound)
            if not free:
                return (
                    0,
                    svc,
                    f"no free relay ports available for {svc!r}; open ports: "
                    f"{', '.join(str(p) for p in bound)}",
                )
            port = free[0]

    summary = _free_ports_summary_locked(bound)
    if port in unavail:
        return (
            port,
            lease_name,
            f"relay port {port} is unavailable on receiver ({unavail[port]}); "
            f"free ports: {summary}",
        )
    if bound and port not in bound:
        return (
            port,
            lease_name,
            f"relay port {port} is not in the open relay port pool; "
            f"free ports: {summary}",
        )
    return port, lease_name, None


def _claim_relay_locked(
    svc: str, carrier: str, q: queue.Queue[Any], port: int, bound: list[int]
) -> str | None:
    """Grant ``svc``/``port`` to ``carrier`` under the lease lock, or refuse it."""
    key = str(port) if port > 0 else svc
    name_lease = _leases.get(svc)
    port_lease = _port_leases.get(port) if port > 0 else None

    if name_lease is not None and name_lease["id"] != carrier:
        prev_port = int(name_lease.get("port", 0))
        prev_key = str(prev_port) if prev_port > 0 else svc
        if _busy_locked(prev_key, _relays.get(prev_key), name_lease):
            held = int(time.time() - float(name_lease["since"]))
            port_note = f" on port {prev_port}" if prev_port > 0 else ""
            return (
                f"relay service {svc!r} is already held by another carrier"
                f"{port_note} (for {held}s); free ports: "
                f"{_free_ports_summary_locked(bound)}"
            )

    if (
        port > 0
        and port_lease is not None
        and port_lease["id"] != carrier
        and _busy_locked(key, q, port_lease)
    ):
        held = int(time.time() - float(port_lease["since"]))
        owner_name = str(port_lease.get("name", port))
        return (
            f"relay port {port} is already in use by another carrier "
            f"(service {owner_name!r}, for {held}s); free ports: "
            f"{_free_ports_summary_locked(bound)}"
        )

    if name_lease is None and len(_leases) >= MAX_RELAY_QUEUES:
        return "relay registry is full; release a service before claiming a new one"
    now = time.time()
    if name_lease is None or name_lease["id"] != carrier:
        _leases[svc] = {
            "id": carrier,
            "port": port,
            "since": now,
            "seen": now,
            "gen": _next_gen_locked(svc),
        }
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
                "gen": _next_gen_locked(str(port)),
            }
        else:
            port_lease["seen"] = now
            port_lease["name"] = svc
    return None


def resolve_and_claim_relay(
    svc: str,
    carrier: str,
    requested_port: int,
) -> tuple[queue.Queue[Any] | None, int, str | None]:
    """Resolve relay target ``svc`` to a queue and port, checking carrier leases.

    Resolution, admission, and queue allocation run in one critical section so
    two carriers cannot both be told the same free port.

    Returns ``(queue, assigned_port, error_reason)``.
    """
    static_map = relay_services()
    with _leases_lock:
        bound = sorted(_bound_relay_ports)
        unavail = dict(_unavailable_ports)
        port, lease_name, reason = _resolve_relay_locked(
            svc, carrier, requested_port, bound, unavail, static_map
        )
        key = str(port) if port > 0 else svc
        q = _relay_queue_locked(key)
        if q is None:
            return None, port, (
                f"relay registry is full ({MAX_RELAY_QUEUES} labels); "
                "release a service before claiming a new one"
            )
        if reason is not None:
            return q, port, reason
        reason = _claim_relay_locked(lease_name, carrier, q, port, bound)
        return q, port, reason


def admit_relay(
    svc: str,
    carrier: str,
    requested_port: int,
    sock: socket.socket,
    *,
    response: bytes = b"",
    pairing: str = "data",
) -> tuple[int, str | None, QueuedTunnel | None]:
    """Admit one relay carrier and enqueue its socket atomically.

    A failed insertion rolls the lease back, so a refused carrier cannot leave
    the port looking owned.  For ``pairing="event"`` the 101 is deferred and
    carried in ``response``: the pairer sends it (then the pairing marker) when
    a peer actually arrives, which is what lets a server-first backend greet
    the peer before the carrier has seen any data. Enables TCP keepalive on
    the standby relay socket to prevent ghost sockets from persisting.

    Preconditions:
        ``svc`` is the relay service name or port string.
        ``carrier`` is the non-empty carrier identifier string.
        ``requested_port`` is an integer port or 0 for auto.
        ``sock`` is the connected carrier transport socket.
    Postconditions:
        Returns ``(assigned_port, None, entry)`` on success with ``sock`` enqueued
        and TCP keepalive options set. Returns ``(port, reason, None)`` on refusal.
    Failure Modes:
        Returns error reason if relay registry is full, port/service is in use by
        another carrier, or the relay queue is full.
    """
    static_map = relay_services()
    with _leases_lock:
        bound = sorted(_bound_relay_ports)
        unavail = dict(_unavailable_ports)
        port, lease_name, reason = _resolve_relay_locked(
            svc, carrier, requested_port, bound, unavail, static_map
        )
        key = str(port) if port > 0 else svc
        q = _relay_queue_locked(key)
        if q is None:
            return port, (
                f"relay registry is full ({MAX_RELAY_QUEUES} labels); "
                "release a service before claiming a new one"
            ), None
        if reason is None:
            reason = _claim_relay_locked(lease_name, carrier, q, port, bound)
        if reason is not None:
            return port, reason, None
        set_tcp_keepalive(sock)
        entry = QueuedTunnel(
            sock=sock,
            gen=_lease_gen_locked(key),
            carrier=carrier,
            key=key,
            response=response,
            pairing=pairing,
        )
        try:
            q.put_nowait(entry)
        except queue.Full:
            # No tunnel exists for this carrier: do not leave a lease behind.
            if port > 0 and _port_leases.get(port, {}).get("id") == carrier:
                _port_leases.pop(port, None)
            if _leases.get(lease_name, {}).get("id") == carrier:
                _leases.pop(lease_name, None)
            return port, f"relay queue for {key} is full; retry shortly", None
        # The admitting thread sets ready only after its handshake write is
        # complete; the pairer waits on it before touching the socket.
        return port, None, entry


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

    ports_free: list[int] = []
    ports_in_use: dict[str, dict[str, Any]] = {}
    names_in_use: dict[str, int] = {}
    with _leases_lock:
        bound = sorted(_bound_relay_ports)
        unavail = {str(k): v for k, v in sorted(_unavailable_ports.items())}
        for port in bound:
            key = str(port)
            port_lease = _port_leases.get(port)
            if _busy_locked(key, _relays.get(key), port_lease):
                queue_ref = _relays.get(key)
                q_cnt = live_queued(queue_ref) if queue_ref is not None else 0
                a_cnt = _relay_active.get(key, 0)
                svc_name = str(port_lease.get("name", port)) if port_lease else key
                ports_in_use[key] = {
                    "name": svc_name,
                    "queued": q_cnt,
                    "active": a_cnt,
                    "since": int(port_lease["since"]) if port_lease else 0,
                }
                names_in_use[svc_name] = port
            else:
                ports_free.append(port)

    return {
        "ok": True,
        "relay_auth": "token" if RELAY_TOKEN else "none",
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
            if not relay_authorized(hdrs):
                body = b"status requires the relay token"
                with contextlib.suppress(OSError):
                    conn.sendall(
                        b"HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\n"
                        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                        b"Connection: close\r\n\r\n" + body
                    )
                with contextlib.suppress(OSError):
                    conn.close()
                log("refused status probe without relay token")
                return
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
            reason, admitted_v2 = admit_host(host, carrier, q, conn)
            if reason is not None:
                status = "503 Service Unavailable" if "queue full" in reason else "409 Conflict"
                refuse(conn, status, reason, detail=reason)
                return
            try:
                conn.sendall(
                    b"HTTP/1.1 101 Switching Protocols\r\n"
                    b"Upgrade: " + UPGRADE_TOKEN.encode() + b"\r\n"
                    b"Connection: Upgrade\r\n"
                    b"X-Moesh-Tunnel-Version: 2\r\n"
                    b"X-Moesh-Tunnel-Name: " + host.encode() + b"\r\n\r\n"
                )
            finally:
                # Only now may a pairer use the socket: the 101 is on the wire.
                if admitted_v2 is not None:
                    admitted_v2.ready.set()
            conn.settimeout(None)
            set_tcp_keepalive(conn)
            log(f"host tunnel v2 attached from {addr} host {host}")
            return
        if token != "websocket":  # noqa: S105 - a protocol identifier, not a secret
            refuse(conn, "400 Bad Request", f"unsupported upgrade token {token!r}")
            return
        # The v1 shell path and the relay path are the legacy product's
        # paths; only the v2 path is moesh's.
        assigned_port = 0
        svc = ""
        relay_carrier = ""
        relay_pairing = "data"
        req_port = 0
        queue_ref: queue.Queue[Any] | None = None
        if path == V1_TUNNEL_PATH:
            if not ALLOW_V1:
                refuse(
                    conn, "426 Upgrade Required", "v1 shell tunnel disabled by cutover"
                )
                return
            queue_ref = _shell
        elif path.startswith(RELAY_PATH_PREFIX):
            svc = path[len(RELAY_PATH_PREFIX) :]
            if not valid_host(svc):
                refuse(conn, "400 Bad Request", f"invalid relay service {svc!r}")
                return
            if not relay_authorized(hdrs):
                refuse(
                    conn,
                    "401 Unauthorized",
                    "relay carrier authentication required",
                    detail="present X-Moesh-Relay-Auth with the bridge relay token",
                )
                return
            relay_carrier = extract_carrier(hdrs, addr)
            for line in hdrs.split(b"\r\n")[1:]:
                low = line.lower()
                if low.startswith(RELAY_PORT_HEADER):
                    port_txt = line.split(b":", 1)[1].strip().decode("latin-1", "replace")
                    if port_txt.isdigit():
                        req_port = int(port_txt)
                elif low.startswith(RELAY_PAIRING_HEADER):
                    mode = line.split(b":", 1)[1].strip().decode("latin-1", "replace")
                    if mode == PAIRING_EVENT:
                        relay_pairing = PAIRING_EVENT
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

        admitted: QueuedTunnel | None = None
        if svc:
            assigned_port, reason, admitted = admit_relay(
                svc, relay_carrier, req_port, conn, pairing=relay_pairing
            )
            if reason is not None:
                status = "503 Service Unavailable" if "full" in reason else "409 Conflict"
                refuse(conn, status, reason, detail=reason)
                return

        extra_hdrs = b""
        if svc:
            extra_hdrs += b"X-Moesh-Relay-Name: " + svc.encode("latin-1", "replace") + b"\r\n"
        announced_port = assigned_port or req_port
        if announced_port > 0:
            extra_hdrs += f"X-Moesh-Relay-Port: {announced_port}\r\n".encode("latin-1")
        if relay_pairing == PAIRING_EVENT:
            extra_hdrs += b"X-Moesh-Relay-Pairing: event\r\n"
        response_bytes = (
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: " + accept + b"\r\n"
            + extra_hdrs
            + b"\r\n"
        )
        port_log = f" port {assigned_port}" if assigned_port > 0 else ""
        if svc and relay_pairing == PAIRING_EVENT:
            # The 101 travels with the queue entry: it is written when a peer
            # is actually paired, so the carrier can connect its backend
            # before any peer byte exists (server-first protocols).
            if admitted is not None:
                admitted.response = response_bytes
                admitted.ready.set()
            conn.settimeout(None)
            log(f"relay carrier queued from {addr} path {path}{port_log} (deferred 101)")
            return
        conn.sendall(response_bytes)
        if admitted is not None:
            admitted.ready.set()
        conn.settimeout(None)
        log(f"host tunnel attached from {addr} path {path}{port_log}")
        if svc:
            return
        if queue_ref is not None:
            queue_ref.put(conn, timeout=120)
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


def pump(
    a: socket.socket,
    b: socket.socket,
    linger: float | None = None,
    on_half_close: Callable[[], None] | None = None,
) -> None:
    """Relay bytes both ways, honouring TCP half-close semantics.

    A direction that reaches EOF forwards it as ``SHUT_WR`` and leaves the
    reverse direction alone: that is how a client says "request complete" and
    still reads the response (an SMTP/HTTP style exchange).  Closing both legs
    immediately, or shutting down the *read* side of the surviving direction,
    destroys the response, which is what the previous implementation did.

    The other direction is allowed ``linger`` seconds to finish.  A peer that
    never closes would otherwise leave this pair blocked in ``recv`` forever
    (CLOSE-WAIT accumulation), so after the linger both sockets are shut down
    and closed.

    ``on_half_close`` runs once, when the first direction ends.  Callers use it
    to retire the pairing from admission accounting immediately: the drained
    direction may legitimately outlive the attached peer by the whole linger,
    and holding the lease for that long would refuse a replacement carrier long
    after the peer that justified the lease is gone.

    Args:
        a: First leg (the queued host/tunnel side).
        b: Second leg (the peer/operator side).
        linger: Seconds to wait for the second direction; defaults to
            ``MOESH_BRIDGE_HALFCLOSE_LINGER``.
        on_half_close: Called once when either direction reaches EOF.
    """
    if linger is None:
        linger = HALFCLOSE_LINGER
    done = threading.Event()
    half_closed = threading.Lock()

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
            log(f"pump {name} ended")
            done.set()
            if on_half_close is not None and half_closed.acquire(blocking=False):
                try:
                    on_half_close()
                except Exception as exc:  # must not kill the pump
                    log(f"half-close bookkeeping failed: {exc!r}")

    workers = [
        threading.Thread(target=copy, args=(a, b, "host->peer"), daemon=True),
        threading.Thread(target=copy, args=(b, a, "peer->host"), daemon=True),
    ]
    for worker in workers:
        worker.start()
    done.wait()
    deadline = time.time() + linger
    for worker in workers:
        worker.join(max(0.0, deadline - time.time()))
    if any(worker.is_alive() for worker in workers):
        log(f"half-closed pair exceeded {linger}s linger; forcing close")
    for sock in (a, b):
        with contextlib.suppress(OSError):
            sock.shutdown(socket.SHUT_RDWR)
    for worker in workers:
        worker.join(1.0)
    for sock in (a, b):
        with contextlib.suppress(OSError):
            sock.close()
    log("pair closed")


def pair(
    conn: socket.socket,
    q: queue.Queue[Any],
    label: str,
    wait: int,
    on_detach: Callable[[], None] | None = None,
    on_pair: Callable[[], None] | None = None,
) -> None:
    """Pair one incoming connection with the oldest live tunnel in ``q``.

    A queued entry is only usable when it belongs to the current lease
    generation and its admitting thread has finished writing the handshake
    response.  Stale entries are discarded instead of being spliced into the
    new owner's traffic.

    ``on_detach`` runs once when one direction ends, so the caller can retire
    its active-pairing count without waiting out the drain.
    ``on_pair`` runs once when an active, live tunnel is paired with ``conn``,
    allowing callers to defer incrementing active pairing counts until an actual
    tunnel is acquired.

    Preconditions:
        ``conn`` is a connected client or peer socket.
        ``q`` is a tunnel queue containing ``QueuedTunnel`` instances or raw sockets.
        ``wait`` is timeout seconds to wait on ``q.get``.
    Postconditions:
        When pairing succeeds, configures socket options, notifies ``on_pair``,
        and pumps traffic until closed or detached.
    Failure Modes:
        Raises ``queue.Empty`` if wait expires without a live tunnel arriving.
        Closes sockets safely on errors.
    """
    saw_dead = False
    try:
        log(f"{label} attached from {conn.getpeername()}")
        item: Any = None
        nb: socket.socket | None = None
        paired = False
        while not paired:
            try:
                item = q.get(timeout=wait)
            except queue.Empty:
                # No tunnel arrived in time.  If we discarded a dead one along
                # the way, tell the operator so it can retry immediately instead
                # of waiting out its backoff (the dead-tunnel race).
                if saw_dead:
                    with contextlib.suppress(OSError):
                        conn.sendall(PAIR_DEAD_MARKER)
                raise
            nb = _sock_of(item)
            if isinstance(item, QueuedTunnel):
                if not entry_is_current(item):
                    log(f"discarding stale {label} tunnel from a superseded lease")
                    with contextlib.suppress(OSError):
                        nb.close()
                    continue
                if not item.ready.wait(ADMISSION_READY_TIMEOUT):
                    log(f"discarding {label} tunnel whose handshake never completed")
                    with contextlib.suppress(OSError):
                        nb.close()
                    continue
            if not alive(nb):
                # Dead tunnel (or TOCTOU close): discard and retry.
                saw_dead = True
                log(f"discarding stale {label} tunnel")
                with contextlib.suppress(OSError):
                    nb.close()
                # If the agent died, no live tunnel will arrive from it; tell
                # the operator to retry now instead of waiting out the queue
                # timeout (the dead-tunnel race).
                if live_queued(q) == 0:
                    log(f"sending PAIR_DEAD_MARKER to {label} operator")
                    with contextlib.suppress(OSError):
                        conn.sendall(PAIR_DEAD_MARKER)
                    with contextlib.suppress(OSError):
                        conn.close()
                    return
                continue
            # Final re-check right before pairing: closes the window between
            # the peek above and the pump below as much as TCP allows.
            if not alive(nb):
                saw_dead = True
                log(f"discarding stale {label} tunnel")
                with contextlib.suppress(OSError):
                    nb.close()
                if live_queued(q) == 0:
                    log(f"sending PAIR_DEAD_MARKER to {label} operator")
                    with contextlib.suppress(OSError):
                        conn.sendall(PAIR_DEAD_MARKER)
                    with contextlib.suppress(OSError):
                        conn.close()
                    return
                continue
            paired = True
        assert nb is not None and item is not None
        nb = _sock_of(item)
        log(f"pairing {label} with a host")
        if on_pair is not None:
            on_pair()
        # Both legs are unbounded once paired: a session may sit idle for
        # hours, and a socket timeout left armed on either side would tear
        # the pair down without anyone noticing.
        conn.settimeout(None)
        nb.settimeout(None)
        # Half-open peers (a client process that died without a clean FIN)
        # would otherwise leave the pump blocked in recv() for minutes.  TCP
        # keepalive makes the kernel probe and tear down such a leg promptly
        # (the cause of the 3s-reconnect race in CI).  The bridge stays blind:
        # socket options are transport-level, not decrypting.
        for _sock in (conn, nb):
            set_tcp_keepalive(_sock)
        if isinstance(item, QueuedTunnel) and item.response:
            # Deferred handshake: the carrier has been waiting for this 101 so
            # it can open its backend connection before any peer byte exists.
            try:
                nb.sendall(item.response)
                if item.pairing == PAIRING_EVENT:
                    nb.sendall(PAIR_MARKER)
            except OSError:
                with contextlib.suppress(OSError):
                    nb.close()
                with contextlib.suppress(OSError):
                    conn.close()
                return
        pump(nb, conn, on_half_close=on_detach)
    except queue.Empty:
        log(f"{label} connected but no {label} tunnel within {wait}s")
        # If a dead tunnel was discarded along the way, signal the operator so
        # it retries immediately instead of waiting out its backoff.
        if saw_dead:
            log(f"sending PAIR_DEAD_MARKER to {label} operator")
            with contextlib.suppress(OSError):
                conn.sendall(PAIR_DEAD_MARKER)
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
    """Pair one operator connection with the host it asked for.

    Preconditions:
        ``conn`` is an active socket accepted from an incoming operator connection.
        ``addr`` is the (host, port) tuple of the peer.
    Postconditions:
        Reads host label, resolves queue, and invokes ``pair()``. Increments active
        host pairing count only upon successful pairing via ``on_pair`` callback,
        and decrements it upon detachment.
    Failure Modes:
        Invalid or missing host labels trigger socket closure and refusal.
        Timeouts or empty queues during wait exit without marking host active.
    """
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
    paired = threading.Event()
    detached = threading.Lock()

    def attach() -> None:
        """Record active pairing once a tunnel has been acquired."""
        if not paired.is_set():
            paired.set()
            touch_host(host, 1)

    def detach() -> None:
        """Stop counting this pairing as attached; safe to call twice."""
        if paired.is_set() and detached.acquire(blocking=False):
            touch_host(host, -1)

    try:
        pair(conn, q, f"operator-v2[{host}]", 120, on_detach=detach, on_pair=attach)
    finally:
        detach()


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


def main(argv: list[str] | None = None) -> int:
    """Run the moesh-bridge server and block on active listeners."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="moesh-bridge",
        description=(
            "Blind pairing broker: terminates the HTTP/1.1 Upgrade and relays "
            "opaque bytes.  Configuration is environment-only; --help documents "
            "the entry point for packaging smoke tests."
        ),
    )
    parser.parse_args(argv)
    if RELAY_TOKEN:
        log("relay carrier authentication enabled (shared token)")
    else:
        log(
            "relay carrier authentication is DISABLED: any client that can reach "
            "the tunnel listener may claim a relay port; set "
            "MOESH_BRIDGE_RELAY_TOKEN to require a shared secret"
        )
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
        if q is None:
            log(f"relay port {port} skipped: relay registry is full")
            continue

        def make_relay_handler(
            queue_ref: queue.Queue[socket.socket], port_num: int
        ) -> Callable[[socket.socket, tuple[str, int]], None]:
            label = str(port_num)

            def handler(conn: socket.socket, addr: tuple[str, int]) -> None:
                detached = threading.Lock()

                def detach() -> None:
                    if detached.acquire(blocking=False):
                        touch_relay(label, -1)

                touch_relay(label, 1)
                try:
                    pair(conn, queue_ref, f"relay:{port_num}", 20, on_detach=detach)
                finally:
                    detach()

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
        return 1
    threading.Event().wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
