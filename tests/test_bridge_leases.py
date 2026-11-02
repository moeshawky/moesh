#!/usr/bin/env python3
"""Ownership regressions for the bridge: leases, relay authorization, registry bounds.

MOESH-002 (atomic admission), MOESH-003 (relay carrier authorization), and
MOESH-010 (bounded relay registry).  The concurrency cases use a barrier so the
contending claims overlap instead of hoping a stress loop finds the window.
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import socket
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from tests.harness import Bridge, next_ports

ROOT = Path(__file__).resolve().parent.parent


def _bridge_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "moesh_bridge_lease_tests", ROOT / "moesh-bridge.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def bridge_mod() -> Any:
    """A bridge module with fresh in-process registries."""
    mod = _bridge_module()
    for name in (
        "_relays",
        "_leases",
        "_port_leases",
        "_host_leases",
        "_host_active",
        "_relay_active",
        "_unavailable_ports",
        "_bound_relay_ports",
        "_shell_v2",
    ):
        getattr(mod, name).clear()
    return mod


def _sock_pair() -> tuple[socket.socket, socket.socket]:
    return socket.socketpair()


# ---------------------------------------------------------------------------
# MOESH-002 — exactly one owner is admitted
# ---------------------------------------------------------------------------


def test_concurrent_host_admission_grants_exactly_one_owner(bridge_mod: Any) -> None:
    """A free host slot admits one carrier even when claims start together."""
    for round_index in range(30):
        host = f"host-{round_index}"
        q: Any = bridge_mod.host_queue(host)
        assert q is not None
        contenders = 24
        barrier = threading.Barrier(contenders)
        granted: list[str] = []
        lock = threading.Lock()
        # Each contender's peer end stays open for the whole round: closing it
        # early makes the admitted tunnel look dead to the next contender.
        peers: list[socket.socket] = []

        def claim(
            index: int,
            host: str = host,
            q: Any = q,
            barrier: threading.Barrier = barrier,
            peers: list[socket.socket] = peers,
            granted: list[str] = granted,
            lock: threading.Lock = lock,
        ) -> None:
            carrier = f"carrier-{index}"
            a, b = _sock_pair()
            peers.append(b)
            barrier.wait(timeout=10)
            reason, _entry = bridge_mod.admit_host(host, carrier, q, a)
            if reason is None:
                with lock:
                    granted.append(carrier)

        threads = [threading.Thread(target=claim, args=(i,)) for i in range(contenders)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        for peer in peers:
            with contextlib.suppress(OSError):
                peer.close()

        assert len(granted) == 1, f"round {round_index}: granted {granted}"
        assert q.qsize() == 1


def test_concurrent_relay_admission_grants_exactly_one_owner(bridge_mod: Any) -> None:
    """A relay service/port pair admits one carrier; the rest are refused."""
    for round_index in range(30):
        bridge_mod._bound_relay_ports.clear()
        bridge_mod._bound_relay_ports.add(26420 + round_index)
        service = f"svc-{round_index}"
        contenders = 24
        barrier = threading.Barrier(contenders)
        granted: list[tuple[str, int]] = []
        lock = threading.Lock()

        def claim(
            index: int,
            service: str = service,
            barrier: threading.Barrier = barrier,
            granted: list[tuple[str, int]] = granted,
            lock: threading.Lock = lock,
        ) -> None:
            carrier = f"carrier-{index}"
            barrier.wait(timeout=10)
            q, port, reason = bridge_mod.resolve_and_claim_relay(service, carrier, 0)
            if reason is None and q is not None:
                with lock:
                    granted.append((carrier, port))

        threads = [threading.Thread(target=claim, args=(i,)) for i in range(contenders)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)

        assert len(granted) == 1, f"round {round_index}: granted {granted}"
        # The admitted owner is the one recorded in the lease.
        assert bridge_mod._leases[service]["id"] == granted[0][0]
        assert bridge_mod._port_leases[granted[0][1]]["id"] == granted[0][0]


def test_auto_port_assignment_never_hands_one_port_to_two_carriers(
    bridge_mod: Any,
) -> None:
    """Concurrent ``auto`` claims receive distinct ports or a refusal."""
    ports = [26420, 26421, 26422]
    bridge_mod._bound_relay_ports.update(ports)
    contenders = 12
    barrier = threading.Barrier(contenders)
    assigned: list[tuple[str, int]] = []
    lock = threading.Lock()

    def claim(index: int) -> None:
        carrier = f"auto-carrier-{index}"
        barrier.wait(timeout=10)
        _q, port, reason = bridge_mod.resolve_and_claim_relay("auto", carrier, 0)
        if reason is None:
            with lock:
                assigned.append((carrier, port))

    threads = [threading.Thread(target=claim, args=(i,)) for i in range(contenders)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)

    assert len(assigned) <= len(ports)
    used = [port for _carrier, port in assigned]
    assert len(used) == len(set(used)), f"port handed to two carriers: {assigned}"
    assert set(used) <= set(ports)


def test_failed_queue_insertion_rolls_back_the_lease(bridge_mod: Any) -> None:
    """A full queue refuses admission and leaves no lease behind for that name."""
    q = bridge_mod.relay_queue("stuffed")
    assert q is not None
    stuffed: list[socket.socket] = []
    for _ in range(q.maxsize):
        a, b = _sock_pair()
        stuffed.append(b)
        q.put_nowait(bridge_mod.relay_entry(a, 0, "someone"))

    a2, b2 = _sock_pair()
    try:
        _port, reason, _entry = bridge_mod.admit_relay("stuffed", "carrier-x", 0, a2)
    finally:
        with contextlib.suppress(OSError):
            b2.close()
        with contextlib.suppress(OSError):
            a2.close()

    assert reason is not None
    assert "full" in reason.lower()
    assert "stuffed" not in bridge_mod._leases

    for sock in stuffed:
        with contextlib.suppress(OSError):
            sock.close()
    bridge_mod.live_queued(q)
    _q2, _port2, reason2 = bridge_mod.resolve_and_claim_relay("stuffed", "carrier-y", 0)
    assert reason2 is None, reason2


def test_stale_carrier_socket_is_not_paired_with_a_new_owner(bridge_mod: Any) -> None:
    """A queued socket from an older lease generation is discarded on pairing."""
    bridge_mod._bound_relay_ports.add(26420)
    q, _port, reason = bridge_mod.resolve_and_claim_relay("alpha", "carrier-a", 0)
    assert reason is None
    generation = bridge_mod.lease_generation("26420")
    stale_a, stale_b = _sock_pair()
    entry = bridge_mod.relay_entry(stale_a, generation, "carrier-a", key="26420")
    q.put_nowait(entry)

    # The owner disappears and a new carrier takes the service over.
    with contextlib.suppress(OSError):
        stale_a.close()
    bridge_mod.live_queued(q)
    with bridge_mod._leases_lock:
        bridge_mod._leases.pop("alpha", None)
        bridge_mod._port_leases.pop(26420, None)
    _q2, _p2, reason2 = bridge_mod.resolve_and_claim_relay("alpha", "carrier-b", 0)
    assert reason2 is None

    assert bridge_mod.entry_is_current(entry) is False
    with contextlib.suppress(OSError):
        stale_b.close()


# ---------------------------------------------------------------------------
# MOESH-003 — relay carriers are authorized, not merely named
# ---------------------------------------------------------------------------


def _read_headers(sock: socket.socket, timeout: float = 5.0) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    while b"\r\n\r\n" not in buf:
        try:
            chunk = sock.recv(4096)
        except TimeoutError:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def test_relay_registration_requires_the_configured_token(tmp_path: Path) -> None:
    """Without a valid token a carrier must not claim a relay slot."""
    tunnel_port, operator_port, operator_v2_port = next_ports()
    bridge = Bridge(
        tunnel_port,
        operator_port,
        operator_v2_port,
        env_extra={"MOESH_BRIDGE_RELAY_TOKEN": "s3cret"},
    )
    try:
        def ask(extra: bytes, timeout: float = 5.0) -> bytes:
            request = (
                b"GET /__relay/gpu HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                b"X-Moesh-Relay-Pairing: event\r\n" + extra + b"\r\n"
            )
            with socket.create_connection(("127.0.0.1", tunnel_port), timeout=5) as sock:
                sock.sendall(request)
                return _read_headers(sock, timeout=timeout)

        assert b" 401 " in ask(b"")
        assert b" 401 " in ask(b"X-Moesh-Relay-Auth: wrong\r\n")

        # The authorized carrier registers; its 101 is deferred until pairing.
        assert ask(b"X-Moesh-Relay-Auth: s3cret\r\n", timeout=0.5) == b""
    finally:
        bridge.stop()


def test_status_probe_hides_ownership_without_the_token(tmp_path: Path) -> None:
    """Status exposes slots only to an authorized caller when a token is set."""
    tunnel_port, operator_port, operator_v2_port = next_ports()
    bridge = Bridge(
        tunnel_port,
        operator_port,
        operator_v2_port,
        env_extra={"MOESH_BRIDGE_RELAY_TOKEN": "s3cret"},
    )
    try:

        def status(headers: bytes) -> bytes:
            with socket.create_connection(("127.0.0.1", tunnel_port), timeout=5) as sock:
                sock.sendall(
                    b"GET /__moesh/status HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                    b"Connection: close\r\n" + headers + b"\r\n"
                )
                return _read_headers(sock)

        unauthorized = status(b"")
        assert b" 401 " in unauthorized
        authorized = status(b"X-Moesh-Relay-Auth: s3cret\r\n")
        assert b" 200 " in authorized
        assert b"ports_open" in authorized
    finally:
        bridge.stop()


# ---------------------------------------------------------------------------
# MOESH-010 — bounded relay registry
# ---------------------------------------------------------------------------


def test_relay_registry_refuses_new_names_at_the_cap(bridge_mod: Any) -> None:
    """High-cardinality labels must not grow queues or leases without bound."""
    cap = bridge_mod.MAX_RELAY_QUEUES
    for index in range(cap + 200):
        bridge_mod.resolve_and_claim_relay(f"svc-{index}", f"carrier-{index}", 0)
    assert len(bridge_mod._relays) <= cap
    assert len(bridge_mod._leases) <= cap


def test_status_snapshot_is_json_serializable_under_load(bridge_mod: Any) -> None:
    """The probe endpoint keeps its contract while registries are populated."""
    for index in range(20):
        bridge_mod.resolve_and_claim_relay(f"svc-{index}", f"carrier-{index}", 0)
    payload = bridge_mod.bridge_status()
    json.dumps(payload)
    assert payload["ok"] is True


def test_status_snapshot_completes_promptly(bridge_mod: Any) -> None:
    """A populated registry must not make the status probe block."""
    for index in range(20):
        bridge_mod.resolve_and_claim_relay(f"svc-{index}", f"carrier-{index}", 0)
    started = time.monotonic()
    bridge_mod.bridge_status()
    assert time.monotonic() - started < 2.0


def test_same_carrier_cannot_rebind_live_service_to_different_port(
    bridge_mod: Any,
) -> None:
    """A live named service on port A must not be silently rebound to port B."""
    bridge_mod._bound_relay_ports.update({26500, 26510})
    a1, b1 = _sock_pair()
    a2, b2 = _sock_pair()
    try:
        port1, reason1, _entry1 = bridge_mod.admit_relay(
            "mimo", "addr:127.0.0.1", 26510, a1
        )
        assert reason1 is None
        assert port1 == 26510
        assert bridge_mod._leases["mimo"]["port"] == 26510

        # A second relay sharing the fallback carrier (or same-host carrier)
        # asks for the same service name on a different port while 26510 is live.
        _port2, reason2, _entry2 = bridge_mod.admit_relay(
            "mimo", "addr:127.0.0.1", 26500, a2
        )
        assert reason2 is not None, "live service was silently rebound to a second port"
        assert bridge_mod._leases["mimo"]["port"] == 26510
    finally:
        for sock in (a1, b1, a2, b2):
            with contextlib.suppress(OSError):
                sock.close()


def test_extract_carrier_ignores_spoofed_forwarded_headers_and_isolates_remote_ips(
    bridge_mod: Any,
) -> None:
    """Direct non-proxy peers cannot spoof X-Forwarded-For or collide across IPs."""
    spoofed_hdrs = (
        b"GET /__relay/mimo HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"X-Forwarded-For: 10.0.0.1\r\n"
        b"X-Real-IP: 10.0.0.1\r\n\r\n"
    )
    # Direct external connection: must ignore X-Forwarded-For / X-Real-IP.
    direct_id = bridge_mod.extract_carrier(spoofed_hdrs, ("198.51.100.7", 51234))
    assert direct_id == "addr:198.51.100.7", direct_id

    # Trusted loopback proxy connection: must honor forwarded IP.
    proxied_id = bridge_mod.extract_carrier(spoofed_hdrs, ("127.0.0.1", 51234))
    assert proxied_id == "addr:10.0.0.1", proxied_id

    # Cloned VMs presenting the same X-Moesh-Relay-Id from two different remote
    # IPs must not resolve to the same carrier identity.
    cloned_hdr_a = (
        b"GET /__relay/mimo HTTP/1.1\r\n"
        b"X-Moesh-Relay-Id: deadbeef12345678\r\n"
        b"X-Real-IP: 198.51.100.7\r\n\r\n"
    )
    cloned_hdr_b = (
        b"GET /__relay/mimo HTTP/1.1\r\n"
        b"X-Moesh-Relay-Id: deadbeef12345678\r\n"
        b"X-Real-IP: 203.0.113.9\r\n\r\n"
    )
    id_a = bridge_mod.extract_carrier(cloned_hdr_a, ("127.0.0.1", 50001))
    id_b = bridge_mod.extract_carrier(cloned_hdr_b, ("127.0.0.1", 50002))
    assert id_a != id_b, f"cloned carrier ID collided across distinct IPs: {id_a}"


def test_admit_relay_queue_full_preserves_existing_owner_and_generation_and_purges_dead_sockets(
    bridge_mod: Any,
) -> None:
    """admit_relay must purge dead sockets on same-carrier refresh and never corrupt leases or generations on queue.Full."""
    q = bridge_mod.relay_queue("svc-full")
    assert q is not None
    live_peers: list[socket.socket] = []
    extra_a, extra_b = _sock_pair()
    try:
        # 1. Fill the queue with live sockets owned by carrier-owner.
        for _ in range(q.maxsize):
            a, b = _sock_pair()
            live_peers.extend([a, b])
            _port, reason, entry = bridge_mod.admit_relay(
                "svc-full", "carrier-owner", 0, a
            )
            assert reason is None and entry is not None
            entry.ready.set()

        gen_before = bridge_mod._lease_gens["svc-full"]
        # 2. Existing owner hits queue.Full: its active lease and generation must stay intact.
        _port, reason_full, _entry = bridge_mod.admit_relay(
            "svc-full", "carrier-owner", 0, extra_a
        )
        assert reason_full is not None and "full" in reason_full.lower()
        assert "svc-full" in bridge_mod._leases, "existing owner lease was wiped on queue.Full"
        assert bridge_mod._leases["svc-full"]["id"] == "carrier-owner"
        assert bridge_mod._lease_gens["svc-full"] == gen_before

        # 3. Close one peer so one queued socket becomes dead; same-carrier admit_relay
        # must purge the dead socket via live_queued(q) and succeed instead of failing with queue.Full.
        live_peers[1].close()
        live_peers[0].close()
        _port, reason_after_purge, entry_after = bridge_mod.admit_relay(
            "svc-full", "carrier-owner", 0, extra_a
        )
        assert reason_after_purge is None, f"dead socket was not purged: {reason_after_purge}"
        assert entry_after is not None
    finally:
        for sock in [*live_peers, extra_a, extra_b]:
            with contextlib.suppress(OSError):
                sock.close()
