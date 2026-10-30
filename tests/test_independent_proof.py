#!/usr/bin/env python3
"""Independent verification suite for AP fixes.

Authored by Independent Verification Specialist (Anti-Idiocy & Python Testing Patterns).
Covers:
- RC-1: Deferred touch_host active accounting in operator_v2_conn
- RC-2 & RC-3: Standby socket SO_KEEPALIVE enforcement in admit_host and admit_relay
- RC-4: Generational counter consistency on queue.Full in admit_host
- RC-5 & RC-9: Incident-scoped claim_deadline resets in tunnel_worker and relay worker
- RC-6 & RC-10: Stable carrier ID derivation across restarts
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import os
import queue
import socket
import threading
import time
from pathlib import Path
from typing import Any

import pytest

import moesh_relay
import moesh_tunnel


def _load_bridge() -> Any:
    bridge_path = Path(__file__).resolve().parent.parent / "moesh-bridge.py"
    spec = importlib.util.spec_from_file_location("moesh_bridge", bridge_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _tcp_pair() -> tuple[socket.socket, socket.socket]:
    """Create a connected pair of real TCP sockets over IPv4 loopback."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", port))
    server_conn, _ = srv.accept()
    srv.close()
    return client, server_conn


# ==============================================================================
# RC-1: Deferred touch_host Active Accounting
# ==============================================================================

def test_rc1_concurrent_waiting_operator_does_not_block_agent_admission() -> None:
    """Verify that an operator blocked waiting in queue does not trigger 409 Conflict for an incoming agent."""
    bridge = _load_bridge()
    host = "test-host-rc1-live"
    q = bridge.host_queue(host)
    assert q is not None

    s_op, s_op_peer = socket.socketpair()
    s_agent, s_agent_peer = socket.socketpair()

    operator_started = threading.Event()
    operator_finished = threading.Event()

    def run_operator() -> None:
        orig_label = bridge.read_host_label
        bridge.read_host_label = lambda _conn: host
        try:
            operator_started.set()
            bridge.operator_v2_conn(s_op, ("127.0.0.1", 54321))
        finally:
            bridge.read_host_label = orig_label
            operator_finished.set()

    t_op = threading.Thread(target=run_operator, daemon=True)
    t_op.start()

    assert operator_started.wait(timeout=2.0)
    # Give the thread a moment to enter pair() and block on q.get()
    time.sleep(0.05)

    try:
        # Operator is waiting. Active count MUST be 0!
        active_during_wait = bridge._host_active.get(host, 0)
        assert active_during_wait == 0, f"Expected active 0 during wait, got {active_during_wait}"

        # Incoming agent connects with a new carrier ID
        reason, entry = bridge.admit_host(host, "carrier-agent-1", q, s_agent)
        # Pre-patch would have failed here with 409 Conflict because active was 1
        assert reason is None, f"Agent admission refused: {reason}"
        assert entry is not None

        # Mark tunnel ready so pair() can complete pairing
        entry.ready.set()

        # Give pump time to pair
        time.sleep(0.05)
        active_during_pairing = bridge._host_active.get(host, 0)
        assert active_during_pairing == 1, f"Expected active 1 during pairing, got {active_during_pairing}"

        # Now disconnect operator leg
        s_op.close()
        s_op_peer.close()
        t_op.join(timeout=2.0)

        assert bridge._host_active.get(host, 0) == 0, "Expected active 0 after disconnect"
    finally:
        s_agent.close()
        s_agent_peer.close()


def test_rc1_falsification_pre_patch_simulation_causes_409() -> None:
    """Negative control: If touch_host(host, 1) was called before admit_host, admit_host returns 409 conflict reason."""
    bridge = _load_bridge()
    host = "test-host-rc1-falsify"
    q = bridge.host_queue(host)
    s_agent, s_agent_peer = socket.socketpair()

    try:
        # First lease host to carrier A
        bridge._host_leases[host] = {"id": "carrier-A", "since": time.time(), "gen": 1}
        # Pre-patch simulated bug: operator sets active = 1 before pairing
        bridge.touch_host(host, 1)
        assert bridge._host_active.get(host, 0) == 1

        # Now carrier B tries to admit
        reason, entry = bridge.admit_host(host, "carrier-B", q, s_agent)
        assert entry is None
        assert reason is not None
        assert "already in use by another tunnel" in reason
        assert "1 active" in reason
    finally:
        bridge.touch_host(host, -1)
        s_agent.close()
        s_agent_peer.close()


def test_rc1_operator_timeout_never_decrements_below_zero() -> None:
    """Edge verification: If pair() raises Empty timeout, active stays 0 and never decrements to -1."""
    bridge = _load_bridge()
    host = "test-host-rc1-empty"
    s1, s2 = socket.socketpair()

    def timeout_pair(*_args: Any, **_kwargs: Any) -> None:
        raise queue.Empty()

    orig_pair = bridge.pair
    orig_label = bridge.read_host_label
    bridge.pair = timeout_pair
    bridge.read_host_label = lambda _conn: host

    try:
        with pytest.raises(queue.Empty):
            bridge.operator_v2_conn(s1, ("127.0.0.1", 54321))
        assert bridge._host_active.get(host, 0) == 0
    finally:
        bridge.pair = orig_pair
        bridge.read_host_label = orig_label
        s1.close()
        s2.close()


# ==============================================================================
# RC-2 & RC-3: Standby Socket TCP Keepalive
# ==============================================================================

def test_rc2_rc3_keepalive_options_and_fault_tolerance() -> None:
    """Verify SO_KEEPALIVE and TCP probe options are set by set_tcp_keepalive on real TCP sockets."""
    bridge = _load_bridge()
    s1, s2 = _tcp_pair()
    try:
        # Check defaults on fresh TCP socket
        assert s1.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) == 0

        # Run helper directly
        bridge.set_tcp_keepalive(s1)
        assert s1.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) == 1

        # Check Linux specific TCP options
        if hasattr(socket, "TCP_KEEPIDLE"):
            assert s1.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE) == 5
        if hasattr(socket, "TCP_KEEPINTVL"):
            assert s1.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL) == 2
        if hasattr(socket, "TCP_KEEPCNT"):
            assert s1.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT) == 3

        # Fault tolerance: call on closed socket, must not raise
        s1.close()
        bridge.set_tcp_keepalive(s1)  # should safely catch and suppress OSError
    finally:
        s2.close()

    # Fault tolerance on Unix domain socket (AF_UNIX) where TCP options raise Errno 95
    u1, u2 = socket.socketpair()
    try:
        bridge.set_tcp_keepalive(u1)  # must safely succeed without unhandled error
    finally:
        u1.close()
        u2.close()


def test_rc2_admit_host_enables_keepalive() -> None:
    """Verify admit_host enables keepalive on the admitted carrier socket."""
    bridge = _load_bridge()
    host = "test-host-rc2-direct"
    q = bridge.host_queue(host)
    s, peer = _tcp_pair()
    try:
        assert s.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) == 0
        reason, entry = bridge.admit_host(host, "carrier-1", q, s)
        assert reason is None
        assert entry is not None
        assert s.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) == 1
    finally:
        s.close()
        peer.close()


def test_rc3_admit_relay_enables_keepalive() -> None:
    """Verify admit_relay enables keepalive on the admitted carrier socket."""
    bridge = _load_bridge()
    s, peer = _tcp_pair()
    try:
        assert s.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) == 0
        _port, reason, entry = bridge.admit_relay("relay-svc-1", "carrier-1", 0, s)
        assert reason is None
        assert entry is not None
        assert s.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) == 1
    finally:
        s.close()
        peer.close()


# ==============================================================================
# RC-4: Generational Counter Atomicity on Queue Full
# ==============================================================================

def test_rc4_generation_atomicity_and_subsequent_success() -> None:
    """Verify generation counter does not drift on queue.Full and correctly commits on success."""
    bridge = _load_bridge()
    host = "test-host-rc4-atomicity"
    s1, p1 = socket.socketpair()
    s2, p2 = socket.socketpair()
    s3, p3 = socket.socketpair()

    # Create a bounded queue of size 1 and fill it
    q: queue.Queue[Any] = queue.Queue(maxsize=1)
    q.put_nowait(s1)

    try:
        initial_gen = bridge._lease_gens.get(host, 0)
        assert initial_gen == 0

        # Attempt admission when queue is full
        reason, entry = bridge.admit_host(host, "carrier-1", q, s2)
        assert reason == "tunnel queue full"
        assert entry is None
        # Must NOT have drifted
        assert bridge._lease_gens.get(host, 0) == 0
        assert bridge._host_leases.get(host) is None

        # Free space in queue
        q.get_nowait()

        # Second attempt with space available
        reason2, entry2 = bridge.admit_host(host, "carrier-1", q, s3)
        assert reason2 is None
        assert entry2 is not None
        assert bridge._lease_gens.get(host, 0) == 1
        assert entry2.gen == 1
        assert bridge._host_leases[host]["gen"] == 1
        assert bridge._host_leases[host]["id"] == "carrier-1"
    finally:
        for s in (s1, p1, s2, p2, s3, p3):
            s.close()


# ==============================================================================
# RC-5 & RC-9: Incident-Scoped Claim Deadline
# ==============================================================================

def test_rc5_tunnel_worker_recovers_from_transient_conflict(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify tunnel_worker retries transient conflict without aborting, and resets deadline."""
    timeline = ["steady", "conflict", "steady", "conflict", "steady", "stop"]
    idx = 0

    def mock_serve_once(*_args: Any, **_kwargs: Any) -> str:
        nonlocal idx
        event = timeline[idx]
        idx += 1
        if event == "steady":
            return "closed"
        if event == "conflict":
            raise moesh_tunnel.HostConflictError("mock 409 conflict")
        if event == "stop":
            raise moesh_tunnel.Stop()
        return "closed"

    monkeypatch.setattr(moesh_tunnel, "serve_once", mock_serve_once)
    monkeypatch.setattr("moesh_tunnel.time.sleep", lambda _s: None)
    moesh_tunnel._stopping = False
    moesh_tunnel._conflict_refused = False

    pool = moesh_tunnel.ShellPool()
    try:
        moesh_tunnel.tunnel_worker("127.0.0.1", 80, "/path", "host", pool)
        assert moesh_tunnel._conflict_refused is False
        assert idx == len(timeline)
    finally:
        moesh_tunnel._stopping = False
        moesh_tunnel._conflict_refused = False
        pool.terminate_all()


def test_rc5_tunnel_worker_falsification_persistent_conflict_terminates(monkeypatch: pytest.MonkeyPatch) -> None:
    """Falsification: A persistent conflict lasting >= 2s MUST terminate the worker with _conflict_refused = True."""
    current_time = 1000.0

    def mock_time() -> float:
        nonlocal current_time
        return current_time

    def mock_sleep(s: float) -> None:
        nonlocal current_time
        current_time += s

    def mock_serve_once(*_args: Any, **_kwargs: Any) -> str:
        raise moesh_tunnel.HostConflictError("persistent 409 conflict")

    monkeypatch.setattr("moesh_tunnel.time.time", mock_time)
    monkeypatch.setattr("moesh_tunnel.time.sleep", mock_sleep)
    monkeypatch.setattr(moesh_tunnel, "serve_once", mock_serve_once)
    moesh_tunnel._stopping = False
    moesh_tunnel._conflict_refused = False

    pool = moesh_tunnel.ShellPool()
    try:
        moesh_tunnel.tunnel_worker("127.0.0.1", 80, "/path", "host", pool)
        assert moesh_tunnel._conflict_refused is True
        assert moesh_tunnel._stopping is True
    finally:
        moesh_tunnel._stopping = False
        moesh_tunnel._conflict_refused = False
        pool.terminate_all()


def test_rc9_relay_worker_recovers_from_transient_conflict(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify relay worker retries transient conflict without aborting and resets deadline."""
    timeline = ["steady", "conflict", "steady", "stop"]
    idx = 0

    def mock_connect_tunnel(*_args: Any, **_kwargs: Any) -> tuple[Any, int, bytes, bool]:
        nonlocal idx
        event = timeline[idx]
        idx += 1
        if event == "steady":
            s1, _s2 = socket.socketpair()
            return s1, 26420, b"ready", False
        if event == "conflict":
            raise moesh_relay.RelayRefused("mock 409 conflict")
        if event == "stop":
            raise KeyboardInterrupt()
        s, _ = socket.socketpair()
        return s, 26420, b"", False

    monkeypatch.setattr(moesh_relay, "connect_tunnel", mock_connect_tunnel)
    monkeypatch.setattr("moesh_relay.time.sleep", lambda _s: None)

    refused = threading.Event()
    with contextlib.suppress(KeyboardInterrupt):
        moesh_relay.worker(
            0, "127.0.0.1", 80, "/path", "127.0.0.1", 8080, 0,
            "carrier-1", refused, 2.0
        )

    assert refused.is_set() is False, "Relay worker prematurely refused on transient conflict"
    assert idx == len(timeline)


def test_rc9_relay_worker_falsification_persistent_conflict_aborts(monkeypatch: pytest.MonkeyPatch) -> None:
    """Falsification: A persistent conflict in relay worker lasting >= incident_wait MUST trigger refused.set()."""
    current_time = 1000.0

    def mock_time() -> float:
        nonlocal current_time
        return current_time

    def mock_sleep(s: float) -> None:
        nonlocal current_time
        current_time += s

    def mock_connect_tunnel(*_args: Any, **_kwargs: Any) -> tuple[Any, int, bytes, bool]:
        raise moesh_relay.RelayRefused("persistent 409 conflict")

    monkeypatch.setattr("moesh_relay.time.time", mock_time)
    monkeypatch.setattr("moesh_relay.time.sleep", mock_sleep)
    monkeypatch.setattr(moesh_relay, "connect_tunnel", mock_connect_tunnel)

    refused = threading.Event()
    moesh_relay.worker(
        0, "127.0.0.1", 80, "/path", "127.0.0.1", 8080, 0,
        "carrier-1", refused, 2.0
    )

    assert refused.is_set() is True, "Relay worker did not set refused on persistent conflict"


# ==============================================================================
# RC-6 & RC-10: Persistent Carrier ID Derivation
# ==============================================================================

def test_rc6_rc10_carrier_id_derivation_cascade() -> None:
    """Verify derive_carrier_id behaves deterministically across calls and follows fallback cascade."""
    # 1. Direct environment variable override
    os.environ["MOESH_TUNNEL_ID"] = "custom-tunnel-id"
    assert moesh_tunnel.derive_carrier_id() == "custom-tunnel-id"
    os.environ.pop("MOESH_TUNNEL_ID")

    os.environ["MOESH_RELAY_ID"] = "custom-relay-id"
    assert moesh_relay.derive_carrier_id() == "custom-relay-id"
    assert moesh_relay.derive_carrier_id("cli-arg-id") == "cli-arg-id"
    os.environ.pop("MOESH_RELAY_ID")

    # 2. Machine-ID derivation (deterministic)
    id1 = moesh_tunnel.derive_carrier_id()
    id2 = moesh_tunnel.derive_carrier_id()
    assert id1 == id2
    assert len(id1) == 16
    assert all(c in "0123456789abcdef" for c in id1)

    r_id1 = moesh_relay.derive_carrier_id()
    r_id2 = moesh_relay.derive_carrier_id()
    assert r_id1 == r_id2
    assert len(r_id1) == 16
    assert r_id1 == id1  # Same machine id produces same carrier id!

    # 3. Fallback when machine-id is unreadable
    with pytest.MonkeyPatch.context() as m:
        m.setattr(os.path, "exists", lambda _p: False)
        orig_open = open
        def mock_open(path: Any, *args: Any, **kwargs: Any) -> Any:
            if "machine-id" in str(path):
                raise OSError("Permission denied")
            return orig_open(path, *args, **kwargs)
        m.setattr("builtins.open", mock_open)

        # Tunnel should check agent key
        os.environ["MOESH_TUNNEL_AGENT_KEY"] = "static-test-key-material"
        key_id = moesh_tunnel.derive_carrier_id()
        expected_key_id = hashlib.sha256(b"static-test-key-material").hexdigest()[:16]
        assert key_id == expected_key_id
        os.environ.pop("MOESH_TUNNEL_AGENT_KEY")

        # When all files and keys fail, falls back to 16 hex characters
        rand_id = moesh_tunnel.derive_carrier_id()
        assert len(rand_id) == 16
        assert all(c in "0123456789abcdef" for c in rand_id)
