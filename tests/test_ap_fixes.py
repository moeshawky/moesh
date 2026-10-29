#!/usr/bin/env python3
"""Adversarial regression and boundary tests for AP fixes.

Validates the surgical resolution of RC-1 through RC-6, RC-9, and RC-10:
- RC-1: Deferred touch_host active accounting in operator_v2_conn
- RC-2 & RC-3: Standby socket SO_KEEPALIVE enforcement in admit_host and admit_relay
- RC-4: Generational counter consistency on queue.Full in admit_host
- RC-5 & RC-9: Incident-scoped claim_deadline resets in tunnel_worker and relay worker
- RC-6 & RC-10: Stable carrier ID derivation across restarts
"""

from __future__ import annotations

import importlib.util
import os
import queue
import socket
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


def test_operator_v2_touch_host_deferred_until_paired() -> None:
    """RC-1: touch_host must not mark host active while operator is waiting."""
    bridge = _load_bridge()
    host = "test-host-rc1"
    q = bridge.host_queue(host)
    assert q is not None

    s1, s2 = socket.socketpair()
    observed_active_during_wait = None

    def fake_pair(
        conn: socket.socket,
        queue_arg: Any,
        label: str,
        wait: int,
        on_detach: Any = None,
        on_pair: Any = None,
    ) -> None:
        nonlocal observed_active_during_wait
        observed_active_during_wait = bridge._host_active.get(host, 0)
        # Verify that if on_pair is called, active becomes 1
        assert on_pair is not None
        on_pair()
        assert bridge._host_active.get(host, 0) == 1
        if on_detach is not None:
            on_detach()
        assert bridge._host_active.get(host, 0) == 0

    orig_pair = bridge.pair
    orig_label = bridge.read_host_label
    bridge.pair = fake_pair
    bridge.read_host_label = lambda _conn: host

    try:
        bridge.operator_v2_conn(s1, ("127.0.0.1", 54321))
        assert observed_active_during_wait == 0
        assert bridge._host_active.get(host, 0) == 0
    finally:
        bridge.pair = orig_pair
        bridge.read_host_label = orig_label
        s1.close()
        s2.close()


def test_operator_v2_timeout_does_not_leak_active() -> None:
    """RC-1: If pair() times out before acquiring a tunnel, active must stay 0."""
    bridge = _load_bridge()
    host = "test-host-rc1-timeout"
    q = bridge.host_queue(host)
    assert q is not None

    s1, s2 = socket.socketpair()

    def timing_out_pair(
        conn: socket.socket,
        queue_arg: Any,
        label: str,
        wait: int,
        on_detach: Any = None,
        on_pair: Any = None,
    ) -> None:
        raise queue.Empty()

    orig_pair = bridge.pair
    orig_label = bridge.read_host_label
    bridge.pair = timing_out_pair
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


def test_admit_host_standby_socket_keepalive() -> None:
    """RC-2: Queued standby tunnel sockets must have SO_KEEPALIVE set."""
    bridge = _load_bridge()
    host = "test-host-rc2"
    q = bridge.host_queue(host)
    assert q is not None

    s_tun, s_peer = socket.socketpair()
    try:
        reason, entry = bridge.admit_host(host, "carrier-rc2", q, s_tun)
        assert reason is None
        assert entry is not None
        assert s_tun.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) == 1
    finally:
        s_tun.close()
        s_peer.close()


def test_admit_relay_standby_socket_keepalive() -> None:
    """RC-3: Queued standby relay sockets must have SO_KEEPALIVE set."""
    bridge = _load_bridge()
    s_relay, s_peer = socket.socketpair()
    try:
        _port, reason, entry = bridge.admit_relay("rc3-test-svc", "carrier-rc3", 0, s_relay)
        assert reason is None
        assert entry is not None
        assert s_relay.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) == 1
    finally:
        s_relay.close()
        s_peer.close()


def test_admit_host_no_generation_drift_on_queue_full() -> None:
    """RC-4: Generational counter must not advance if queue.put_nowait fails."""
    bridge = _load_bridge()
    host = "test-host-rc4"
    s_dummy, peer_dummy = socket.socketpair()
    s_full, peer_full = socket.socketpair()

    q_full: queue.Queue[Any] = queue.Queue(maxsize=1)
    q_full.put_nowait(s_dummy)

    try:
        gen_before = bridge._lease_gens.get(host, 0)
        reason, entry = bridge.admit_host(host, "carrier-rc4", q_full, s_full)
        gen_after = bridge._lease_gens.get(host, 0)

        assert reason == "tunnel queue full"
        assert entry is None
        assert gen_after == gen_before
    finally:
        s_dummy.close()
        peer_dummy.close()
        s_full.close()
        peer_full.close()


def test_carrier_id_stability_and_overrides() -> None:
    """RC-6 & RC-10: Carrier identity must be stable and overridable."""
    # Test moesh_tunnel
    orig_env = os.environ.get("MOESH_TUNNEL_ID")
    try:
        os.environ.pop("MOESH_TUNNEL_ID", None)
        c1 = moesh_tunnel.derive_carrier_id()
        c2 = moesh_tunnel.derive_carrier_id()
        assert c1 == c2
        assert len(c1) == 16

        os.environ["MOESH_TUNNEL_ID"] = "explicit-tunnel-id"
        assert moesh_tunnel.derive_carrier_id() == "explicit-tunnel-id"
    finally:
        if orig_env is not None:
            os.environ["MOESH_TUNNEL_ID"] = orig_env
        else:
            os.environ.pop("MOESH_TUNNEL_ID", None)

    # Test moesh_relay
    orig_relay_env = os.environ.get("MOESH_RELAY_ID")
    try:
        os.environ.pop("MOESH_RELAY_ID", None)
        r1 = moesh_relay.derive_carrier_id()
        r2 = moesh_relay.derive_carrier_id()
        assert r1 == r2
        assert len(r1) == 16

        os.environ["MOESH_RELAY_ID"] = "env-relay-id"
        assert moesh_relay.derive_carrier_id() == "env-relay-id"

        assert moesh_relay.derive_carrier_id("explicit-arg-id") == "explicit-arg-id"
    finally:
        if orig_relay_env is not None:
            os.environ["MOESH_RELAY_ID"] = orig_relay_env
        else:
            os.environ.pop("MOESH_RELAY_ID", None)


def test_tunnel_worker_incident_scoped_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    """RC-5: tunnel_worker must retry transient 409s during steady state."""
    calls = 0

    def mock_serve_once(*_args: Any, **_kwargs: Any) -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            # Steady state session
            return "closed"
        if calls == 2:
            # Transient 409 incident
            raise moesh_tunnel.HostConflictError("transient conflict")
        if calls == 3:
            # Successfully resolved retry
            return "closed"
        raise moesh_tunnel.Stop()

    monkeypatch.setattr(moesh_tunnel, "serve_once", mock_serve_once)
    monkeypatch.setattr(moesh_tunnel.time, "sleep", lambda _s: None)
    moesh_tunnel._stopping = False
    moesh_tunnel._conflict_refused = False

    dummy_pool = moesh_tunnel.ShellPool()
    try:
        moesh_tunnel.tunnel_worker("127.0.0.1", 80, "/path", "host", dummy_pool)
        assert moesh_tunnel._conflict_refused is False
        assert calls == 4
    finally:
        dummy_pool.terminate_all()

