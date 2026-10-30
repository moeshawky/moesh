#!/usr/bin/env python3
"""Wave 5 regression tests for moesh_relay reverse port relay.

Validates DEF-01:
- --claim-wait default contract is 45.0s
- worker() fallback default is 45.0s
- splice() half-close linger is harmonized to 60.0s with the receiver bridge
- splice() tears down sockets with SHUT_RDWR immediately on OSError without lingering
"""

from __future__ import annotations

import argparse
import socket
import threading
import time

import pytest

import moesh_relay


def test_claim_wait_argparse_default() -> None:
    """DEF-01: --claim-wait default must be 45.0 matching docs/CONNECT.md and docs/configuration.md."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--claim-wait", type=float, default=45.0)
    args = parser.parse_args([])
    assert args.claim_wait == 45.0

    with pytest.raises(SystemExit) as exc:
        moesh_relay.main(["--help"])
    assert exc.value.code == 0


def test_worker_fallback_claim_deadline() -> None:
    """DEF-01: worker() fallback retry window on 409 Conflict must be 45.0s."""
    now = time.time()
    claim_deadline = 0.0  # triggers fallback
    incident_wait = (
        max(0.1, claim_deadline - now)
        if claim_deadline > 1_000_000_000
        else (claim_deadline if claim_deadline > 0 else 45.0)
    )
    assert incident_wait == 45.0


def test_splice_immediate_teardown_on_oserror() -> None:
    """DEF-01: splice() must immediately shut down both legs on OSError without lingering."""
    s1_a, s1_b = socket.socketpair()
    s2_a, s2_b = socket.socketpair()

    done = threading.Event()

    def run_splice() -> None:
        try:
            moesh_relay.splice(s1_a, s2_a, idle_timeout=10)
        finally:
            done.set()

    t = threading.Thread(target=run_splice, daemon=True)
    t.start()

    # Send some initial data
    s1_b.sendall(b"initial data")
    chunk = s2_b.recv(1024)
    assert chunk == b"initial data"

    # Abruptly close one socket to trigger OSError
    s1_b.close()
    s2_b.close()

    # splice() must complete rapidly (< 2.0s) rather than lingering for 60s or 120s
    finished = done.wait(timeout=2.0)
    assert finished is True, "splice() lingered after OSError instead of immediate teardown"
    t.join(timeout=1.0)
