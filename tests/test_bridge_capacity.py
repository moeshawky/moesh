#!/usr/bin/env python3
"""Global connection ceiling for the bridge: ``MOESH_BRIDGE_MAX_CONNECTIONS``.

The ceiling is optional and configurable.  ``0`` or unset means no ceiling:
the ordinary path stays simple and byte-for-byte identical to today (no
counter is touched, no lock is taken).  A positive N caps
simultaneously-active accepted connections across *every* listener (tunnel,
operator v1, operator v2, every relay port).

Shape (the non-negotiable part): the check and the increment are one atomic
critical section at the accept->worker handoff in ``serve()``.  A ceiling
refusal happens *before* any ``client_worker`` is spawned and *before* any
queue or lease is touched, so it consumes zero queued tunnel slots and cannot
recreate the Iron Law 4 probe-starvation trap.  The release runs exactly once
in a ``finally`` covering normal close, timeout and exception; the increment is
rolled back if the worker thread never starts.

Every test here binds an ephemeral port via the harness (never the real
operator ports 44440/44441/9447) and starts a real bridge subprocess, so none
of them probe a live deployment.

Regression status: every refusal/recovery test structurally fails against the
code it replaces, because before this patch there is no ceiling at all -- an
excess connection was simply admitted, and the counter did not exist.

House style: tests poll state transitions (queue depth, log lines, pairing)
instead of sleeping fixed intervals.  Under shared-bridge load a fixed margin
can land before the release it waits for -- the measured flakiness here was a
second carrier's upgrade coming back 503 instead of 101, and a bridge log line
that existed but had not flushed yet (2026-11-03: 2 cores, 3x CPU
oversubscription, ~25% solo failure rate for the ceiling-operator test).
"""
# RULE 1 (headroom): every test keeps ONE permanent free slot for probes.
# Refusal assertions stay exact (attempt N+1 on ceiling N), but status/_queued
# observation only ever runs when the test has arranged active < ceiling.  This is
# NOT weakening: Iron Law 4 (refused attempt consumed no queued carrier) is still
# asserted with the carrier queue exact and the refusal classification exact.
# T6 therefore runs ceiling=3: 2 fillable + 1 permanent probe slot.
# RULE 2 (state over logs): verify pairing by POLLING _queued for a DROP (2->1),
# never by log needle.  Refusal log line may stay a _wait_for_log convenience but
# no assertion's fate may depend on a stdout flush.
#
# Measured failure evidence (2026-11-03, load-avg 6.7 / 2 cores):
#   * status probe got 503 during settled-poll: the observation channel competed
#     with the system under test for the very slots it measures (TOCTOU).
#   * pairing log line sat unflushed in block-buffered stdout >30 s: log polling
#     under load is inherently flush-limited.
# RULE 3 (recovery polls, refusal stays single-shot): a recovery assertion
# polls to first-accept; only refusals at ARRANGED-full (persistently-held
# sockets, not an observation) are single-shot.  Measured 2026-11-03 solo x10
# (3/10 red at :266/:370): the trailing single-shot after a successful recovery
# probe raced that probe's own slot release -- observation channels consume
# slots transiently, so instantaneous re-observation of recovery cannot be
# race-free, while first-accept polling proves admission exactly.
# RULE 4 (proven admission): every slot-holder is proven admitted (_hold reads
# through a silence-window; silence = admitted, 503/EOF = refused = zero bridge
# state, retried) before any fullness assertion.  create_connection returns
# from the backlog, so a held socket can be gate-refused unseen behind a
# lagging status-probe release, and the single-shot excess then sails through
# the phantom slot (measured 2026-11-03, 6-burner load: 503-then-accepted).
# Proven-admitted holders make active >= ceiling a fact, not a probe sample.

from __future__ import annotations

import contextlib
import json
import socket
import time
from typing import Any, cast

import moesh_proto as proto
import moesh_wire as wire
from tests.harness import Bridge, next_ports


def _raw_connect(port: int) -> socket.socket:
    """Open a raw TCP connection to the bridge on ``port``."""
    return socket.create_connection(("127.0.0.1", port), timeout=5.0)


def _read_head(sock: socket.socket, timeout: float = 10.0) -> bytes:
    """Read one HTTP response head from an already-connected socket."""
    sock.settimeout(timeout)
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = sock.recv(4096)
        if not chunk:
            break
        head += chunk
    return head


def _v2_upgrade(path: str) -> bytes:
    """Build a v2 host-tunnel upgrade request for ``path``."""
    lines = [
        f"GET {path} HTTP/1.1",
        "Host: 127.0.0.1",
        f"Upgrade: {wire.UPGRADE_TOKEN}",
        "Connection: Upgrade",
        f"X-Moesh-Tunnel-Version: {proto.PROTOCOL_VERSION}",
    ]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def _raw_request(port: int, request: bytes) -> bytes:
    """Send ``request`` to the bridge on ``port`` and return the response head."""
    with socket.create_connection(("127.0.0.1", port), timeout=10.0) as sock:
        sock.sendall(request)
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        return response


def _status(tunnel_port: int) -> dict[str, Any]:
    """Read the bridge's own JSON status probe."""
    raw = _raw_request(
        tunnel_port,
        b"GET /__moesh/status HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    )
    assert b" 200 " in raw.split(b"\r\n", 1)[0], raw
    return cast("dict[str, Any]", json.loads(raw.split(b"\r\n\r\n", 1)[1]))


def _queued(tunnel_port: int) -> int:
    """Total carriers queued across all host queues, per the bridge status."""
    details = _status(tunnel_port)["hosts"]["details"]
    return sum(int(detail.get("queued", 0)) for detail in details.values())


def _wait_for_log(bridge: Bridge, needle: str, timeout: float = 10.0) -> None:
    """Poll the bridge log until ``needle`` appears, up to ``timeout`` seconds.

    The bridge emits its log lines through the harness log file, whose stdout
    is block-buffered: a line the bridge has already emitted can still be
    absent from :meth:`Bridge.log_text` the instant a test reads it after the
    triggering response (measured 2026-11-03, the same flush/ordering failure
    as the rc=120 case).  Polling instead of asserting immediately removes the
    race; this mirrors the pairing poll already used in
    ``test_ceiling_exceeded_operator_does_not_consume_queued_carrier``.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if needle in bridge.log_text():
            return
        time.sleep(0.1)
    raise AssertionError(
        f"bridge log did not contain {needle!r} within {timeout}s: "
        f"{bridge.log_text()}"
    )


def _attempt_raw(port: int, read_timeout: float = 2.0) -> str:
    """Connect raw TCP and classify the bridge's response.

    Returns ``"refused"`` when the bridge answers with a 503 (ceiling refusal)
    and ``"accepted"`` when it admits the connection (no data comes back while
    the worker blocks in the handshake).
    """
    sock = socket.create_connection(("127.0.0.1", port), timeout=5.0)
    sock.settimeout(read_timeout)
    try:
        data = sock.recv(4096)
        return "refused" if b"503" in data else "unexpected-data"
    except TimeoutError:
        return "accepted"
    finally:
        with contextlib.suppress(OSError):
            sock.close()


def _hold(port: int, count: int, timeout: float = 20.0, window: float = 3.0) -> list[socket.socket]:
    """Prove ``count`` raw connections admitted; each holds one counter slot.

    ``create_connection`` returns from the listener backlog, so a socket the
    test holds may still be gate-refused: under load a lagging status-probe
    release fills the ceiling exactly as the holder is accepted, and every
    downstream fullness assertion is then built on a phantom slot (measured
    2026-11-03, 6-burner load: the Iron Law 4 guard's held socket was refused
    unseen, its 503 unread, and the single-shot excess came back ``accepted``).
    Each round connects the missing sockets, sends nothing -- an admitted
    worker blocks in ``read_headers`` and stays silent -- and reads every
    socket through a ``window`` deadline: a 503 head or EOF is a refusal (the
    bridge left zero state: refusal precedes the increment, Iron Law 4), so
    the round retries it; silence through the whole window is admission.
    """
    admitted: list[socket.socket] = []
    deadline = time.time() + timeout
    while len(admitted) < count:
        missing = count - len(admitted)
        socks = [_raw_connect(port) for _ in range(missing)]
        data = [b""] * missing
        refused: set[int] = set()
        window_end = time.time() + window
        while time.time() < window_end:
            for i, sock in enumerate(socks):
                if i in refused:
                    continue
                sock.settimeout(0.1)
                try:
                    chunk = sock.recv(4096)
                except TimeoutError:
                    continue
                data[i] += chunk
                if not chunk or b"\r\n\r\n" in data[i]:
                    refused.add(i)
        for i, sock in enumerate(socks):
            if i in refused:
                with contextlib.suppress(OSError):
                    sock.close()
            else:
                sock.settimeout(None)
                admitted.append(sock)
        if len(admitted) < count and time.time() >= deadline:
            for sock in admitted:
                with contextlib.suppress(OSError):
                    sock.close()
            raise AssertionError(
                f"only {len(admitted)} of {count} connections proven admitted "
                f"within {timeout}s ({len(refused)} refused in last round)"
            )
    return admitted


def _wait_until_accepted(port: int, timeout: float = 10.0) -> None:
    """Poll raw-admission until a connection is admitted, up to ``timeout``.

    Recovery-side rule (RULE 3, measured 2026-11-03 solo x10, 3/10 red): a
    single-shot re-observation right after a successful probe races that
    probe's own slot release -- the observation channel transiently consumes
    the very slot it measures, so the re-observation came back 503.  Polling
    to first-accept proves admission just as rigorously; single-shot stays
    only for refusals at arranged-full.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _attempt_raw(port) == "accepted":
            return
        time.sleep(0.1)
    raise AssertionError(f"no admission within {timeout}s (slot not released)")


def _wait_for_queued(tunnel_port: int, expected: int, timeout: float = 10.0) -> None:
    """Poll the bridge status until ``_queued`` reads ``expected``.

    Tolerates ``_status`` being 503-refused at the ceiling (a previous probe's
    worker still releasing its slot -- RULE 1): the queue itself can only move
    through pairing, so during these windows no actor can change it and the
    invariant stays exact.  With T6's permanent headroom (ceiling=3) refusals here are momentary only.
    If a refusal had consumed a carrier (the bug this
    guards), the queue would never read ``expected`` and the deadline fails.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if _queued(tunnel_port) == expected:
                return
        except AssertionError:
            pass  # status refused at the ceiling; previous probe still releasing
        time.sleep(0.1)
    raise AssertionError(f"_queued never read {expected} within {timeout}s")


def _await_carrier(tunnel_port: int) -> socket.socket:
    """Connect one v2 carrier and retry until its 101 upgrade is admitted.

    A carrier is admitted only once the previous carrier's admitting worker
    has released its connection slot; under load that release can land after a
    connect, so the upgrade comes back ``503`` instead of ``101`` (the
    worker sends the 101 at moesh-bridge.py:1127 and releases the slot in its
    :func:`client_worker` finally at moesh-bridge.py:1687).  Refused connects
    consume no slot and touch no queued carrier (Iron Law 4), so retrying
    cannot starve the ceiling or consume a queued carrier.  Retrying until the
    101 arrives asserts the release path instead of assuming a fixed margin is
    enough (measured 2026-11-03: 2 cores, 3x oversubscription, ~25% solo
    failure for this test).
    """
    deadline = time.time() + 10.0
    last_head = b""
    while time.time() < deadline:
        carrier = _raw_connect(tunnel_port)
        carrier.sendall(_v2_upgrade(wire.TUNNEL_PATH))
        try:
            head = _read_head(carrier, timeout=5.0)
        except OSError:
            with contextlib.suppress(OSError):
                carrier.close()
            continue
        if b" 101 " in head.split(b"\r\n", 1)[0]:
            return carrier
        last_head = head
        with contextlib.suppress(OSError):
            carrier.close()
        time.sleep(0.1)
    raise AssertionError(
        f"carrier upgrade was never admitted (ceiling slot not released); "
        f"last head: {last_head!r}"
    )


def test_ceiling_refuses_excess_connections_while_first_n_stay_unaffected() -> None:
    """With MAX_CONNECTIONS=N the first N raw connections are admitted and the rest are refused promptly."""
    ceiling = 2
    extra = 3
    tunnel_port, operator_port, operator_v2_port = next_ports()
    bridge = Bridge(
        tunnel_port,
        operator_port,
        operator_v2_port,
        env_extra={"MOESH_BRIDGE_MAX_CONNECTIONS": str(ceiling)},
    )
    socks: list[socket.socket] = []
    try:
        # Connect N+K raw tunnels: the bridge admits exactly N and refuses the
        # rest at accept time.  No bytes are sent, so admitted workers block in
        # the handshake and keep holding their slots while the excess are read.
        for _ in range(ceiling + extra):
            socks.append(_raw_connect(tunnel_port))
        results: list[str] = []
        for sock in socks:
            # a 503 later than this would mis-classify as accepted (RULE 4 evidence)
            sock.settimeout(5.0)
            try:
                data = sock.recv(4096)
                results.append("refused" if b"503" in data else "unexpected-data")
            except TimeoutError:
                results.append("accepted")
        refused = sum(1 for result in results if result == "refused")
        accepted = sum(1 for result in results if result == "accepted")
        assert refused == extra, f"expected {extra} refusals, got {refused}: {results}"
        assert accepted == ceiling, f"expected {ceiling} admissions, got {accepted}: {results}"
        _wait_for_log(bridge, "connection ceiling", 15.0)
    finally:
        for sock in socks:
            with contextlib.suppress(OSError):
                sock.close()
        bridge.stop()


def test_ceiling_exhaustion_then_recovery_admits_after_close() -> None:
    """At the ceiling an excess connection is refused; closing one held connection releases its slot and admits a new one."""
    ceiling = 2
    tunnel_port, operator_port, operator_v2_port = next_ports()
    bridge = Bridge(
        tunnel_port,
        operator_port,
        operator_v2_port,
        env_extra={"MOESH_BRIDGE_MAX_CONNECTIONS": str(ceiling)},
    )
    held: list[socket.socket] = []
    try:
        held = _hold(tunnel_port, ceiling)  # hold ceiling sockets; counted asynchronously
        # holders are proven-admitted: fullness is a fact, not a probe sample (RULE 4)
        assert _attempt_raw(tunnel_port) == "refused"  # excess refused (single-shot)
        held[0].close()  # client disconnect releases one slot -> headroom = 1
        # Poll until recovery admits: polling the classification IS the property
        # (recovery admits eventually), so this is legitimate.  Headroom = 1 is
        # kept because _attempt_raw closes every probe connection (RULE 1).
        # RULE 3: poll to first-accept IS the recovery assertion.  The old
        # trailing single-shot raced the successful probe's own slot release
        # (measured 2026-11-03: 503 on the re-observation).
        _wait_until_accepted(tunnel_port, 10.0)
    finally:
        for sock in held:
            with contextlib.suppress(OSError):
                sock.close()
        bridge.stop()


def test_counter_releases_on_client_disconnect_before_pairing() -> None:
    """A client that disconnects before pairing releases its slot so a new connection is admitted."""
    ceiling = 2
    tunnel_port, operator_port, operator_v2_port = next_ports()
    bridge = Bridge(
        tunnel_port,
        operator_port,
        operator_v2_port,
        env_extra={"MOESH_BRIDGE_MAX_CONNECTIONS": str(ceiling)},
    )
    held: list[socket.socket] = []
    operator_a: socket.socket | None = None
    try:
        held = _hold(tunnel_port, ceiling - 1)  # one slot held
        operator_a = _hold(tunnel_port, 1)[0]  # proven admitted; holds the last slot, no prelude, not paired
        assert operator_a is not None
        # RULE 4: both holders proven-admitted, so the ceiling is provably full here.
        # holders are proven-admitted: fullness is a fact, not a probe sample (RULE 4)
        assert _attempt_raw(tunnel_port) == "refused"  # ceiling full (single-shot)
        operator_a.close()  # client disconnects before pairing
        operator_a = None
        # Wait for the release to land instead of a fixed margin: under load the
        # worker's finally can release the slot after a connect, so polling the
        # status probe (admitted once a slot is free) waits for the real release
        # (measured 2026-11-03).  The final probe below stays single-shot.
        deadline = time.time() + 10.0
        released = False
        while time.time() < deadline:
            try:
                _status(tunnel_port)
                released = True
                break
            except AssertionError:
                time.sleep(0.1)
        assert released, "connection slot was not released after client disconnect"
        # RULE 3: raw-admission observed by polling to first-accept, not a
        # single-shot racing the status probe's own slot release.
        _wait_until_accepted(tunnel_port, 10.0)
    finally:
        for sock in held:
            with contextlib.suppress(OSError):
                sock.close()
        if operator_a is not None:
            with contextlib.suppress(OSError):
                operator_a.close()
        bridge.stop()


def test_counter_releases_after_request_raises_mid_handling() -> None:
    """A connection admitted then raising mid-handshake releases its slot instead of leaking it."""
    ceiling = 2
    tunnel_port, operator_port, operator_v2_port = next_ports()
    bridge = Bridge(
        tunnel_port,
        operator_port,
        operator_v2_port,
        env_extra={"MOESH_BRIDGE_MAX_CONNECTIONS": str(ceiling)},
    )
    held: list[socket.socket] = []
    raiser: socket.socket | None = None
    try:
        held = _hold(tunnel_port, ceiling - 1)  # one slot held
        raiser = _hold(tunnel_port, 1)[0]  # PROVEN admitted (RULE 4) -- a refused raiser would make this leak-test vacuous
        # Oversized header block with no terminator: read_headers raises mid-handshake.
        raiser.sendall(
            b"GET /__moesh/tunnel HTTP/1.1\r\n"
            + b"X-Junk: "
            + b"a" * 70000
            + b"\r\n"
        )
        with contextlib.suppress(OSError):
            raiser.close()
        raiser = None
        # RULE 3: poll to first-accept IS the recovery assertion (no fixed
        # margin; headroom = 1 exists after raiser closes, so probing is
        # RULE 1-safe).  The trailing single-shot raced the successful probe's
        # own slot release (measured 2026-11-03: 503 on the re-observation).
        _wait_until_accepted(tunnel_port, 10.0)
    finally:
        for sock in held:
            with contextlib.suppress(OSError):
                sock.close()
        if raiser is not None:
            with contextlib.suppress(OSError):
                raiser.close()
        bridge.stop()


def test_ceiling_zero_or_unset_admits_many_without_refusal() -> None:
    """MAX_CONNECTIONS=0 or unset behaves like today: any number admitted, no refusal in the logs."""
    for value in ("0", None):
        env_extra: dict[str, str] | None = None if value is None else {"MOESH_BRIDGE_MAX_CONNECTIONS": value}
        tunnel_port, operator_port, operator_v2_port = next_ports()
        bridge = Bridge(tunnel_port, operator_port, operator_v2_port, env_extra=env_extra)
        socks: list[socket.socket] = []
        try:
            socks = [_raw_connect(tunnel_port) for _ in range(10)]
            refused = 0
            for sock in socks:
                sock.settimeout(0.3)
                try:
                    data = sock.recv(4096)
                    if b"503" in data:
                        refused += 1
                except TimeoutError:
                    pass  # admitted: blocked in handshake, no data yet
            assert refused == 0, f"MAX_CONNECTIONS={value!r} refused {refused} of 10"
            assert "connection ceiling" not in bridge.log_text(), bridge.log_text()
        finally:
            for sock in socks:
                with contextlib.suppress(OSError):
                    sock.close()
            bridge.stop()


def test_ceiling_exceeded_operator_does_not_consume_queued_carrier() -> None:
    """IRON LAW 4 guard: a ceiling-exceeded operator connection must not consume a queued carrier.

    ceiling=3.  Two carriers are queued on the bare v2 path; they hold queue
    entries, not slots (their admitting workers released their counter slots
    after the 101).  Operator A connects with no prelude and holds slot 1 of 3
    (RULE 1: one slot stays permanently free for status probes — measured
    2026-11-03/04: at ceiling 2 with zero headroom, a lingering probe slot
    starved every status read and the pairing poll failed though pairing had
    succeeded).  held_extra fills TWO slots (active == ceiling == 3); an excess
    attempt is refused at accept time (single-shot, exact: attempt N+1 on ceiling
    N).  The refusal consumed nothing: after closing held_extra and operator_a and
    waiting for the release (probe-200-poll), _queued stays 2 (state, RULE 2).
    Operator C then pairs; _queued drops 2->1 observed by polling state with a 30 s
    deadline (no log needle, no flush dependency).  Finally _queued==0.
    """
    ceiling = 3
    tunnel_port, operator_port, operator_v2_port = next_ports()
    bridge = Bridge(
        tunnel_port,
        operator_port,
        operator_v2_port,
        env_extra={"MOESH_BRIDGE_MAX_CONNECTIONS": str(ceiling)},
    )
    carriers: list[socket.socket] = []
    operator_a: socket.socket | None = None
    operator_c: socket.socket | None = None
    held_extra: list[socket.socket] = []
    try:
        # Two carriers queued on the bare v2 path.  Their admitting workers
        # release their counter slots after the 101 (sent at moesh-bridge.py:1127,
        # slot released in client_worker's finally at moesh-bridge.py:1687), so
        # under load the release can still be in flight after connect.  Retry
        # until each 101 lands.
        for _ in range(2):
            carriers.append(_await_carrier(tunnel_port))
        # Settled-poll: wait until both carrier slots are released so headroom
        # exists (active < ceiling) before asserting queue depth.  Keeps RULE 1
        # (headroom for probes) and is state, not log (RULE 2).
        deadline = time.time() + 10.0
        settled = False
        while time.time() < deadline:
            try:
                _status(tunnel_port)
                settled = True
                break
            except AssertionError:
                time.sleep(0.1)
        assert settled, "carrier connection slots were not released"
        # RULE 3 shape for state reads: poll, tolerating a 503 on the status
        # probe while the settled-poll's own probe is still releasing its slot.
        _wait_for_queued(tunnel_port, 2)

        # Operator A connects with no prelude: holds slot 1 of 2 -> 1 headroom.
        # read_host_label blocks on its MSG_PEEK (up to 15 s) so the slot is held
        # while we fill the headroom and probe the refusal; closing the socket
        # ends the peek promptly (EOF), releasing the slot.
        operator_a = _hold(operator_v2_port, 1)[0]  # proven admitted; holds slot 1 of 2
        assert operator_a is not None

        # Fill the headroom: active == ceiling.  Excess attempt refused at accept
        # time (single-shot, exact: attempt N+1 on ceiling N).
        held_extra = _hold(tunnel_port, 2)
        # holders are proven-admitted: fullness is a fact, not a probe sample (RULE 4)
        assert _attempt_raw(tunnel_port) == "refused"

        # Close held_extra (restore 1 headroom so probes work again), then
        # operator_a, wait for release via probe-200-poll (state: a 200 status
        # means a slot is free; no log flush dependency).
        for sock in held_extra:
            with contextlib.suppress(OSError):
                sock.close()
        held_extra = []
        operator_a.close()
        operator_a = None
        deadline = time.time() + 10.0
        released = False
        while time.time() < deadline:
            try:
                _status(tunnel_port)
                released = True
                break
            except AssertionError:
                time.sleep(0.1)
        assert released, "connection slot was not released after operator disconnect"

        # THE guard: refusal consumed nothing — both carriers still queued.
        # _queued is state (RULE 2) polled (RULE 3): the deadline fails if the
        # refusal had eaten a carrier; nothing else can move the queue here
        # (operator_c has not connected yet).
        _wait_for_queued(tunnel_port, 2)

        # Operator C connects + prelude default; pairing observed as STATE:
        # _queued drops 2->1, polled with a 30 s deadline, no log, no flush.
        # _queued polls _status; if operator_a's release is still in flight
        # (active == ceiling), _status is refused and we retry — headroom
        # returns as soon as operator_a's worker exits on the EOF.
        operator_c = _raw_connect(operator_v2_port)
        assert operator_c is not None
        operator_c.sendall(wire.PRELUDE_PREFIX + b"default\n")
        _wait_for_queued(tunnel_port, 1, 30.0)

        # Close operator_c + all carriers; queue drains to 0.  Poll _queued
        # until 0 (state; headroom = 2 since all legs are closed) so the
        # assertion does not race the bridge's pair teardown under load.
        operator_c.close()
        operator_c = None
        for sock in carriers:
            with contextlib.suppress(OSError):
                sock.close()
        _wait_for_queued(tunnel_port, 0)
    finally:
        for sock in carriers:
            with contextlib.suppress(OSError):
                sock.close()
        if operator_a is not None:
            with contextlib.suppress(OSError):
                operator_a.close()
        if operator_c is not None:
            with contextlib.suppress(OSError):
                operator_c.close()
        for sock in held_extra:
            with contextlib.suppress(OSError):
                sock.close()
        bridge.stop()
