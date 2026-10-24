#!/usr/bin/env python3
"""Unit and cryptographic tests for the moesh v2 protocol core.

Run with an interpreter that has ``noiseprotocol`` installed (the tooling
venv)::

    python -m pytest tests/test_protocol_core.py -q

Every cryptographic test states the property it measures; a passing suite is
not taken as proof of a property the probe does not measure.
"""

from __future__ import annotations

import importlib.util
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Any

import pytest

import moesh_proto as proto
import moesh_tunnel as agent
from moesh_proto import (
    AuthenticationError,
    FramingError,
    Msg,
    NegotiationError,
    ProtocolError,
    State,
    StateError,
)

_BRIDGE_PATH = Path(__file__).resolve().parent.parent / "moesh-bridge.py"
_bridge_spec = importlib.util.spec_from_file_location("moesh_bridge", _BRIDGE_PATH)
assert _bridge_spec is not None and _bridge_spec.loader is not None
_bridge = importlib.util.module_from_spec(_bridge_spec)
_bridge_spec.loader.exec_module(_bridge)
read_host_label = _bridge.read_host_label
PRELUDE_PREFIX = _bridge.PRELUDE_PREFIX

PRIVATE_A, PUBLIC_A = proto.generate_static_keypair()
PRIVATE_B, PUBLIC_B = proto.generate_static_keypair()


def _initiator(sock: socket.socket, session: proto.NoiseSession) -> None:
    """Run the initiator half of the Noise handshake over ``sock``."""
    channel = proto.Channel(sock)
    channel.send_frame(session.write_handshake())
    session.read_handshake(channel.recv_frame())
    channel.send_frame(session.write_handshake())


def _responder(sock: socket.socket, session: proto.NoiseSession) -> None:
    """Run the responder half of the Noise handshake over ``sock``."""
    channel = proto.Channel(sock)
    session.read_handshake(channel.recv_frame())
    channel.send_frame(session.write_handshake())
    session.read_handshake(channel.recv_frame())


def handshake_pair(
    private_a: bytes = PRIVATE_A,
    public_a: bytes = PUBLIC_A,
    private_b: bytes = PRIVATE_B,
    public_b: bytes = PUBLIC_B,
    pin_a: bytes | None = None,
    pin_b: bytes | None = None,
) -> tuple[
    proto.NoiseSession,
    proto.NoiseSession,
    socket.socket,
    socket.socket,
    list[Exception],
]:
    """Run a complete XX handshake between two endpoints.

    ``pin_a`` is the key endpoint A expects from B and ``pin_b`` the key
    endpoint B expects from A.  Returns the two sessions, the socket pair and
    the list of errors raised by the initiator thread.
    """
    sock_a, sock_b = socket.socketpair()
    sock_a.settimeout(10)
    sock_b.settimeout(10)
    errors: list[Exception] = []
    session_a = proto.NoiseSession("initiator", private_a, pin_a or public_b)
    session_b = proto.NoiseSession("responder", private_b, pin_b or public_a)

    def run_initiator() -> None:
        try:
            _initiator(sock_a, session_a)
        except Exception as exc:
            errors.append(exc)

    def run_responder() -> None:
        try:
            _responder(sock_b, session_b)
        except Exception as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=run_initiator, daemon=True),
        threading.Thread(target=run_responder, daemon=True),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)
    return session_a, session_b, sock_a, sock_b, errors


# --------------------------------------------------------------------------
# Framing
# --------------------------------------------------------------------------


def test_frame_roundtrip() -> None:
    """A framed payload is recovered byte for byte."""
    reader = proto.FrameReader()
    reader.feed(proto.frame(b"terminal bytes\x00\xff"))
    assert reader.next_frame() == b"terminal bytes\x00\xff"
    assert reader.next_frame() is None


def test_frame_split_across_reads() -> None:
    """A frame delivered one byte at a time is reassembled."""
    reader = proto.FrameReader()
    payload = b"x" * 1000
    wire = proto.frame(payload)
    for index in range(len(wire)):
        reader.feed(wire[index : index + 1])
        if index < len(wire) - 1:
            assert reader.next_frame() is None
    assert reader.next_frame() == payload


def test_multiple_frames_in_one_read() -> None:
    """Several frames delivered by one read are all returned, in order."""
    reader = proto.FrameReader()
    reader.feed(proto.frame(b"one") + proto.frame(b"two") + proto.frame(b"three"))
    assert reader.frames() == [b"one", b"two", b"three"]


def test_frame_larger_than_bound_is_rejected() -> None:
    """An oversized frame is refused instead of being buffered."""
    reader = proto.FrameReader(max_frame=1024)
    reader.feed(struct.pack(">I", 4096) + b"x" * 16)
    with pytest.raises(FramingError):
        reader.next_frame()


def test_zero_length_frame_is_rejected() -> None:
    """A zero-length frame is refused."""
    reader = proto.FrameReader()
    reader.feed(struct.pack(">I", 0))
    with pytest.raises(FramingError):
        reader.next_frame()


# --------------------------------------------------------------------------
# State machine
# --------------------------------------------------------------------------


def test_state_machine_allows_the_documented_path() -> None:
    """CONNECTED -> AUTHENTICATED -> NEGOTIATING -> READY -> ACTIVE -> CLOSING."""
    machine = proto.SessionState()
    for target in (
        State.AUTHENTICATED,
        State.NEGOTIATING,
        State.READY,
        State.ACTIVE,
        State.CLOSING,
    ):
        machine.to(target)
        assert machine.state is target


def test_state_machine_rejects_a_skipped_state() -> None:
    """Skipping a state fails closed."""
    machine = proto.SessionState()
    with pytest.raises(StateError):
        machine.to(State.ACTIVE)
    assert machine.state is State.CONNECTED


def test_state_machine_rejects_a_backwards_transition() -> None:
    """Going back to an earlier state fails closed."""
    machine = proto.SessionState()
    machine.to(State.AUTHENTICATED)
    with pytest.raises(StateError):
        machine.to(State.CONNECTED)


# --------------------------------------------------------------------------
# Negotiation validation
# --------------------------------------------------------------------------


def _good_hello() -> dict[str, Any]:
    return {
        "version": 2,
        "term": "xterm-256color",
        "encoding": "utf-8",
        "rows": 40,
        "cols": 120,
        "capabilities": ["resize"],
        "max_record": 32768,
    }


def test_validate_hello_accepts_a_good_hello() -> None:
    """A well-formed HELLO is accepted with the peer's dimensions."""
    accepted = proto.validate_hello(_good_hello())
    assert accepted["rows"] == 40
    assert accepted["cols"] == 120
    assert accepted["max_record"] == 32768


@pytest.mark.parametrize(
    "mutation",
    [
        {"version": 1},
        {"version": 3},
        {"rows": 0},
        {"cols": 0},
        {"rows": 5000},
        {"cols": 5000},
        {"rows": "40"},
        {"encoding": "latin-1"},
        {"term": ""},
        {"term": "x" * 40},
        {"term": "bad\x01term"},
        {"max_record": 3},
        {"capabilities": "resize"},
    ],
)
def test_validate_hello_rejects_bad_values(mutation: dict[str, Any]) -> None:
    """Every malformed HELLO value is refused."""
    hello = _good_hello()
    hello.update(mutation)
    with pytest.raises(NegotiationError):
        proto.validate_hello(hello)


def test_validate_resize_bounds() -> None:
    """RESIZE dimensions are validated on both ends."""
    assert proto.validate_resize({"rows": 24, "cols": 80}) == (24, 80)
    for bad in (
        {"rows": 0, "cols": 80},
        {"rows": 24, "cols": 0},
        {"rows": 24, "cols": 99999},
    ):
        with pytest.raises(NegotiationError):
            proto.validate_resize(bad)


# --------------------------------------------------------------------------
# Cryptography
# --------------------------------------------------------------------------


def test_pinned_peers_authenticate() -> None:
    """Two endpoints with matching pins complete the handshake and agree on the transcript."""
    session_a, session_b, sock_a, sock_b, errors = handshake_pair()
    assert errors == []
    assert session_a.handshake_finished and session_b.handshake_finished
    assert session_a.authenticated and session_b.authenticated
    assert session_a.handshake_hash() == session_b.handshake_hash()
    sock_a.close()
    sock_b.close()


def test_unknown_peer_is_rejected() -> None:
    """An endpoint whose pin does not match the peer aborts before any record."""
    wrong_pin = proto.generate_static_keypair()[1]
    session_a, _session_b, sock_a, sock_b, errors = handshake_pair(pin_a=wrong_pin)
    assert any(isinstance(error, AuthenticationError) for error in errors)
    assert not session_a.authenticated
    sock_a.close()
    sock_b.close()


def test_responder_rejects_an_unknown_initiator() -> None:
    """The responder also refuses an initiator whose static key is not pinned."""
    wrong_pin = proto.generate_static_keypair()[1]
    _session_a, _session_b, sock_a, sock_b, errors = handshake_pair(pin_b=wrong_pin)
    assert any(isinstance(error, AuthenticationError) for error in errors)
    sock_a.close()
    sock_b.close()


def test_tampered_record_is_rejected() -> None:
    """A modified ciphertext fails authentication."""
    session_a, session_b, sock_a, sock_b, _errors = handshake_pair()
    ciphertext = session_a.encrypt(bytes([Msg.DATA]) + b"secret terminal bytes")
    tampered = bytearray(ciphertext)
    tampered[3] ^= 0x01
    with pytest.raises(AuthenticationError):
        session_b.decrypt(bytes(tampered))
    sock_a.close()
    sock_b.close()


def test_record_from_another_session_is_rejected() -> None:
    """A record minted in a different session cannot be replayed into this one."""
    _session_a, session_b, sock_a, sock_b, _errors = handshake_pair()
    other_a, _other_b, other_sock_a, other_sock_b, _other_errors = handshake_pair()
    ciphertext = other_a.encrypt(bytes([Msg.DATA]) + b"replayed")
    with pytest.raises(AuthenticationError):
        session_b.decrypt(ciphertext)
    for sock in (sock_a, sock_b, other_sock_a, other_sock_b):
        sock.close()


def test_sessions_have_independent_state() -> None:
    """Two sessions of the same key pair derive different transport state."""
    first = handshake_pair()
    second = handshake_pair()
    assert first[0].handshake_hash() != second[0].handshake_hash()
    sock_a, sock_b = socket.socketpair()
    channel_a = proto.Channel(sock_a)
    channel_b = proto.Channel(sock_b)
    secure_a = proto.SecureChannel(channel_a, first[0])
    secure_b = proto.SecureChannel(channel_b, first[1])
    secure_a.send(Msg.DATA, b"hello")
    msg_type, payload = secure_b.recv()
    assert msg_type == Msg.DATA
    assert payload == b"hello"
    for item in (first, second):
        item[2].close()
        item[3].close()
    sock_a.close()
    sock_b.close()


def test_the_broker_sees_no_plaintext() -> None:
    """Bytes observed by a broker contain no terminal plaintext and are not decryptable by it."""
    session_a, _session_b, sock_a, sock_b, _errors = handshake_pair()
    channel_a = proto.Channel(sock_a)
    channel_b = proto.Channel(sock_b)
    secure_a = proto.SecureChannel(channel_a, session_a)
    secret = b"echo hunter2 is the password"
    secure_a.send(Msg.DATA, secret)

    # What a broker in the middle would capture.
    captured = channel_b.next_frame()
    assert captured is None
    channel_b.fill()
    captured = channel_b.next_frame()
    assert captured is not None
    assert secret not in captured
    assert b"hunter2" not in captured

    # The broker holds no key: its own session cannot decrypt the record.
    broker_private, broker_public = proto.generate_static_keypair()
    broker = proto.NoiseSession("responder", broker_private, broker_public)
    with pytest.raises(AuthenticationError):
        broker.decrypt(captured)
    sock_a.close()
    sock_b.close()


def test_a_different_prologue_fails_closed() -> None:
    """A peer speaking another protocol identity cannot complete the handshake."""
    sock_a, sock_b = socket.socketpair()
    sock_a.settimeout(10)
    sock_b.settimeout(10)
    errors: list[Exception] = []

    def run_initiator() -> None:
        try:
            session = proto.NoiseSession(
                "initiator",
                PRIVATE_A,
                PUBLIC_B,
                prologue=b"moesh-tunnel-v2/1/other_suite",
            )
            _initiator(sock_a, session)
        except Exception as exc:
            errors.append(exc)

    def run_responder() -> None:
        try:
            session = proto.NoiseSession("responder", PRIVATE_B, PUBLIC_A)
            _responder(sock_b, session)
        except Exception as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=run_initiator, daemon=True),
        threading.Thread(target=run_responder, daemon=True),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)
    assert errors, "a mismatched prologue must fail the handshake on both sides"
    sock_a.close()
    sock_b.close()


def test_a_truncated_handshake_message_fails_closed() -> None:
    """A handshake message that is too short to be valid is refused."""
    sock_a, sock_b = socket.socketpair()
    session = proto.NoiseSession("responder", PRIVATE_B, PUBLIC_A)
    with pytest.raises(ProtocolError):
        session.read_handshake(b"\x00" * 5)
    sock_a.close()
    sock_b.close()


def test_an_oversized_handshake_message_is_refused() -> None:
    """A handshake message beyond the framing bound is refused before parsing."""
    sock_a, sock_b = socket.socketpair()
    session = proto.NoiseSession("responder", PRIVATE_B, PUBLIC_A)
    with pytest.raises(FramingError):
        session.read_handshake(b"\x00" * (proto.MAX_HANDSHAKE_FRAME + 1))
    sock_a.close()
    sock_b.close()


# --------------------------------------------------------------------------
# The transport's buffer is the source of truth
# --------------------------------------------------------------------------


def test_a_frame_in_the_transport_buffer_is_read_without_a_socket_read() -> None:
    """A frame that is already buffered is returned by the non-blocking read.

    The contract the waiters rely on: bytes that came off the socket live in
    the transport's buffer until they are consumed, so a frame can be
    readable while the socket has nothing left to report.
    """
    left, right = socket.socketpair()
    try:
        channel = proto.Channel(left)
        channel.seed(proto.frame(b"a frame that arrived early"))
        assert channel.next_frame() == b"a frame that arrived early"
        assert channel.next_frame() is None
    finally:
        left.close()
        right.close()


def test_buffered_frames_are_returned_without_reading_the_socket() -> None:
    """Every complete frame in the buffer is returned, and only once."""
    left, right = socket.socketpair()
    try:
        channel = proto.Channel(left)
        channel.seed(proto.frame(b"first") + proto.frame(b"second"))
        assert channel.buffered_frames() == [b"first", b"second"]
        assert channel.buffered_frames() == []
    finally:
        left.close()
        right.close()


def test_a_record_already_in_the_buffer_is_returned_by_the_session() -> None:
    """A record the transport already holds is readable without the socket.

    The session loops drain the buffer on every pass, so a record that
    arrived together with another one is never stranded behind a socket that
    has nothing left to report.
    """
    session_a, session_b, sock_a, sock_b, errors = handshake_pair()
    try:
        assert not errors, f"the handshake must succeed: {errors!r}"
        payload = bytes([int(proto.Msg.PING)])
        sock_b.sendall(proto.frame(session_b.encrypt(payload)))
        channel = proto.Channel(sock_a)
        secure = proto.SecureChannel(channel, session_a)
        channel.fill()
        records = secure.buffered()
        assert records == [(int(proto.Msg.PING), b"")]
        assert secure.buffered() == []
    finally:
        sock_a.close()
        sock_b.close()


def test_the_agent_sees_a_frame_that_arrived_with_the_http_response() -> None:
    """The agent must not wait on the socket for a frame it already holds.

    Regression (2026-10-21): the agent waited for the operator's first
    handshake frame by selecting on the socket.  When that frame arrived in
    the same TCP segment as the HTTP 101 response, it was already in the
    transport's own buffer and the socket had nothing left to report — so
    the agent waited for an operator who had already spoken, and the
    operator sat in its handshake until its own timeout.  Measured on the
    suite: the failing test rotated between runs and appeared in roughly
    one run in three; the frame arrived with the response in exactly the
    runs that failed.

    The probe puts the frame in the buffer directly and leaves the socket
    silent, so the race cannot hide: against the unfixed code the wait
    never returns.
    """
    left, right = socket.socketpair()
    try:
        channel = proto.Channel(left)
        channel.seed(proto.frame(b"the operator's first frame"))
        result: list[bytes] = []

        def waiter() -> None:
            result.append(agent.wait_for_handshake(channel, agent.ShellPool()))

        thread = threading.Thread(target=waiter, daemon=True)
        thread.start()
        thread.join(timeout=5.0)
        assert not thread.is_alive(), (
            "the agent is still waiting for an operator who already spoke: the "
            "frame is in the transport's buffer, not in the socket"
        )
        assert result == [b"the operator's first frame"]
    finally:
        left.close()
        right.close()


def test_read_host_label_valid_label() -> None:
    """A valid label line is parsed and leaves following Noise bytes untouched."""
    left, right = socket.socketpair()
    try:
        noise_bytes = b"\x00\x00\x00\x20noise-handshake-bytes"
        left.sendall(PRELUDE_PREFIX + b"host-42\n" + noise_bytes)
        label = read_host_label(right)
        assert label == "host-42"
        remaining = right.recv(len(noise_bytes))
        assert remaining == noise_bytes
    finally:
        left.close()
        right.close()


def test_read_host_label_no_label() -> None:
    """A connection with no label (first byte 0x00 Noise prefix) returns empty and leaves bytes unconsumed."""
    left, right = socket.socketpair()
    try:
        noise_bytes = b"\x00\x00\x00\x20noise-handshake-bytes"
        left.sendall(noise_bytes)
        label = read_host_label(right)
        assert label == ""
        remaining = right.recv(len(noise_bytes))
        assert remaining == noise_bytes
    finally:
        left.close()
        right.close()


def test_read_host_label_chunked_reads() -> None:
    """A label arriving in single-byte chunks does not duplicate data in MSG_PEEK."""
    left, right = socket.socketpair()
    try:
        noise_bytes = b"\x00\x00\x00\x20noise-handshake-bytes"
        payload = PRELUDE_PREFIX + b"host-chunked\n" + noise_bytes

        def slow_sender() -> None:
            for b in payload:
                left.sendall(bytes([b]))
                time.sleep(0.002)

        thread = threading.Thread(target=slow_sender, daemon=True)
        thread.start()
        label = read_host_label(right)
        thread.join(timeout=5.0)
        assert label == "host-chunked"
        remaining = right.recv(len(noise_bytes))
        assert remaining == noise_bytes
    finally:
        left.close()
        right.close()


def test_escape_filter_detach_sequence() -> None:
    """An escape sequence \r~. causes detach immediately."""
    from moesh_shell import EscapeFilter

    ef = EscapeFilter()
    to_send, detached = ef.feed(b"\r~.")
    assert detached is True
    assert to_send == b"\r"


def test_escape_filter_literal_escape() -> None:
    """Typing ~~ after a newline emits a single ~ and returns to normal state."""
    from moesh_shell import EscapeFilter

    ef = EscapeFilter()
    to_send, detached = ef.feed(b"\r~~")
    assert detached is False
    assert to_send == b"\r~"

    # Subsequent . is now in normal state and does not detach
    to_send2, detached2 = ef.feed(b".")
    assert detached2 is False
    assert to_send2 == b"."


def test_escape_filter_normal_text_with_tildes() -> None:
    """Normal text containing tildes (e.g. echo ~user) is not detached."""
    from moesh_shell import EscapeFilter

    ef = EscapeFilter()
    # As a single chunk
    to_send, detached = ef.feed(b"echo ~user\n")
    assert detached is False
    assert to_send == b"echo ~user\n"

    # As individual keystrokes
    ef2 = EscapeFilter()
    output = bytearray()
    for char in b"echo ~user\n":
        chunk, detached = ef2.feed(bytes([char]))
        assert detached is False
        output.extend(chunk)
    assert bytes(output) == b"echo ~user\n"


def test_escape_filter_split_arrival() -> None:
    """An escape sequence split across separate reads triggers detach."""
    from moesh_shell import EscapeFilter

    ef = EscapeFilter()
    out1, det1 = ef.feed(b"\r")
    assert det1 is False
    assert out1 == b"\r"

    out2, det2 = ef.feed(b"~")
    assert det2 is False
    assert out2 == b""

    out3, det3 = ef.feed(b".")
    assert det3 is True
    assert out3 == b""


def test_escape_filter_burst_paste_immunity() -> None:
    """A multi-byte burst (>3 bytes) containing \\r~. does not trigger detach (GAP-01)."""
    from moesh_shell import EscapeFilter

    ef = EscapeFilter()
    payload = b"echo hello\r~.exit\n"
    to_send, detached = ef.feed(payload)
    assert detached is False
    assert to_send == payload


def test_escape_filter_bracketed_paste_immunity() -> None:
    """Bracketed paste blocks containing \\r~. do not trigger detach (GAP-01)."""
    from moesh_shell import EscapeFilter

    # Single chunk with bracketed paste wrapper
    ef = EscapeFilter()
    payload = b"\x1b[200~\r~.\x1b[201~"
    to_send, detached = ef.feed(payload)
    assert detached is False
    assert to_send == payload

    # Split chunks across reads with bracketed paste
    ef2 = EscapeFilter()
    out1, det1 = ef2.feed(b"\x1b[200~")
    assert det1 is False
    assert out1 == b"\x1b[200~"

    out2, det2 = ef2.feed(b"\r~.")
    assert det2 is False
    assert out2 == b"\r~."

    out3, det3 = ef2.feed(b"\x1b[201~")
    assert det3 is False
    assert out3 == b"\x1b[201~"


def test_escape_filter_trailing_bytes_on_detach() -> None:
    """When . is detected after ~, trailing bytes are not processed and detach returns immediately (GAP-04)."""
    from moesh_shell import EscapeFilter

    ef = EscapeFilter()
    ef.feed(b"\r")
    ef.feed(b"~")
    # Feed slice containing '.' and trailing byte 'x' (len 2 <= 3)
    to_send, detached = ef.feed(b".x")
    assert detached is True
    assert to_send == b""

    # Also test when '~', '.', and trailing byte arrive together in one slice (len 3 <= 3)
    ef2 = EscapeFilter()
    ef2.feed(b"\r")
    to_send2, detached2 = ef2.feed(b"~.x")
    assert detached2 is True
    assert to_send2 == b""


def test_escape_filter_flush_pending_tilde() -> None:
    """Pending held tilde is emitted on flush when stream ends."""
    from moesh_shell import EscapeFilter

    ef = EscapeFilter()
    ef.feed(b"\r~")
    assert ef.flush() == b"~"
    assert ef.flush() == b""


def test_sigwinch_restoration_in_run_session() -> None:
    """run_session restores the previous SIGWINCH handler on exit (GAP-02)."""
    import os
    import signal
    from unittest.mock import MagicMock

    from moesh_shell import run_session

    def dummy_handler(_signum: int, _frame: Any) -> None:
        pass

    old_handler = signal.getsignal(signal.SIGWINCH)
    signal.signal(signal.SIGWINCH, dummy_handler)
    r_in, w_in = os.pipe()
    r_out, w_out = os.pipe()
    try:
        left, right = socket.socketpair()
        try:
            mock_secure = MagicMock()
            mock_secure.buffered.return_value = [(Msg.CLOSE, {})]
            agreed = {"rows": 24, "cols": 80, "term": "xterm"}
            status = run_session(
                left,
                mock_secure,
                agreed,
                ping_every=0,
                dead_after=0,
                stdin_fd=r_in,
                stdout_fd=w_out,
            )
            assert status == 0
            # Ensure dummy_handler was restored
            assert signal.getsignal(signal.SIGWINCH) == dummy_handler
        finally:
            left.close()
            right.close()
    finally:
        os.close(r_in)
        os.close(w_in)
        os.close(r_out)
        os.close(w_out)
        signal.signal(signal.SIGWINCH, old_handler)

