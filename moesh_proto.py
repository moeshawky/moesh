#!/usr/bin/env python3
"""moesh v2 — shared protocol core (framing, Noise session, state machine).

This module is the single source of truth for the encrypted terminal protocol
used by the host-side agent (``moesh_tunnel.py``) and the operator-side
client (``moesh_shell.py``).  Neither endpoint re-declares a wire constant.

Wire format
-----------
Every byte on the wire belongs to exactly one length-prefixed frame::

    uint32_be(ciphertext_length) || ciphertext

The same framing carries the three Noise handshake messages and every
post-handshake transport record, because the two phases never interleave.
A transport record's plaintext is::

    uint8(message_type) || payload

``DATA`` payloads are raw terminal bytes and are never reinterpreted; every
other payload is a compact JSON object.

Cryptography
------------
``Noise_XX_25519_ChaChaPoly_BLAKE2s`` — initiator is the operator, responder
is the host agent — through the ``noiseprotocol`` package (import name
``noise``).  The receiver bridge does **not** terminate this session: it relays
ciphertext opaquely, so the broker never holds plaintext terminal data.

Static pinning
--------------
Noise XX transmits the peer's static key encrypted, and ``noiseprotocol``
overwrites any pre-set remote-static with the value learned from the handshake
(measured 2026-10-20 with ``noiseprotocol==0.3.1``: ``state.py:381`` assigns
``self.rs`` from the decrypted static).  ``set_remote_static_key`` therefore
cannot enforce pinning in XX.  Pinning is enforced here instead: the static key
learned from the handshake is compared against the expected pin *before the
first transport record is accepted*, and a mismatch aborts the session.

The fixed prologue binds the protocol identity, its major version and the
cipher suite to the handshake, so a peer speaking a different protocol cannot
complete a handshake (measured: a prologue mismatch fails closed with
``InvalidTag`` while reading the second handshake message).

Side effects: none.  This module only reads and writes the socket handed to it.
"""

from __future__ import annotations

import enum
import hashlib
import json
import struct
from typing import Any

from moesh_wire import (
    DEFAULT_HOST,
    DEFAULT_PATH,
    MAX_CONTROL_PAYLOAD,
    MAX_DATA_PAYLOAD,
    PRELUDE_PREFIX,
    PROTOCOL_VERSION,
    TUNNEL_PATH,
    UPGRADE_TOKEN,
)

__all__ = [
    "DEFAULT_HOST",
    "DEFAULT_PATH",
    "MAX_CONTROL_PAYLOAD",
    "MAX_DATA_PAYLOAD",
    "PRELUDE_PREFIX",
    "PROTOCOL_VERSION",
    "TUNNEL_PATH",
    "UPGRADE_TOKEN",
]

# Noise protocol identifier selecting the XX pattern with X25519, ChaChaPoly, and BLAKE2s for transport sessions.
NOISE_NAME = b"Noise_XX_25519_ChaChaPoly_BLAKE2s"
"""Noise pattern and cipher suite used for the transport."""

# Fixed application prologue binding the cryptographic handshake schema revision to PROTOCOL_VERSION; peers must agree on it.
PROLOGUE = f"moesh-tunnel-v2/{PROTOCOL_VERSION}/noise_xx_25519_chachapoly_blake2s".encode("ascii")
"""Fixed application prologue binding cryptographic handshake schema revision to PROTOCOL_VERSION."""

# Maximum ciphertext bytes in one framed message, matching Noise MAX_MESSAGE_LEN; larger frames are rejected.
MAX_CIPHERTEXT = 65535
"""Maximum ciphertext in one frame (Noise MAX_MESSAGE_LEN)."""

# Maximum accepted Noise handshake message size; handshake frames above this bound are rejected.
MAX_HANDSHAKE_FRAME = 4096
"""Maximum Noise handshake message (measured size is 32..112 bytes)."""

# Seconds either side waits for the other during the Noise handshake; it must exceed the bridge queue wait to avoid aborting late hosts.
HANDSHAKE_TIMEOUT = 150.0
"""Seconds a side waits for the other end of the handshake.

It must be longer than the receiver bridge's queue wait (120s, hard-coded in
``moesh-bridge.py``): the bridge keeps an operator connection open while it waits
for the host to attach, so a client that gives up sooner restarts that
wait on every attempt and reports a timeout for a host that is merely
late.  Measured on 2026-10-21: the operator's client abandoned the wait at
30s and reconnected every 30-90s while the host was down, and each
attempt was thrown away by the bridge's 120s timer.
"""
"""Seconds allowed for the three-message Noise handshake."""

# Seconds allowed for HELLO, ACCEPT, and READY messages after the Noise handshake.
NEGOTIATION_TIMEOUT = 30.0
"""Seconds allowed for HELLO/ACCEPT/READY."""

# Upper bound for terminal rows because TIOCSWINSZ uses unsigned shorts; values above this are invalid.
MAX_ROWS = 1000
"""Upper bound for terminal rows (TIOCSWINSZ uses unsigned shorts)."""

# Upper bound for terminal columns; values above this are invalid.
MAX_COLS = 1000
"""Upper bound for terminal columns."""

# Default terminal row count used when a peer does not specify dimensions.
DEFAULT_ROWS = 24
# Default terminal column count used when a peer does not specify dimensions.
DEFAULT_COLS = 80
# Default TERM value used for remote PTY sessions.
DEFAULT_TERM = "xterm-256color"
# Default text encoding used for terminal input and output.
DEFAULT_ENCODING = "utf-8"


class ProtocolError(Exception):
    """Base class for every protocol failure.  Always fatal for the session."""


class FramingError(ProtocolError):
    """A frame was malformed, empty or larger than the negotiated bound."""


class AuthenticationError(ProtocolError):
    """The peer failed authentication (wrong static key or broken handshake)."""


class NegotiationError(ProtocolError):
    """HELLO/ACCEPT carried values the peer must not accept."""


class StateError(ProtocolError):
    """An illegal state transition was attempted; the session fails closed."""


class TransportEOF(ProtocolError):
    """The transport ended without an authenticated CLOSE record."""


class Msg(enum.IntEnum):
    """Transport record types.  Values are part of the wire contract."""

    HELLO = 1
    ACCEPT = 2
    READY = 3
    DATA = 4
    RESIZE = 5
    EXIT = 6
    PING = 7
    PONG = 8
    ERROR = 9
    CLOSE = 10


class State(enum.Enum):
    """Session lifecycle.  Transitions are enforced, never assumed."""

    CONNECTED = "CONNECTED"
    AUTHENTICATED = "AUTHENTICATED"
    NEGOTIATING = "NEGOTIATING"
    READY = "READY"
    ACTIVE = "ACTIVE"
    CLOSING = "CLOSING"


_ALLOWED: dict[State, frozenset[State]] = {
    State.CONNECTED: frozenset({State.AUTHENTICATED, State.CLOSING}),
    State.AUTHENTICATED: frozenset({State.NEGOTIATING, State.CLOSING}),
    State.NEGOTIATING: frozenset({State.READY, State.CLOSING}),
    State.READY: frozenset({State.ACTIVE, State.CLOSING}),
    State.ACTIVE: frozenset({State.CLOSING}),
    State.CLOSING: frozenset(),
}


class SessionState:
    """Guarded state machine.

    Every transition is checked against :data:`_ALLOWED`; an unlisted
    transition raises :class:`StateError` so the caller fails closed instead of
    continuing in a state the peer did not agree to.
    """

    def __init__(self) -> None:
        """Initialize the session state to CONNECTED; later transitions are validated by to()."""
        self._state = State.CONNECTED

    @property
    def state(self) -> State:
        """The current state."""
        return self._state

    def to(self, target: State) -> None:
        """Move to ``target`` or raise :class:`StateError`."""
        if target not in _ALLOWED[self._state]:
            raise StateError(
                f"illegal transition {self._state.value} -> {target.value}"
            )
        self._state = target

    def require(self, *states: State) -> None:
        """Raise :class:`StateError` unless the current state is one of ``states``."""
        if self._state not in states:
            raise StateError(
                f"state {self._state.value} not in {[s.value for s in states]}"
            )


def frame(payload: bytes) -> bytes:
    """Return ``payload`` as a length-prefixed frame."""
    return struct.pack(">I", len(payload)) + payload


class FrameReader:
    """Reassembles length-prefixed frames from a byte stream.

    Handles partial frames (a frame split across reads) and multiple frames
    delivered by one read.  A frame larger than ``max_frame`` is rejected
    immediately rather than buffered.
    """

    def __init__(self, max_frame: int = MAX_CIPHERTEXT) -> None:
        """Create an empty reassembly buffer with max_frame as the largest accepted frame size."""
        self._buffer = bytearray()
        self._max_frame = max_frame

    def feed(self, data: bytes) -> None:
        """Append received bytes to the reassembly buffer."""
        self._buffer += data

    def pending(self) -> int:
        """Number of buffered bytes not yet consumed."""
        return len(self._buffer)

    def next_frame(self) -> bytes | None:
        """Return the next complete frame, or ``None`` if more bytes are needed."""
        if len(self._buffer) < 4:
            return None
        (length,) = struct.unpack(">I", self._buffer[:4])
        if length == 0:
            raise FramingError("zero-length frame")
        if length > self._max_frame:
            raise FramingError(
                f"frame of {length} bytes exceeds bound {self._max_frame}"
            )
        if len(self._buffer) < 4 + length:
            return None
        payload = bytes(self._buffer[4 : 4 + length])
        del self._buffer[: 4 + length]
        return payload

    def frames(self) -> list[bytes]:
        """Drain and return every complete frame currently buffered."""
        out: list[bytes] = []
        while True:
            item = self.next_frame()
            if item is None:
                return out
            out.append(item)


class Channel:
    """Length-prefixed frames over a blocking socket.

    The same object carries the Noise handshake messages and the transport
    records, so bytes that arrive together are never lost between phases.

    **The buffer is the source of truth.**  Bytes that came off the socket
    live here until they are consumed, so a frame can be complete while the
    socket has nothing left to report — a reader that watches only the
    socket never sees that frame.  Every waiter therefore asks the channel
    first (:meth:`next_frame`, :meth:`buffered_frames`) and the socket
    second.  Measured 2026-10-21: the agent watched only the socket, so a
    frame that arrived together with the HTTP 101 response was stranded in
    this buffer and the operator waited out its own handshake timeout.
    """

    def __init__(self, sock: Any, max_frame: int = MAX_CIPHERTEXT) -> None:
        """Wrap the given socket and create a FrameReader using max_frame for incoming frames."""
        self._sock = sock
        self._reader = FrameReader(max_frame)

    @property
    def socket(self) -> Any:
        """The underlying socket."""
        return self._sock

    def send_frame(self, payload: bytes) -> None:
        """Send one frame."""
        self._sock.sendall(frame(payload))

    def seed(self, data: bytes) -> None:
        """Feed bytes that arrived together with the HTTP response headers."""
        self._reader.feed(data)

    def fill(self) -> int:
        """Read one chunk from the socket into the reassembly buffer.

        Returns the number of bytes read.

        Raises:
            TransportEOF: the peer closed the transport.
        """
        data = self._sock.recv(65536)
        if not data:
            raise TransportEOF("transport closed by peer")
        self._reader.feed(data)
        return len(data)

    def next_frame(self) -> bytes | None:
        """Return the next complete frame, or ``None`` if more bytes are needed."""
        return self._reader.next_frame()

    def buffered_frames(self) -> list[bytes]:
        """Return every complete frame already in the buffer.

        This never reads the socket: it is the non-blocking half of
        :meth:`recv_frame`, for a waiter that must ask the buffer before it
        asks the socket.
        """
        return self._reader.frames()

    def recv_frame(self) -> bytes:
        """Return the next frame, blocking until it is complete.

        Raises:
            TransportEOF: the peer closed the transport.
        """
        while True:
            item = self._reader.next_frame()
            if item is not None:
                return item
            self.fill()


def _import_noise() -> Any:
    """Import the Noise library with an actionable error message."""
    try:
        from noise.connection import Keypair, NoiseConnection
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise ProtocolError(
            "the 'noiseprotocol' package is required: pip install noiseprotocol==0.3.1"
        ) from exc
    return Keypair, NoiseConnection


class NoiseSession:
    """A Noise_XX session with explicit static-key pinning.

    Args:
        role: ``"initiator"`` (operator) or ``"responder"`` (host agent).
        static_private: the local static private key, 32 raw bytes.
        peer_static: the expected peer static public key, 32 raw bytes.
        prologue: handshake prologue; ``None`` uses the fixed module constant.
            Tests pass a different value to prove a mismatched identity fails
            closed; production code never overrides it.

    Raises:
        ProtocolError: the Noise library is unavailable.
        AuthenticationError: the learned peer static key differs from the pin.
    """

    def __init__(
        self,
        role: str,
        static_private: bytes,
        peer_static: bytes | tuple[bytes, ...],
        prologue: bytes | None = None,
    ) -> None:
        """Validate role and key lengths, store static and peer static keys, and initialize Noise state; raises ProtocolError on invalid role or key sizes."""
        if role not in ("initiator", "responder"):
            raise ProtocolError(f"unknown Noise role {role!r}")
        if len(static_private) != 32:
            raise ProtocolError("static private key must be 32 bytes")
        if isinstance(peer_static, (tuple, list, set)):
            self._peer_static: tuple[bytes, ...] = tuple(bytes(k) for k in peer_static)
            if not self._peer_static or not all(len(k) == 32 for k in self._peer_static):
                raise ProtocolError("peer static public keys must be 32 bytes each")
        else:
            if len(peer_static) != 32:
                raise ProtocolError("peer static public key must be 32 bytes")
            self._peer_static = (bytes(peer_static),)
        keypair, connection = _import_noise()
        self._role = role
        self._conn = connection.from_name(NOISE_NAME)
        self._conn.set_prologue(PROLOGUE if prologue is None else prologue)
        if role == "initiator":
            self._conn.set_as_initiator()
        else:
            self._conn.set_as_responder()
        self._conn.set_keypair_from_private_bytes(keypair.STATIC, static_private)
        self._conn.start_handshake()
        # Keep our own reference: the library deletes handshake_state once the
        # handshake completes, and the learned peer static lives there.
        self._handshake_state = self._conn.noise_protocol.handshake_state
        self._pin_checked = False
        self._authenticated = False

    @property
    def role(self) -> str:
        """``"initiator"`` or ``"responder"``."""
        return self._role

    @property
    def handshake_finished(self) -> bool:
        """True once the Noise handshake completed on this side."""
        return bool(self._conn.handshake_finished)

    @property
    def authenticated(self) -> bool:
        """True once the peer static key matched the pin."""
        return self._authenticated

    def handshake_hash(self) -> bytes:
        """The 32-byte Noise handshake hash; both peers must agree on it."""
        return bytes(self._conn.get_handshake_hash())

    def write_handshake(self) -> bytes:
        """Produce the next handshake message to send."""
        try:
            return bytes(self._conn.write_message())
        except Exception as exc:
            raise ProtocolError(
                f"cannot write Noise handshake message: {exc!r}"
            ) from exc

    def read_handshake(self, message: bytes) -> None:
        """Consume one handshake message and enforce the static-key pin.

        Raises:
            FramingError: the message is larger than a handshake message may be.
            AuthenticationError: the peer static key does not match the pin.
            ProtocolError: the handshake message was rejected by the library.
        """
        if len(message) > MAX_HANDSHAKE_FRAME:
            raise FramingError(
                f"handshake message of {len(message)} bytes is too large"
            )
        try:
            self._conn.read_message(message)
        except Exception as exc:
            raise ProtocolError(f"Noise handshake message rejected: {exc!r}") from exc
        self._check_pin()

    def _check_pin(self) -> None:
        """Compare the peer static learned from the handshake with the pin."""
        if self._pin_checked:
            return
        from noise.constants import Empty

        learned = getattr(self._handshake_state, "rs", None)
        if learned is None or isinstance(learned, Empty):
            if self.handshake_finished:
                raise AuthenticationError(
                    "Noise handshake finished without learning remote static key"
                )
            return
        learned_bytes = bytes(learned.public_bytes)
        if learned_bytes not in self._peer_static:
            expected = ", ".join(hashlib.sha256(p).hexdigest()[:16] for p in self._peer_static)
            raise AuthenticationError(
                f"peer static key mismatch: pinned [{expected}], learned {hashlib.sha256(learned_bytes).hexdigest()[:16]}"
            )
        self._pin_checked = True
        self._authenticated = True

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt one transport message."""
        if not self._authenticated:
            raise AuthenticationError("cannot encrypt on unauthenticated session")
        try:
            return bytes(self._conn.encrypt(plaintext))
        except Exception as exc:
            raise ProtocolError(f"transport encryption failed: {exc!r}") from exc

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt one transport message.

        Raises:
            AuthenticationError: the ciphertext was modified or is out of session.
        """
        if not self._authenticated:
            raise AuthenticationError("cannot decrypt on unauthenticated session")
        try:
            return bytes(self._conn.decrypt(ciphertext))
        except Exception as exc:
            raise AuthenticationError(
                f"transport record failed authentication: {exc!r}"
            ) from exc


class SecureChannel:
    """Encrypted records over a :class:`Channel`.

    Args:
        channel: the framed byte channel carrying the session.
        session: the Noise session protecting the records.
    """

    def __init__(self, channel: Channel, session: NoiseSession) -> None:
        """Wrap a Channel and NoiseSession without performing I/O; encryption and framing happen in later send and receive calls."""
        self._channel = channel
        self._session = session

    @property
    def session(self) -> NoiseSession:
        """The Noise session behind this channel."""
        return self._session

    def send(self, msg_type: int, payload: bytes = b"") -> None:
        """Send one record of ``msg_type`` with a raw payload.

        DATA records are capped at ``MAX_DATA_PAYLOAD``; every control record
        is capped at ``MAX_CONTROL_PAYLOAD`` so the control bound is enforced
        on the session send path, not only in ``send_control`` (measured:
        ``send(Msg.PING, 4108-byte payload)`` was accepted while
        ``send_control`` rejected it, a parser downgrade on the same message
        type).
        """
        limit = MAX_DATA_PAYLOAD if msg_type == Msg.DATA else MAX_CONTROL_PAYLOAD
        if len(payload) > limit:
            raise FramingError(
                f"payload of {len(payload)} bytes exceeds {limit}"
            )
        plaintext = bytes([int(msg_type)]) + payload
        self._channel.send_frame(self._session.encrypt(plaintext))

    def send_control(self, msg_type: int, obj: dict[str, Any]) -> None:
        """Send one control record whose payload is a compact JSON object."""
        raw = json.dumps(obj, separators=(",", ":")).encode()
        if len(raw) > MAX_CONTROL_PAYLOAD:
            raise FramingError(
                f"control payload of {len(raw)} bytes exceeds {MAX_CONTROL_PAYLOAD}"
            )
        self.send(msg_type, raw)

    def recv(self) -> tuple[int, bytes]:
        """Return the next ``(message_type, payload)``.

        Raises:
            AuthenticationError: the record failed authentication.
            FramingError: the record was malformed or oversized.
            TransportEOF: the peer closed the transport.
        """
        frame_bytes = self._channel.recv_frame()
        plaintext = self._session.decrypt(frame_bytes)
        if not plaintext:
            raise FramingError("empty transport record")
        msg_type = plaintext[0]
        payload = plaintext[1:]
        limit = MAX_DATA_PAYLOAD if msg_type == Msg.DATA else MAX_CONTROL_PAYLOAD
        if len(payload) > limit:
            raise FramingError(
                f"inbound payload of {len(payload)} bytes exceeds {limit}"
            )
        return msg_type, payload

    def recv_control(self) -> tuple[int, dict[str, Any]]:
        """Return the next ``(message_type, json_object)`` control record.

        Raises:
            FramingError: the payload is not a JSON object or exceeds bounds.
        """
        msg_type, payload = self.recv()
        if len(payload) > MAX_CONTROL_PAYLOAD:
            raise FramingError(
                f"inbound control payload of {len(payload)} bytes exceeds {MAX_CONTROL_PAYLOAD}"
            )
        try:
            obj = json.loads(payload.decode())
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FramingError(f"control record is not valid JSON: {exc!r}") from exc
        if not isinstance(obj, dict):
            raise FramingError("control record is not a JSON object")
        return msg_type, obj

    def buffered(self) -> list[tuple[int, bytes]]:
        """Return every record already in the transport's buffer.

        This never reads the socket.  A record that arrived together with
        another one is already here, and the socket has nothing left to
        report, so a waiter that only reads the socket would strand it.
        """
        out: list[tuple[int, bytes]] = []
        for frame_bytes in self._channel.buffered_frames():
            plaintext = self._session.decrypt(frame_bytes)
            if not plaintext:
                raise FramingError("empty transport record")
            msg_type = plaintext[0]
            payload = plaintext[1:]
            limit = MAX_DATA_PAYLOAD if msg_type == Msg.DATA else MAX_CONTROL_PAYLOAD
            if len(payload) > limit:
                raise FramingError(
                    f"inbound payload of {len(payload)} bytes exceeds {limit}"
                )
            out.append((msg_type, payload))
        return out

    def drain(self) -> list[tuple[int, bytes]]:
        """Read one chunk and return every record it completed.

        Returns an empty list when the chunk did not complete a record; the
        caller loops again, so a partial frame never blocks the other
        direction of the session.
        """
        self._channel.fill()
        return self.buffered()


def validate_hello(
    hello: dict[str, Any], max_record: int = MAX_DATA_PAYLOAD
) -> dict[str, Any]:
    """Validate a HELLO payload and return the accepted configuration.

    The accepted configuration is what the agent will apply to the PTY; the
    operator's values are authoritative for rows/columns.

    Raises:
        NegotiationError: a mandatory value is missing, malformed or out of bounds.
    """
    version = hello.get("version")
    if version != PROTOCOL_VERSION:
        raise NegotiationError(f"unsupported protocol version {version!r}")
    term = hello.get("term")
    if not isinstance(term, str) or not term or len(term) > 32:
        raise NegotiationError(f"invalid terminal type {term!r}")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in term):
        raise NegotiationError("terminal type contains control characters")
    encoding = hello.get("encoding")
    if encoding != DEFAULT_ENCODING:
        raise NegotiationError(f"unsupported character encoding {encoding!r}")
    rows = hello.get("rows")
    cols = hello.get("cols")
    for name, value in (("rows", rows), ("cols", cols)):
        if not isinstance(value, int) or isinstance(value, bool):
            raise NegotiationError(f"{name} must be an integer, got {value!r}")
        if name == "rows":
            if not 1 <= value <= MAX_ROWS:
                raise NegotiationError(f"{name}={value} is out of bounds")
        else:
            if not 1 <= value <= MAX_COLS:
                raise NegotiationError(f"{name}={value} is out of bounds")
    peer_max = hello.get("max_record")
    if not isinstance(peer_max, int) or isinstance(peer_max, bool) or peer_max < 256:
        raise NegotiationError(f"invalid max_record {peer_max!r}")
    capabilities = hello.get("capabilities", [])
    if not isinstance(capabilities, list) or any(
        not isinstance(c, str) for c in capabilities
    ):
        raise NegotiationError("capabilities must be a list of strings")
    fresh = hello.get("fresh_session", False)
    if not isinstance(fresh, bool):
        raise NegotiationError(f"fresh_session must be a boolean, got {fresh!r}")
    session_type = hello.get("session_type", "shell")
    if not isinstance(session_type, str) or session_type not in ("shell", "transfer"):
        raise NegotiationError(f"invalid session_type {session_type!r}")
    return {
        "version": PROTOCOL_VERSION,
        "term": term,
        "encoding": encoding,
        "rows": rows,
        "cols": cols,
        "capabilities": sorted(set(capabilities)),
        "max_record": min(peer_max, max_record),
        "fresh_session": fresh,
        "session_type": session_type,
    }


def validate_resize(resize: dict[str, Any]) -> tuple[int, int]:
    """Validate a RESIZE payload and return ``(rows, cols)``.

    Raises:
        NegotiationError: the dimensions are missing, malformed or out of bounds.
    """
    rows = resize.get("rows")
    cols = resize.get("cols")
    if not isinstance(rows, int) or isinstance(rows, bool):
        raise NegotiationError(f"rows must be an integer, got {rows!r}")
    if not isinstance(cols, int) or isinstance(cols, bool):
        raise NegotiationError(f"cols must be an integer, got {cols!r}")
    if not 1 <= rows <= MAX_ROWS:
        raise NegotiationError(f"rows={rows} is out of bounds")
    if not 1 <= cols <= MAX_COLS:
        raise NegotiationError(f"cols={cols} is out of bounds")
    return rows, cols


# Prefix for host names; a number is expanded to prefix-number so one number names the same host on both ends.
DEFAULT_PREFIX = "host"
"""Prefix for host names: a number is expanded to ``<prefix>-<number>``, so one
number names the same host on both ends (the way SSH host entries used to
pick the endpoint)."""


def host_name(number: str, prefix: str = DEFAULT_PREFIX) -> str:
    """Return the routing name of a host.

    A number is expanded to ``<prefix>-<number>`` so both ends can speak in
    the same single number: the host sets ``MOESH_TUNNEL_HOST = 3`` and the
    operator asks for ``-n 3``.

    The result is validated the same way on both ends: it must be ASCII
    (the prelude is encoded latin-1 while the agent path is UTF-8, so only
    ASCII agrees across encodings), at most 64 characters, and drawn from the
    label charset (letters, digits, dot, dash, underscore).  The agent applies
    the identical check, so the name the operator sends is the name the agent
    queues and pins.

    Raises:
        ProtocolError: the number contains characters that are not allowed in
            a routing label, or the expanded name is not a valid label.
    """
    number = number.strip()
    if not number:
        name = "default"
    else:
        if not all(ch.isalnum() or ch in "._-" for ch in number):
            raise ProtocolError(f"invalid host number {number!r}")
        name = f"{prefix}-{number}"
    if (
        not name
        or len(name) > 64
        or not name.isascii()
        or not all(ch.isalnum() or ch in "._-" for ch in name)
    ):
        raise ProtocolError(f"invalid host name {name!r}")
    return name


def derive_static_key(master: bytes, name: str) -> bytes:
    """Derive a host's static private key from a master secret and its name.

    The master secret never leaves the host (and the operator's own
    machine); the identity NUMBER is the only thing that changes when the
    operator switches hosts — the same "one number" the SSH host
    entries gave.

    The derivation is HKDF-SHA256 with a fixed, application-specific info
    string, so the same (master, name) always yields the same key and no two
    hosts share one.

    Args:
        master: the host's master secret.
        name: the host's routing name.

    Returns:
        The 32-byte X25519 private key.

    Raises:
        ProtocolError: the master secret is missing or the derivation failed.
    """
    if not isinstance(master, (bytes, bytearray)):
        raise ProtocolError("master secret must be bytes")
    if not master:
        raise ProtocolError("no master secret to derive from")
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise ProtocolError("the 'cryptography' package is required") from exc
    info = b"moesh-tunnel-v2/agent-static-key/v1/" + name.encode("utf-8")
    try:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(
            master
        )
    except Exception as exc:  # derivation failures are protocol errors, not TypeError
        raise ProtocolError(f"key derivation failed: {exc}") from exc


def public_key_of(private: bytes) -> str:
    """Return the static public key of a private key, as hex.

    The public key is not a secret: printing it lets the operator pin this
    host without guessing.
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import x25519
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise ProtocolError("the 'cryptography' package is required") from exc
    if len(private) != 32:
        raise ProtocolError("private key must be 32 bytes")
    key = x25519.X25519PrivateKey.from_private_bytes(private)
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )


def public_key_bytes(private: bytes) -> bytes:
    """Return the 32-byte static public key of a private key."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import x25519
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise ProtocolError("the 'cryptography' package is required") from exc
    if len(private) != 32:
        raise ProtocolError("private key must be 32 bytes")
    key = x25519.X25519PrivateKey.from_private_bytes(private)
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def generate_static_keypair() -> tuple[bytes, bytes]:
    """Generate a Noise static key pair with the ``cryptography`` library.

    Returns:
        ``(private_bytes, public_bytes)``, 32 raw bytes each, X25519.

    Raises:
        ProtocolError: the ``cryptography`` package is unavailable.
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import x25519
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise ProtocolError(
            "the 'cryptography' package is required: pip install cryptography"
        ) from exc
    private = x25519.X25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_bytes = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private_bytes, public_bytes
