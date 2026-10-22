#!/usr/bin/env python3
"""moesh v2 — operator-side client (Noise initiator).

The client attaches to the receiver bridge's v2 operator port and speaks the
encrypted terminal protocol to the host agent.  It owns the **local**
terminal: it measures the real window size, advertises it in HELLO, keeps the
local line discipline in raw mode so control characters reach the remote PTY
untouched, forwards SIGWINCH as authenticated RESIZE records, and restores the
original terminal settings on every exit path.

Signal semantics (measured behaviour of the destination PTY)
------------------------------------------------------------
The local terminal is put in raw mode *without* ISIG, so Ctrl+C, Ctrl+Z and
Ctrl+D are transmitted as the bytes 0x03, 0x1a and 0x04.  The remote PTY keeps
its canonical line discipline with ISIG enabled, so the destination generates
SIGINT, SIGTSTP and EOF itself.  No separate remote signal protocol is
invented.

Configuration (environment)
---------------------------
``MOESH_SHELL_V2_ADDR``       bridge operator endpoint (default ``127.0.0.1:44441``)
``MOESH_SHELL_V2_KEYFILE``    operator static private key (default ``~/.config/moesh/operator.key``)
``MOESH_SHELL_V2_PEER_PUBFILE`` pinned agent static public key (default ``~/.config/moesh/agent.pub``)
``MOESH_SHELL_V2_HOSTS_FILE`` pins file, one entry per host (default ``~/.config/moesh/hosts.toml``)

Side effects: reads the local terminal, puts it in raw mode while the session
runs and restores it afterwards; writes the session's bytes to stdout.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import json
import os
import select
import signal
import socket
import struct
import sys
import termios
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from types import TracebackType

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import contextlib

import moesh_proto_v2 as proto
from moesh_proto_v2 import (
    AuthenticationError,
    Msg,
    NegotiationError,
    ProtocolError,
    State,
    TransportEOF,
)

DEFAULT_ADDR = "127.0.0.1:44441"
# All of the operator's state lives in one config directory: the key material
# and the pins file.  Override any piece with its environment variable.
HOSTS_FILE = os.environ.get(
    "MOESH_SHELL_V2_HOSTS_FILE",
    os.path.expanduser("~/.config/moesh/hosts.toml"),
)
DEFAULT_KEYFILE = os.path.expanduser("~/.config/moesh/operator.key")
DEFAULT_PEER_PUBFILE = os.path.expanduser("~/.config/moesh/agent.pub")

CAPABILITIES = ("resize", "ping")


def log(message: str) -> None:
    """Write one flushed log line to stderr (stdout carries the terminal)."""
    print(
        "[shell-v2 {}] {}".format(time.strftime("%H:%M:%S"), message),
        file=sys.stderr,
        flush=True,
    )


def load_config() -> dict[str, Any]:
    """Read the operator's host configuration.

    The file holds the prefix used to expand a number into a name, and one
    entry per host with its pinned public key (or the master secret the
    key is derived from).
    """
    try:
        import tomllib

        with open(HOSTS_FILE, "rb") as handle:
            config: dict[str, Any] = tomllib.load(handle)
            return config
    except FileNotFoundError:
        return {}
    except Exception as exc:
        raise ProtocolError(f"cannot read {HOSTS_FILE}: {exc}") from exc


def resolve_name(requested: str) -> str:
    """Turn what the operator typed into a host name.

    A number is expanded with the configured prefix, so ``-n 3`` means the
    same host as the agent's ``MOESH_TUNNEL_V2_HOST = 3`` — one number on
    both sides, the way the SSH host entries worked.
    """
    requested = requested.strip()
    if not requested:
        return "default"
    if requested.isdigit():
        config = load_config()
        prefix = str(config.get("prefix") or proto.DEFAULT_PREFIX)
        return proto.host_name(requested, prefix)
    return requested


def new_master(host: str) -> int:
    """Print a fresh master secret and the public key it derives for ``host``.

    The master secret is provisioned to the host (through its secret store
    or a key file); the public key goes into the operator's pins file, where
    it pins that host.
    """
    master = os.urandom(32)
    private = proto.derive_static_key(master, host)
    public = proto.public_key_of(private)
    print(f"host:          {host}")
    print(f"master secret: {master.hex()}")
    print("  -> provision this to the host as MOESH_TUNNEL_V2_MASTER")
    print(f"agent public:  {public}")
    print(f"  -> put this in {HOSTS_FILE} as [hosts.{host}] agent_pub")
    return 0


def generate_key(keyfile: str, force: bool = False) -> int:
    """Generate a fresh operator static key pair, ssh-keygen style.

    Writes the private key as hex to ``keyfile`` (mode 0600) and the public
    half as hex to ``keyfile + ".pub"`` (mode 0644).  Only the public half
    and an ssh-keygen-style fingerprint are printed; the private key never
    reaches stdout.  An existing keyfile (or its ``.pub``) is refused unless
    ``force`` is set, so a stray invocation cannot clobber a live key.
    """
    private, public = proto.generate_static_keypair()
    path = os.path.expanduser(keyfile)
    pub_path = path + ".pub"
    if not force and (os.path.exists(path) or os.path.exists(pub_path)):
        print(
            f"refusing to overwrite existing key: {path} (use --force to replace)",
            file=sys.stderr,
        )
        return 1
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(private.hex() + "\n")
    os.chmod(path, 0o600)
    with open(pub_path, "w", encoding="ascii") as handle:
        handle.write(public.hex() + "\n")
    os.chmod(pub_path, 0o644)
    digest = hashlib.sha256(bytes.fromhex(public.hex())).digest()
    fingerprint = base64.b64encode(digest).decode("ascii").rstrip("=")
    print(public.hex())
    print(f"SHA256:{fingerprint}")
    return 0


def pinned_key(host: str) -> bytes:
    """Return the pinned public key of one host.

    The pins live in ``~/.config/moesh/hosts.toml``::

        prefix = "host"
        master = "<64 hex>"  # optional: one master for every host

        [hosts.host - 3]
        agent_pub = "<64 hex>"  # a pinned key
        # or
        master = "<64 hex>"  # derive the key from this master

    A host with no entry of its own falls back to the shared master, so
    switching numbers needs no configuration change.  A host with neither
    is refused: the client never trusts a key it has not been given.

    Raises:
        ProtocolError: no pin is configured for this host.
    """
    config = load_config()
    pins = config.get("hosts", {})
    entry = pins.get(host) if isinstance(pins, dict) else None
    if not isinstance(entry, dict):
        entry = {}
    if entry.get("agent_pub"):
        raw = str(entry["agent_pub"]).strip().removeprefix("0x")
        try:
            key = bytes.fromhex(raw)
        except ValueError as exc:
            raise ProtocolError(
                f"the pinned key for host {host!r} is not valid hex"
            ) from exc
        if len(key) != 32:
            raise ProtocolError(f"the pinned key for host {host!r} must be 32 bytes")
        return key
    master_hex = entry.get("master") or config.get("master")
    if master_hex:
        raw = str(master_hex).strip().removeprefix("0x")
        try:
            master = bytes.fromhex(raw)
        except ValueError as exc:
            raise ProtocolError(
                f"the master secret for host {host!r} is not valid hex"
            ) from exc
        return proto.public_key_bytes(proto.derive_static_key(master, host))
    raise ProtocolError(
        "no pin for host {!r} in {} (known: {})".format(
            host,
            HOSTS_FILE,
            ", ".join(sorted(pins)) if isinstance(pins, dict) else "none",
        )
    )


def read_key(path: str, what: str) -> bytes:
    """Read a 32-byte hex key from ``path``.

    Raises:
        ProtocolError: the file is missing or malformed.
    """
    try:
        with open(path, encoding="ascii") as handle:
            raw = handle.read().strip()
    except OSError as exc:
        raise ProtocolError(f"cannot read {what} at {path}: {exc}") from exc
    raw = raw.removeprefix("0x").replace(":", "").strip()
    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise ProtocolError(f"{what} at {path} is not valid hex") from exc
    if len(key) != 32:
        raise ProtocolError(f"{what} must be 32 bytes, got {len(key)}")
    return key


def terminal_size(fd: int) -> tuple[int, int]:
    """Return ``(rows, cols)`` of the terminal behind ``fd``.

    Raises:
        ProtocolError: the size cannot be read.
    """
    try:
        packed = fcntl.ioctl(fd, termios.TIOCGWINSZ, b"\0" * 8)
    except OSError as exc:
        raise ProtocolError(f"cannot read the terminal size: {exc}") from exc
    rows, cols, _, _ = struct.unpack("HHHH", packed)
    return rows, cols


class RawTerminal:
    """Put the local terminal in raw mode and restore it afterwards.

    The saved attributes are restored by :meth:`restore`, which is called from
    every exit path (normal end, exception, SIGINT/SIGTERM/SIGHUP).
    """

    def __init__(self, fd: int) -> None:
        self._fd = fd
        self._saved: list[Any] | None = None

    def __enter__(self) -> RawTerminal:
        """Enter raw mode."""
        if not os.isatty(self._fd):
            return self
        self._saved = termios.tcgetattr(self._fd)
        mode = termios.tcgetattr(self._fd)
        # Raw mode without ISIG: control characters travel to the remote PTY,
        # which owns the signal semantics.
        mode[0] &= ~(
            termios.IGNBRK
            | termios.BRKINT
            | termios.PARMRK
            | termios.ISTRIP
            | termios.INLCR
            | termios.IGNCR
            | termios.ICRNL
            | termios.IXON
        )
        mode[1] &= ~termios.OPOST
        mode[2] &= ~(termios.CSIZE | termios.PARENB)
        mode[2] |= termios.CS8
        mode[3] &= ~(
            termios.ECHO
            | termios.ECHONL
            | termios.ICANON
            | termios.ISIG
            | termios.IEXTEN
        )
        mode[6][termios.VMIN] = 1
        mode[6][termios.VTIME] = 0
        termios.tcsetattr(self._fd, termios.TCSADRAIN, mode)
        return self

    def restore(self) -> None:
        """Restore the saved terminal attributes (idempotent)."""
        if self._saved is not None:
            with contextlib.suppress(OSError, termios.error):
                termios.tcsetattr(self._fd, termios.TCSADRAIN, self._saved)
            self._saved = None

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Restore the terminal on every exit path."""
        self.restore()


def handshake(session: proto.NoiseSession, channel: proto.Channel) -> None:
    """Run the Noise handshake as the initiator.

    Raises:
        ProtocolError: the handshake failed.
        AuthenticationError: the agent's static key did not match the pin.
    """
    channel.send_frame(session.write_handshake())
    session.read_handshake(channel.recv_frame())
    channel.send_frame(session.write_handshake())
    if not session.handshake_finished:
        raise ProtocolError("Noise handshake did not complete")
    if not session.authenticated:
        raise AuthenticationError("Agent static key could not be authenticated")
    log("authenticated (agent static key matched the pin)")


def negotiate(
    secure: proto.SecureChannel,
    machine: proto.SessionState,
    term: str,
    fresh: bool = False,
) -> dict[str, Any]:
    """Send HELLO, exchange ACCEPT/READY and return the accepted configuration.

    Raises:
        NegotiationError: the agent's ACCEPT was not acceptable.
    """
    rows, cols = terminal_size(sys.stdin.fileno())
    machine.to(State.NEGOTIATING)
    secure.send_control(
        Msg.HELLO,
        {
            "version": proto.PROTOCOL_VERSION,
            "term": term,
            "encoding": proto.DEFAULT_ENCODING,
            "rows": rows,
            "cols": cols,
            "capabilities": list(CAPABILITIES),
            "max_record": proto.MAX_DATA_PAYLOAD,
            "handshake_hash": secure.session.handshake_hash().hex(),
            "fresh_session": fresh,
        },
    )
    msg_type, accept = secure.recv_control()
    if msg_type != Msg.ACCEPT:
        raise NegotiationError(f"expected ACCEPT, got message type {msg_type}")
    agreed = proto.validate_hello(accept)
    if accept.get("resumed"):
        log("re-attached to the running shell: the previous session continues")
    else:
        log("a new shell was started")
    secure.send_control(Msg.READY, {})
    msg_type, _payload = secure.recv_control()
    if msg_type != Msg.READY:
        raise NegotiationError(f"expected READY, got message type {msg_type}")
    machine.to(State.READY)
    machine.to(State.ACTIVE)
    return agreed


def send_resize(secure: proto.SecureChannel, rows: int, cols: int) -> None:
    """Send an authenticated RESIZE record."""
    secure.send(Msg.RESIZE, struct.pack(">HH", rows, cols))


class SessionTimeout(ProtocolError):
    """No traffic from the peer for longer than the liveness deadline."""


_ESCAPE_NORMAL = 0
_ESCAPE_AFTER_NEWLINE = 1
_ESCAPE_AFTER_TILDE = 2

BRACKETED_PASTE_START = b"\x1b[200~"
BRACKETED_PASTE_END = b"\x1b[201~"


class EscapeFilter:
    """Filter stdin bytes for local escape sequences (~.).

    OpenSSH-compatible escape handling:
    - At start of session or immediately after a newline (CR or LF), '~' starts an escape sequence.
    - If followed by '.', triggers a local detach (returns True).
    - If followed by '~', emits a single literal '~' and returns to normal state.
    - If followed by any other character, emits the held '~' and that character.
    - Multi-byte bursts (>3 bytes) and bracketed paste blocks bypass escape detection to prevent
      accidental detachment during paste operations.
    """

    def __init__(self) -> None:
        self.state: int = _ESCAPE_AFTER_NEWLINE
        self.in_bracketed_paste: bool = False

    def feed(self, data: bytes) -> tuple[bytes, bool]:
        """Process incoming stdin bytes.

        Returns:
            A tuple of (bytes_to_send, detached). If detached is True, the session
            should end immediately without closing the remote shell.
        """
        if not data:
            return b"", False

        # Bracketed paste state tracking
        if BRACKETED_PASTE_START in data:
            self.in_bracketed_paste = True

        to_send = bytearray()

        # Burst / Paste immunity (GAP-01):
        # If bracketed paste is active or data arrives in a multi-byte burst (>3 bytes),
        # do not interpret local escape sequences.
        if self.in_bracketed_paste or len(data) > 3:
            if BRACKETED_PASTE_END in data:
                self.in_bracketed_paste = False
            if self.state == _ESCAPE_AFTER_TILDE:
                to_send.append(126)
            to_send.extend(data)
            if data.endswith(b"\r") or data.endswith(b"\n"):
                self.state = _ESCAPE_AFTER_NEWLINE
            else:
                self.state = _ESCAPE_NORMAL
            return bytes(to_send), False

        # Interactive keystrokes (<= 3 bytes)
        for b in data:
            if self.state == _ESCAPE_NORMAL:
                if b in (13, 10):
                    self.state = _ESCAPE_AFTER_NEWLINE
                to_send.append(b)
            elif self.state == _ESCAPE_AFTER_NEWLINE:
                if b == 126:  # ord('~')
                    self.state = _ESCAPE_AFTER_TILDE
                elif b in (13, 10):
                    self.state = _ESCAPE_AFTER_NEWLINE
                    to_send.append(b)
                else:
                    self.state = _ESCAPE_NORMAL
                    to_send.append(b)
            elif self.state == _ESCAPE_AFTER_TILDE:
                if b == 46:  # ord('.') - Local detach (GAP-04)
                    self.state = _ESCAPE_NORMAL
                    # Stop processing immediately; return what was buffered before detach
                    return bytes(to_send), True
                if b == 126:  # ord('~') - Literal escape (GAP-03)
                    to_send.append(126)
                    self.state = _ESCAPE_NORMAL
                elif b in (13, 10):
                    to_send.append(126)
                    to_send.append(b)
                    self.state = _ESCAPE_AFTER_NEWLINE
                else:
                    to_send.append(126)
                    to_send.append(b)
                    self.state = _ESCAPE_NORMAL

        return bytes(to_send), False

    def flush(self) -> bytes:
        """Return any held escape prefix when the stream ends."""
        if self.state == _ESCAPE_AFTER_TILDE:
            self.state = _ESCAPE_NORMAL
            return b"~"
        return b""


def run_session(
    sock: socket.socket,
    secure: proto.SecureChannel,
    agreed: dict[str, Any],
    ping_every: float = 15.0,
    dead_after: float = 45.0,
    stdin_fd: int | None = None,
    stdout_fd: int | None = None,
) -> int:
    """Relay the local terminal with the remote shell until one side ends.

    The session carries an application-level liveness check: a PING goes out
    every ``ping_every`` seconds, and if nothing at all comes back within
    ``dead_after`` the connection is treated as dead.  A path that silently
    swallows traffic (a middlebox, a half-open TCP) would otherwise hang the
    terminal forever with no way back.

    Returns the exit status of the remote shell.

    Raises:
        TransportEOF: the transport ended without an authenticated CLOSE.
        SessionTimeout: the peer stopped answering.
    """
    log(f"session active: {agreed['rows']}x{agreed['cols']} term={agreed['term']}")
    if stdin_fd is None:
        try:
            stdin_fd = sys.stdin.fileno()
        except (AttributeError, OSError, ValueError):
            stdin_fd = 0
    if stdout_fd is None:
        try:
            stdout_fd = sys.stdout.fileno()
        except (AttributeError, OSError, ValueError):
            stdout_fd = 1
    resized = False
    last_rx = time.time()
    last_ping = time.time()
    shell_exited = False

    def on_winch(_signum: int, _frame: Any) -> None:
        nonlocal resized
        resized = True

    old_winch: Any = None
    try:
        old_winch = signal.getsignal(signal.SIGWINCH)
        signal.signal(signal.SIGWINCH, on_winch)
    except (AttributeError, ValueError, OSError):
        old_winch = None

    try:
        status = 0
        escape_filter = EscapeFilter()
        while True:
            ready, _, _ = select.select([sock, stdin_fd], [], [], 0.5)
            if resized:
                resized = False
                try:
                    rows, cols = terminal_size(stdin_fd)
                    send_resize(secure, rows, cols)
                    log(f"sent resize {rows}x{cols}")
                except (ProtocolError, OSError):
                    pass
            # The transport's buffer is drained every pass, not only when the
            # socket says it is readable: a record that arrived together with
            # another one is already there, and the socket has nothing left to
            # report.  Ask the transport first, the socket second.
            records = secure.buffered()
            if sock in ready:
                try:
                    records += secure.drain()
                except TransportEOF:
                    if shell_exited:
                        # The remote shell ended on purpose: that is a normal end
                        # of session, not a lost connection.
                        return status
                    # An unexpected drop.  The host keeps the shell running, so
                    # the caller re-attaches to the same shell.
                    log("the connection dropped; the remote shell keeps running")
                    raise
            if records:
                last_rx = time.time()
            for msg_type, payload in records:
                if msg_type == Msg.DATA:
                    os.write(stdout_fd, payload)
                elif msg_type == Msg.RESIZE:
                    log(
                        "remote requested a resize (ignored: the operator is authoritative)"
                    )
                elif msg_type == Msg.PING:
                    secure.send(Msg.PONG, payload)
                    last_rx = time.time()
                elif msg_type == Msg.PONG:
                    pass
                elif msg_type == Msg.EXIT:
                    shell_exited = True
                    # The payload is the JSON bytes produced by send_control on
                    # the agent side ({"status": int, "signal": ...}); testing
                    # it as a dict made every exit look like 0 (measured
                    # 2026-10-22: `exit 7` -> client 0).  Decode the JSON here.
                    status = 0
                    try:
                        decoded = json.loads(payload)
                        if not isinstance(decoded, dict):
                            raise ValueError("EXIT payload is not a JSON object")
                        status = int(decoded.get("status", 0))
                    except (json.JSONDecodeError, TypeError, ValueError):
                        log("remote shell exited; could not decode EXIT payload")
                        status = 0
                    log(f"remote shell exited (status {status})")
                elif msg_type == Msg.CLOSE:
                    log("agent closed the session (authenticated close)")
                    return status
                elif msg_type == Msg.ERROR:
                    log(f"agent reported an error: {payload[:200]!r}")
                    return status or 1
                else:
                    raise ProtocolError(f"unexpected message type {msg_type} from agent")

            now = time.time()
            if ping_every > 0 and now - last_ping >= ping_every:
                last_ping = now
                try:
                    secure.send_control(Msg.PING, {"t": int(now)})
                except (OSError, ProtocolError) as exc:
                    raise SessionTimeout("the peer stopped answering") from exc
            if dead_after > 0 and now - last_rx > dead_after:
                raise SessionTimeout(f"no traffic from the host for {int(dead_after)}s")
            if stdin_fd in ready:
                data = os.read(stdin_fd, 65536)
                if not data:
                    pending = escape_filter.flush()
                    if pending:
                        for index in range(0, len(pending), proto.MAX_DATA_PAYLOAD):
                            secure.send(
                                Msg.DATA,
                                bytes(pending[index : index + proto.MAX_DATA_PAYLOAD]),
                            )
                    log(
                        "detached: the remote shell keeps running; run moesh-shell-v2 again to re-attach"
                    )
                    with contextlib.suppress(Exception):
                        secure.send_control(Msg.CLOSE, {"reason": "detach"})
                    return status
                to_send, detached = escape_filter.feed(data)
                if to_send:
                    for index in range(0, len(to_send), proto.MAX_DATA_PAYLOAD):
                        secure.send(
                            Msg.DATA,
                            bytes(to_send[index : index + proto.MAX_DATA_PAYLOAD]),
                        )
                if detached:
                    sys.stderr.write("\n[moesh: detached]\n")
                    sys.stderr.flush()
                    with contextlib.suppress(Exception):
                        secure.send_control(Msg.CLOSE, {"reason": "detach"})
                    return 0
        return status
    finally:
        if old_winch is not None:
            with contextlib.suppress(Exception):
                signal.signal(signal.SIGWINCH, old_winch)


def main(argv: list[str] | None = None) -> int:
    """Attach to the remote shell and relay the local terminal.

    A lost connection is not the end of the session: the host keeps the
    shell running, so the client re-attaches to the same shell on its own
    (with a growing pause between attempts).  ``--no-reconnect`` turns that
    off.
    """
    parser = argparse.ArgumentParser(description="moesh v2 operator client")
    parser.add_argument(
        "--addr", default=os.environ.get("MOESH_SHELL_V2_ADDR", DEFAULT_ADDR)
    )
    parser.add_argument(
        "--keyfile", default=os.environ.get("MOESH_SHELL_V2_KEYFILE", DEFAULT_KEYFILE)
    )
    parser.add_argument(
        "--peer-pubfile",
        default=os.environ.get("MOESH_SHELL_V2_PEER_PUBFILE", DEFAULT_PEER_PUBFILE),
    )
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="start a new shell instead of re-attaching to the running one",
    )
    parser.add_argument(
        "--host",
        "-n",
        default=os.environ.get("MOESH_TUNNEL_V2_HOST", proto.DEFAULT_HOST),
        help=("host number or name to attach to, e.g. 3 (default: %(default)s)"),
    )
    parser.add_argument(
        "--new-master",
        action="store_true",
        help="print a fresh master secret and the public key it derives",
    )
    parser.add_argument(
        "--generate-key",
        action="store_true",
        help="generate a fresh operator static key pair (ssh-keygen style)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing key file when generating",
    )
    parser.add_argument(
        "--no-reconnect",
        dest="reconnect",
        action="store_false",
        help="exit on a lost connection instead of re-attaching",
    )
    args = parser.parse_args(argv)

    if args.generate_key:
        return generate_key(args.keyfile, args.force)

    host = resolve_name(args.host)
    if args.new_master:
        return new_master(host)
    private = read_key(args.keyfile, "operator static private key")
    config = load_config() if os.path.exists(HOSTS_FILE) else {}
    hosts = config.get("hosts", {})
    if hosts:
        # A configured host must be pinned: never fall back to "whatever
        # key file happens to be there".
        peer = pinned_key(host)
    elif host == proto.DEFAULT_HOST:
        # The single-host setup: one key file, no configuration.
        peer = read_key(args.peer_pubfile, "agent static public key")
    else:
        raise ProtocolError(
            f"no configuration for host {host!r} in {HOSTS_FILE}: add a [hosts.{host}] "
            f"section, or run 'moesh-shell-v2 --new-master -n {host}' to create one"
        )

    if not os.isatty(sys.stdin.fileno()):
        raise ProtocolError(
            "standard input is not a terminal: moesh-shell-v2 needs a real terminal "
            "to advertise its size and to restore it afterwards"
        )
    term = os.environ.get("TERM", proto.DEFAULT_TERM)

    attempt = 0
    while True:
        try:
            return run_one_session(args, host, private, peer, term)
        except AuthenticationError:
            # An identity failure is not a network failure: never retry it.
            raise
        except (TransportEOF, SessionTimeout, ProtocolError, OSError) as exc:
            if not args.reconnect:
                raise
            attempt += 1
            delay = min(2**attempt, 30)
            log(
                f"connection lost ({exc}); re-attaching in {delay}s — the remote shell "
                f"keeps running"
            )
            time.sleep(delay)


def run_one_session(
    args: argparse.Namespace,
    host: str,
    private: bytes,
    peer: bytes,
    term: str,
) -> int:
    """Run one session: connect, authenticate, negotiate, relay the terminal.

    Raises:
        ProtocolError: the bridge or the host could not be reached.
        AuthenticationError: the host's identity did not match the pin.
        TransportEOF: the connection ended without an authenticated close.
        SessionTimeout: the peer stopped answering.
    """
    handshake_timeout = float(
        os.environ.get("MOESH_SHELL_V2_HANDSHAKE_TIMEOUT", proto.HANDSHAKE_TIMEOUT)
    )
    # The address and the routing label are different things: ``host`` is
    # the label this operator asks for (a function parameter here), the
    # endpoint is parsed into ``addr_host``.  They were once one name and
    # the overlap silently changed the routing label to the bridge's
    # address — measured 2026-10-21: every session queued under a queue
    # named after the receiver address and no agent ever saw a handshake.
    addr_host, _, port_text = args.addr.rpartition(":")
    if not addr_host:
        raise SystemExit(f"malformed endpoint {args.addr!r}; expected host:port")
    port = int(port_text)

    try:
        sock = socket.create_connection((addr_host, port), timeout=15)
    except OSError as exc:
        raise ProtocolError(
            f"cannot reach the receiver bridge at {addr_host}:{port}: {exc}"
        ) from exc
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    # The routing label: which host the operator is asking for.  It never
    # leaves the receiver host and carries no terminal data.
    sock.sendall(proto.PRELUDE_PREFIX + host.encode("latin-1") + b"\n")

    terminal = RawTerminal(sys.stdin.fileno())
    try:
        channel = proto.Channel(sock)
        session = proto.NoiseSession("initiator", private, peer)
        log(
            f"waiting for host {host!r} — the receiver is holding this "
            "connection while it attaches (it may be restarting)…"
        )
        sock.settimeout(handshake_timeout)
        try:
            handshake(session, channel)
        except TimeoutError as exc:
            raise ProtocolError(
                f"no agent answered within {int(handshake_timeout)}s: is the host still running?"
            ) from exc
        machine = proto.SessionState()
        machine.to(State.AUTHENTICATED)
        secure = proto.SecureChannel(channel, session)
        sock.settimeout(proto.NEGOTIATION_TIMEOUT)
        agreed = negotiate(secure, machine, term, fresh=args.fresh)
        sock.settimeout(None)
        with terminal:
            return run_session(
                sock,
                secure,
                agreed,
                ping_every=float(
                    os.environ.get("MOESH_SHELL_V2_PING_INTERVAL", "15") or 0
                ),
                dead_after=float(
                    os.environ.get("MOESH_SHELL_V2_DEAD_AFTER", "45") or 0
                ),
            )
    finally:
        terminal.restore()
        with contextlib.suppress(OSError):
            sock.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except (ProtocolError, TransportEOF, AuthenticationError) as error:
        log(f"session failed: {error!r}")
        sys.exit(1)
