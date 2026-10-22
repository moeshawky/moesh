#!/usr/bin/env python3
"""moesh v2 — host-side agent (Noise responder).

The agent runs on the host that offers the shell (the side away from the
operator's terminal).  It dials the receiver through an HTTP/1.1 Upgrade
path, terminates a Noise_XX session as the
**responder**, negotiates the terminal configuration with the operator, and
then serves an interactive Bash over an authenticated, encrypted record
channel.  The receiver bridge relays the ciphertext without interpreting it.

Lifecycle (measured, 2026-10-20)
---------------------------------
* The **agent process** is long-lived: it redials after a transport loss.
* The **shell survives operator disconnects**.  When an operator detaches, the
  interactive Bash keeps running: its working directory, its variables and its
  background jobs stay exactly as they were.  The next operator attaches to
  the same shell and receives the output produced while nobody was attached.
  This is what makes "connect again to the same host" mean what an
  operator expects, instead of landing in a fresh, empty shell.
* A detached shell is still drained into a bounded buffer (256 KiB), so a
  chatty job cannot block the PTY while nobody is watching.
* An operator can ask for a fresh shell (HELLO ``fresh_session``), which
  terminates the old one and starts a new one.
* A failed authentication is not a network loss: it backs off instead of
  retrying in a loop, and it never falls back to an unencrypted protocol.
* SIGTERM/SIGINT terminate the shell (SIGHUP) and reap it: no orphan Bash is
  left behind when the host's session is stopped.

Configuration (environment)
---------------------------
``MOESH_TUNNEL_V2_RECEIVER``       receiver address to dial (no default: with
                                   nothing set the agent refuses to start)
``MOESH_TUNNEL_V2_RECEIVER_PORT``  receiver port (default ``80``)
``MOESH_TUNNEL_V2_PATH``      Upgrade path (default ``/__moesh/tunnel``)
``MOESH_TUNNEL_V2_AGENT_KEY``  agent static private key, 64 hex characters
``MOESH_TUNNEL_V2_AGENT_KEYFILE``  file holding the same key
``MOESH_TUNNEL_V2_OPERATOR_PUB``  pinned operator static public key (hex)
``MOESH_TUNNEL_V2_HOST``      this host's NUMBER (the identity switch)
``MOESH_TUNNEL_V2_MASTER``    master secret; the static key is derived from it
``MOESH_TUNNEL_V2_NAME``      explicit routing name (when no number is set)
``MOESH_TUNNEL_V2_CHILD_PIDFILE``  optional file receiving the shell's PID

The agent private key is never embedded in this file, printed, or passed on a
command line; it is read from the environment or from a file.  When no key is
provisioned the agent refuses to start (fail closed).
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import os
import pty
import select
import signal
import socket
import struct
import sys
import termios
import threading
import time
from typing import Any

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

DEFAULT_HOST = ""
"""Receiver address to dial.  Empty by default: an address must be provisioned
(through ``MOESH_TUNNEL_V2_RECEIVER``) or the agent refuses to start, so a
bare checkout never dials anywhere."""
DEFAULT_PORT = 80
DEFAULT_PATH = "/__moesh/tunnel"
DEFAULT_SESSIONS = 3
"""How many operators this agent serves at once.

Three is enough for one person with a few terminals plus a spare.  Each one
is a separate connection with its own shell, so two operators never share a
PTY and their keystrokes cannot interleave.
"""
DEFAULT_NAME = "default"
"""Host name used when the environment does not name one.

The name is a routing label: it tells the receiver which host an
operator is asking for.  It is NOT the identity — that is the static key,
which the operator pins per host.
"""
DEFAULT_KEYFILE = os.path.expanduser("~/.config/moesh/agent.key")

#: Pinned operator static public key (hex).  Provisioned at build time; it is a
#: PUBLIC key, so it is safe to ship in this file.  Empty means "not
#: provisioned" and the agent refuses to start.  Never bake a key into a
#: tracked file; prefer the env var or a key file outside the tree.
PINNED_OPERATOR_PUB = ""

AUTH_BACKOFF = 60.0
"""Seconds to wait after an authentication failure (never a fast retry loop)."""

NET_BACKOFF_MAX = 30.0
"""Upper bound of the exponential backoff used for ordinary network loss."""

DETACHED_BUFFER = 262144
"""Bytes of shell output kept while no operator is attached (256 KiB)."""

_stopping = False


class Stop(Exception):
    """Raised from the signal handler so a blocking read is interrupted.

    A handler that only sets a flag is not enough: PEP 475 restarts the
    interrupted syscall, so an agent waiting for an operator would keep
    waiting and ignore SIGTERM.  Raising breaks the wait.
    """


def log(message: str) -> None:
    """Write one flushed log line; the caller polls this log for its postcondition."""
    print("[tunnel-v2 {}] {}".format(time.strftime("%H:%M:%S"), message), flush=True)


def _on_stop(_signum: int, _frame: Any) -> None:
    """Ask the agent to stop cleanly."""
    global _stopping
    _stopping = True
    raise Stop()


def load_agent_private_key() -> bytes:
    """Return the agent's static private key.

    Sources, in order: ``MOESH_TUNNEL_V2_AGENT_KEY``, ``MOESH_TUNNEL_V2_AGENT_KEYFILE``.

    Raises:
        ProtocolError: no key was provisioned or the key is malformed.
    """
    raw = os.environ.get("MOESH_TUNNEL_V2_AGENT_KEY", "").strip()
    path = os.environ.get("MOESH_TUNNEL_V2_AGENT_KEYFILE", "").strip()
    if not raw and path:
        try:
            with open(path, encoding="ascii") as handle:
                raw = handle.read().strip()
        except OSError as exc:
            raise ProtocolError(f"cannot read agent key file {path}: {exc}") from exc
    if not raw:
        raise ProtocolError(
            "agent static key not provisioned: set MOESH_TUNNEL_V2_AGENT_KEY or "
            "MOESH_TUNNEL_V2_AGENT_KEYFILE"
        )
    raw = raw.removeprefix("0x").replace(":", "").strip()
    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise ProtocolError("agent static key is not valid hex") from exc
    if len(key) != 32:
        raise ProtocolError(f"agent static key must be 32 bytes, got {len(key)}")
    return key


def load_operator_pin() -> bytes:
    """Return the pinned operator static public key.

    Raises:
        ProtocolError: no pin was provisioned.
    """
    raw = (
        os.environ.get("MOESH_TUNNEL_V2_OPERATOR_PUB", "").strip()
        or PINNED_OPERATOR_PUB.strip()
    )
    if not raw:
        raise ProtocolError(
            "operator static public key not provisioned: set "
            "MOESH_TUNNEL_V2_OPERATOR_PUB or bake PINNED_OPERATOR_PUB into the agent"
        )
    try:
        pin = bytes.fromhex(raw.removeprefix("0x").replace(":", "").strip())
    except ValueError as exc:
        raise ProtocolError("operator static public key is not valid hex") from exc
    if len(pin) != 32:
        raise ProtocolError(
            f"operator static public key must be 32 bytes, got {len(pin)}"
        )
    return pin


def host_name() -> str:
    """Return this host's routing name.

    ``MOESH_TUNNEL_V2_HOST`` carries the NUMBER that identifies this
    host, exactly like the port number in the operator's SSH host
    entries: change the number and this host's identity changes.  The name
    is ``<prefix>-<number>``; with no number the host keeps the name
    ``default``.

    Raises:
        ProtocolError: the name is empty or has characters the receiver will
            not accept.
    """
    number = os.environ.get("MOESH_TUNNEL_V2_HOST", "").strip()
    prefix = os.environ.get("MOESH_TUNNEL_V2_PREFIX", proto.DEFAULT_PREFIX).strip()
    if number:
        name = proto.host_name(number, prefix or proto.DEFAULT_PREFIX)
    else:
        name = os.environ.get("MOESH_TUNNEL_V2_NAME", DEFAULT_NAME).strip()
    if (
        not name
        or len(name) > 64
        or not all(ch.isalnum() or ch in "._-" for ch in name)
    ):
        raise ProtocolError(
            f"invalid host name {name!r}: use letters, digits, dot, dash or underscore"
        )
    return name


def agent_private_key(name: str) -> bytes:
    """Return this host's static private key.

    Two sources, in order:

    1. ``MOESH_TUNNEL_V2_MASTER`` — a master secret, from which the key is
       derived for this host's name.  This is the mode that gives the
       operator the old "switch one number" ease: the identity NUMBER set
       on the host side changes the identity by itself.
    2. ``MOESH_TUNNEL_V2_AGENT_KEY`` / ``MOESH_TUNNEL_V2_AGENT_KEYFILE`` — a raw
       32-byte key, for hosts that want a key of their own.

    Raises:
        ProtocolError: no key could be obtained.
    """
    master = os.environ.get("MOESH_TUNNEL_V2_MASTER", "").strip()
    if master:
        cleaned = master.removeprefix("0x").replace(":", "").strip()
        try:
            secret = bytes.fromhex(cleaned)
        except ValueError as exc:
            raise ProtocolError("the master secret is not valid hex") from exc
        if len(secret) < 16:
            raise ProtocolError("the master secret must be at least 16 bytes")
        return proto.derive_static_key(secret, name)
    return load_agent_private_key()


def http_upgrade(
    sock: socket.socket, host: str, port: int, path: str, name: str
) -> bytes:
    """Perform the HTTP/1.1 Upgrade and return the bytes that followed the headers.

    The token is a custom one (``moesh-tunnel-v2``): this connection is not a
    WebSocket and carries no RFC 6455 framing, so it must not claim to be one.
    The response must echo the same token; anything else is refused rather than
    downgraded.

    Raises:
        ProtocolError: the server refused the upgrade or echoed another token.
    """
    request = (
        f"GET {path.rstrip('/')}/{name} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: {proto.UPGRADE_TOKEN}\r\n"
        f"Connection: Upgrade\r\n"
        f"X-Moesh-Tunnel-Version: {proto.PROTOCOL_VERSION}\r\n\r\n"
    ).encode()

    sock.sendall(request)
    buffer = b""
    while b"\r\n\r\n" not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            raise ProtocolError("receiver closed during the HTTP upgrade")
        buffer += chunk
        if len(buffer) > 65536:
            raise ProtocolError("HTTP header block too large")
    head, rest = buffer.split(b"\r\n\r\n", 1)
    status = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    if " 101" not in status:
        raise ProtocolError(f"upgrade refused: {status}")
    token = ""
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"upgrade:"):
            token = line.split(b":", 1)[1].strip().decode("latin-1", "replace").lower()
    if token != proto.UPGRADE_TOKEN:
        raise ProtocolError(
            f"receiver echoed upgrade token {token!r}, expected {proto.UPGRADE_TOKEN!r}"
        )
    echoed = ""
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"x-moesh-tunnel-name:"):
            echoed = line.split(b":", 1)[1].strip().decode("latin-1", "replace")
    if echoed != name:
        raise ProtocolError(
            f"receiver routed this tunnel to {echoed!r}, expected {name!r}"
        )
    return rest


def set_winsize(fd: int, rows: int, cols: int) -> None:
    """Apply a window size to a PTY master fd."""
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


def write_all(fd: int, data: bytes) -> None:
    """Write every byte to the PTY, tolerating partial writes."""
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def chunks(data: bytes, size: int) -> list[bytes]:
    """Split ``data`` into records of at most ``size`` bytes."""
    return [data[i : i + size] for i in range(0, len(data), size)]


def decode_resize(payload: bytes) -> tuple[int, int]:
    """Decode a RESIZE payload (``uint16_be rows || uint16_be cols``).

    Raises:
        NegotiationError: the payload is malformed or the dimensions are out of bounds.
    """
    if len(payload) != 4:
        raise NegotiationError(f"resize payload must be 4 bytes, got {len(payload)}")
    rows, cols = struct.unpack(">HH", payload)
    proto.validate_resize({"rows": rows, "cols": cols})
    return rows, cols


class HostShell:
    """The remote interactive shell.

    The shell outlives an operator session: when the operator detaches, the
    Bash process keeps running and the output it produces is held in a bounded
    buffer for the next operator.
    """

    def __init__(self, max_buffer: int = DETACHED_BUFFER) -> None:
        self.pid: int | None = None
        self.fd: int | None = None
        self.buffer = bytearray()
        self.dropped = 0
        self.max_buffer = max_buffer
        self.term = proto.DEFAULT_TERM
        self.rows = proto.DEFAULT_ROWS
        self.cols = proto.DEFAULT_COLS

    @property
    def alive(self) -> bool:
        """True when a shell process is running."""
        return self.pid is not None and self.fd is not None

    def spawn(self, term: str, rows: int, cols: int) -> None:
        """Terminate any previous shell and start a fresh interactive Bash.

        Raises:
            ProtocolError: the child could not be started.
        """
        self.terminate()
        pid, fd = pty.fork()
        if pid == 0:
            os.environ["TERM"] = term
            os.environ["LANG"] = "C.UTF-8"
            os.environ["LC_ALL"] = "C.UTF-8"
            try:
                # exec, not a shell: the argv is fixed and the path is
                # absolute, so nothing here is interpolated.
                os.execv("/bin/bash", ["/bin/bash", "-i"])  # noqa: S606
            except OSError:
                os._exit(127)
        set_winsize(fd, rows, cols)
        self.pid, self.fd = pid, fd
        self.term, self.rows, self.cols = term, rows, cols
        self.buffer.clear()
        self.dropped = 0
        self._write_pidfile()
        log(f"shell started (pid {pid}, {rows}x{cols})")

    def _write_pidfile(self) -> None:
        """Record the shell's PID where the operator asked for it."""
        path = os.environ.get("MOESH_TUNNEL_V2_CHILD_PIDFILE", "").strip()
        if not path or self.pid is None:
            return
        try:
            with open(path, "w", encoding="ascii") as handle:
                handle.write(f"{self.pid}\n")
        except OSError:
            pass

    def _remove_pidfile(self) -> None:
        """Remove the PID file if this agent owns it."""
        path = os.environ.get("MOESH_TUNNEL_V2_CHILD_PIDFILE", "").strip()
        if not path:
            return
        with contextlib.suppress(OSError):
            os.unlink(path)

    def apply_size(self, rows: int, cols: int) -> None:
        """Apply a new window size to the running shell."""
        fd = self.fd
        if fd is None:
            return
        set_winsize(fd, rows, cols)
        self.rows, self.cols = rows, cols

    def read_output(self) -> bytes | None:
        """Read what the shell produced.

        Returns ``None`` when the shell has exited (the PTY reports EIO).
        """
        fd = self.fd
        if fd is None:
            return None
        try:
            data = os.read(fd, 65536)
        except OSError:
            return None
        return data or None

    def hold(self, data: bytes) -> None:
        """Buffer output produced while no operator is attached."""
        self.buffer += data
        if len(self.buffer) > self.max_buffer:
            excess = len(self.buffer) - self.max_buffer
            del self.buffer[:excess]
            self.dropped += excess

    def take(self) -> bytes:
        """Return and clear the buffered output."""
        out = bytes(self.buffer)
        self.buffer.clear()
        return out

    def reap(self) -> int:
        """Reap the shell if it exited and return its status."""
        if self.pid is None:
            return 0
        status = 0
        try:
            _, wait_status = os.waitpid(self.pid, os.WNOHANG)
            if os.WIFEXITED(wait_status):
                status = os.WEXITSTATUS(wait_status)
            elif os.WIFSIGNALED(wait_status):
                status = 128 + os.WTERMSIG(wait_status)
        except OSError:
            pass
        return status

    def wait_exit(self, timeout: float = 5.0) -> int:
        """Wait for the shell to exit and return its real status.

        The PTY reports EIO before the child becomes waitable, so a single
        ``WNOHANG`` probe can return ``(0, 0)`` and make ``exit 7`` look like
        a clean exit (measured 2026-10-22: ``exit 7`` -> agent ``status 0``).
        Poll until the child is reapable or the deadline expires.  ``self.pid``
        is left untouched so ``terminate()`` and the pidfile keep working.
        """
        if self.pid is None:
            return 0
        deadline = time.monotonic() + timeout
        while True:
            try:
                pid, wait_status = os.waitpid(self.pid, os.WNOHANG)
            except ChildProcessError:
                return 0
            if pid == self.pid:
                if os.WIFEXITED(wait_status):
                    return os.WEXITSTATUS(wait_status)
                if os.WIFSIGNALED(wait_status):
                    return 128 + os.WTERMSIG(wait_status)
                return 0
            if time.monotonic() >= deadline:
                log("timed out waiting for the shell to become reapable; reporting status 0")
                return 0
            time.sleep(0.01)

    def terminate(self) -> None:
        """Terminate the shell and reap it; never leave a zombie or an orphan."""
        if self.pid is None:
            return
        with contextlib.suppress(OSError):
            os.kill(self.pid, signal.SIGHUP)
        if self.fd is not None:
            with contextlib.suppress(OSError):
                os.close(self.fd)
        with contextlib.suppress(OSError):
            os.waitpid(self.pid, 0)
        self.pid = None
        self.fd = None
        self._remove_pidfile()
        log("shell terminated")


class ShellPool:
    """The shells this agent can hand to operators.

    One agent serves several operators at once, so it keeps several shells.
    A shell outlives the session that used it: when the operator detaches, the
    Bash process keeps running and a later operator can re-attach to it with
    its directory, variables and jobs intact.  A session that asks for a fresh
    shell gets one of its own.

    The pool is what makes concurrent connections safe: two operators never
    share a PTY, so their keystrokes cannot interleave.
    """

    def __init__(self, max_idle: int = 4) -> None:
        self._shells: list[HostShell] = []
        self._busy: set[int] = set()
        self._lock = threading.Lock()
        self.max_idle = max_idle

    def _drop(self, shell: HostShell) -> None:
        """Remove a shell from the pool and terminate it."""
        with contextlib.suppress(ValueError):
            self._shells.remove(shell)
        self._busy.discard(id(shell))
        shell.terminate()

    def acquire(self, fresh: bool) -> HostShell:
        """Return a shell for a new session.

        A fresh session always gets its own shell.  Otherwise the most
        recently used idle shell is re-attached to, the way tmux does on
        attach; if there is none, a new one is created.
        """
        with self._lock:
            if not fresh:
                for shell in reversed(self._shells):
                    if id(shell) in self._busy:
                        continue
                    if not shell.alive:
                        continue
                    self._busy.add(id(shell))
                    return shell
            shell = HostShell()
            self._shells.append(shell)
            self._busy.add(id(shell))
            return shell

    def release(self, shell: HostShell) -> None:
        """Give a shell back: it keeps running for the next operator."""
        with self._lock:
            self._busy.discard(id(shell))
            if not shell.alive:
                self._drop(shell)

    def idle_shells(self) -> list[HostShell]:
        """Return the shells that no session is using right now."""
        with self._lock:
            return [
                shell
                for shell in self._shells
                if shell.alive and id(shell) not in self._busy
            ]

    def discard(self, shell: HostShell) -> None:
        """Drop a shell from the pool and terminate it."""
        with self._lock:
            self._drop(shell)

    def reap(self) -> None:
        """Terminate the shells that have exited, keeping the pool bounded."""
        with self._lock:
            for shell in list(self._shells):
                if not shell.alive:
                    self._drop(shell)
            idle = [s for s in self._shells if id(s) not in self._busy]
            while len(idle) > self.max_idle:
                oldest = idle.pop(0)
                log(f"retiring an idle shell (pid {oldest.pid})")
                self._drop(oldest)

    def terminate_all(self) -> None:
        """Terminate every shell this pool owns."""
        with self._lock:
            for shell in list(self._shells):
                self._drop(shell)


def wait_for_handshake(channel: proto.Channel, pool: ShellPool) -> bytes:
    """Wait for the operator's first handshake message, draining the shells.

    The shells keep producing output while nobody is attached; it is read into
    their bounded buffers so the PTY never blocks a shell.

    The transport's buffer is asked **first**, before the socket.  A frame
    that arrived in the same TCP segment as the HTTP 101 response is already
    in that buffer, and the socket has nothing left to report, so waiting on
    the socket alone waits for an operator who has already spoken.
    Measured 2026-10-21: that was the intermittent failure the suite showed
    — the frame arrived with the response in exactly the runs that failed,
    and the operator then sat in its handshake until its own timeout.

    Raises:
        ProtocolError: the agent was asked to stop while waiting.
    """
    waited = 0.0
    while True:
        if _stopping:
            raise ProtocolError("agent stopping")
        waited += 1.0
        if waited >= 30.0:
            waited = 0.0
            log("still waiting for an operator on this tunnel")
        # The buffer first: a frame that is already here must not wait for
        # the socket to report something it will never report.
        item = channel.next_frame()
        if item is not None:
            return item
        idle = pool.idle_shells()
        watched = [channel.socket] + [shell.fd for shell in idle]
        ready, _, _ = select.select(watched, [], [], 1.0)
        # Read the idle shells only when select says they are readable: a
        # blocking read on a quiet PTY would hang this worker and the
        # operator's handshake with it.
        for shell in idle:
            if shell.fd not in ready:
                continue
            data = shell.read_output()
            if data is None:
                log("a shell exited while detached")
                pool.discard(shell)
                continue
            if data:
                shell.hold(data)
        if channel.socket in ready:
            return channel.recv_frame()


def negotiate(
    secure: proto.SecureChannel,
    machine: proto.SessionState,
    pool: ShellPool,
) -> dict[str, Any]:
    """Run HELLO/ACCEPT/READY and attach to (or start) the shell.

    Returns the accepted configuration.

    Raises:
        NegotiationError: the operator's HELLO was not acceptable.
        AuthenticationError: the handshake transcript did not match.
    """
    machine.to(State.NEGOTIATING)
    msg_type, hello = secure.recv_control()
    if msg_type != Msg.HELLO:
        raise NegotiationError(f"expected HELLO, got message type {msg_type}")
    accepted = proto.validate_hello(hello)
    peer_hash = str(hello.get("handshake_hash", ""))
    if peer_hash != secure.session.handshake_hash().hex():
        raise AuthenticationError("operator handshake hash does not match this session")
    fresh = bool(hello.get("fresh_session"))
    # The shell is chosen only now: the HELLO is what says whether this
    # session wants a fresh shell or the running one.
    shell = pool.acquire(fresh)
    resumed = bool(shell.alive and not fresh)
    accepted["resumed"] = resumed
    secure.send_control(Msg.ACCEPT, accepted)
    machine.to(State.READY)
    msg_type, _payload = secure.recv_control()
    if msg_type != Msg.READY:
        raise NegotiationError(f"expected READY, got message type {msg_type}")
    secure.send_control(Msg.READY, {})
    machine.to(State.ACTIVE)

    if fresh or not shell.alive:
        shell.spawn(accepted["term"], accepted["rows"], accepted["cols"])
    else:
        shell.apply_size(accepted["rows"], accepted["cols"])
        # The prompt the previous operator saw was already consumed. A newline
        # makes the shell draw a fresh prompt, the way tmux does on attach.
        fd = shell.fd
        if fd is not None:
            with contextlib.suppress(OSError):
                os.write(fd, b"\n")
        log(f"attached to the running shell (pid {shell.pid})")
    held = shell.take()
    if held:
        if shell.dropped:
            log(f"replaying {len(held)} buffered bytes ({shell.dropped} dropped)")
        else:
            log(f"replaying {len(held)} buffered bytes")
        for piece in chunks(held, proto.MAX_DATA_PAYLOAD):
            secure.send(Msg.DATA, piece)
    accepted["_shell"] = shell
    return accepted


def run_session(
    sock: socket.socket,
    secure: proto.SecureChannel,
    shell: HostShell,
    accepted: dict[str, Any],
) -> str:
    """Serve one operator session.

    Returns ``"detached"`` when the operator went away (the shell stays
    alive) or ``"closed"`` when the shell itself exited.

    Raises:
        TransportEOF: the transport ended without an authenticated CLOSE.
    """
    log(
        f"session active: term={accepted['term']} {accepted['rows']}x{accepted['cols']}"
    )
    graceful = False
    status = 0
    last_rx = time.time()
    last_ping = time.time()
    ping_every = float(os.environ.get("MOESH_TUNNEL_V2_PING_INTERVAL", "15") or 0)
    dead_after = float(os.environ.get("MOESH_TUNNEL_V2_DEAD_AFTER", "90") or 0)
    while True:
        fd = shell.fd
        watched: list[socket.socket | int] = [sock] if fd is None else [sock, fd]
        ready, _, _ = select.select(watched, [], [], 1.0)
        now = time.time()
        if ping_every > 0 and now - last_ping >= ping_every:
            last_ping = now
            try:
                secure.send_control(Msg.PING, {"t": int(now)})
            except (OSError, ProtocolError):
                log("the operator stopped answering; detaching")
                return "detached"
        if dead_after > 0 and now - last_rx > dead_after:
            # The operator client pings every 15s; 90s of silence means it is
            # gone (or the path is black-holing).  Detach and keep the shell.
            log("no traffic from the operator for 90s; detaching (the shell stays)")
            return "detached"
        if shell.fd in ready:
            data = shell.read_output()
            if data is None:
                status = shell.wait_exit()
                if _stopping:
                    # The agent is shutting down (SIGTERM, or the host process
                    # is restarting).  That is a lost transport, not
                    # the end of a session: an orderly CLOSE here would tell
                    # the operator "your shell ended" and make the client
                    # exit instead of waiting for the host to come back.
                    log("the agent is stopping; the session ends abruptly")
                    return "detached"
                log(f"remote shell exited (status {status})")
                try:
                    secure.send_control(Msg.EXIT, {"status": status, "signal": None})
                    secure.send_control(Msg.CLOSE, {"reason": "shell exited"})
                except (OSError, ProtocolError):
                    pass
                return "closed"
            for piece in chunks(data, proto.MAX_DATA_PAYLOAD):
                secure.send(Msg.DATA, piece)
        # The transport's buffer is drained every pass, not only when the
        # socket says it is readable: a record that arrived together with
        # another one is already there, and the socket has nothing left to
        # report.  Ask the transport first, the socket second.
        records = secure.buffered()
        if sock in ready:
            records += secure.drain()
        for msg_type, payload in records:
            last_rx = time.time()
            if msg_type == Msg.DATA:
                if fd is not None:
                    write_all(fd, payload)
            elif msg_type == Msg.RESIZE:
                rows, cols = decode_resize(payload)
                shell.apply_size(rows, cols)
                log(f"resized to {rows}x{cols}")
            elif msg_type == Msg.PING:
                secure.send(Msg.PONG, payload)
            elif msg_type == Msg.PONG:
                pass
            elif msg_type == Msg.ERROR:
                log(f"operator reported an error: {payload[:200]!r}")
                graceful = True
            elif msg_type == Msg.CLOSE:
                log("operator closed the session (authenticated close)")
                graceful = True
            elif msg_type == Msg.EXIT:
                log("operator asked the session to end")
                graceful = True
            else:
                raise ProtocolError(f"unexpected message type {msg_type} from operator")
        if graceful:
            return "detached"
    return "detached"


def serve_once(host: str, port: int, path: str, name: str, pool: ShellPool) -> str:
    """Run one full session: connect, authenticate, negotiate, serve.

    The shell is chosen during the negotiation (the operator's HELLO says
    whether it wants a fresh one) and given back to the pool when the
    session ends, so the next operator can re-attach to it.

    Returns ``"detached"`` or ``"closed"``.

    Raises:
        ProtocolError: any protocol, framing or authentication failure.
    """
    machine = proto.SessionState()
    private = agent_private_key(name)
    log(f"agent static public key: {proto.public_key_of(private)}")
    pin = load_operator_pin()
    sock = socket.create_connection((host, port), timeout=15)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        leftover = http_upgrade(sock, host, port, path, name)
        log(
            f"upgraded (HTTP/1.1 101 Switching Protocols, token {proto.UPGRADE_TOKEN}, host {name})"
        )
        log("queued at the receiver; waiting for an authenticated operator")
        channel = proto.Channel(sock)
        if leftover:
            # The operator's first frame arrived in the same TCP segment as
            # the 101 response.  It is now in the transport's own buffer, not
            # in the socket, so a reader that waits on the socket for
            # readability would never see it.  Measured 2026-10-21: the
            # operator's frame arrived this way in a failing run, the agent
            # waited for an operator that had already spoken, and the
            # operator sat in its handshake until its own timeout.
            log(
                f"the first frame arrived with the HTTP response ({len(leftover)} bytes)"
            )
            channel.seed(leftover)
        session = proto.NoiseSession("responder", private, pin)
        # The tunnel lives until the receiver takes it.  It must not expire
        # under an operator's feet: the receiver holds an operator connection
        # for 120s while it looks for a host, and a tunnel that gave up
        # first left the operator paired with a corpse, waiting out its
        # handshake timeout.  Measured 2026-10-21: connect attempts failed
        # over and over, and one operator connection in three hung.
        sock.settimeout(None)
        log("tunnel established; waiting for an operator")
        first = wait_for_handshake(channel, pool)
        session.read_handshake(first)
        channel.send_frame(session.write_handshake())
        session.read_handshake(channel.recv_frame())
        if not session.handshake_finished:
            raise ProtocolError("Noise handshake did not complete")
        machine.to(State.AUTHENTICATED)
        log("authenticated (peer static key matched the pin)")
        secure = proto.SecureChannel(channel, session)
        sock.settimeout(proto.NEGOTIATION_TIMEOUT)
        accepted = negotiate(secure, machine, pool)
        sock.settimeout(None)
        shell = accepted.pop("_shell")
        try:
            return run_session(sock, secure, shell, accepted)
        finally:
            pool.release(shell)
    finally:
        with contextlib.suppress(OSError):
            sock.close()


def generate_key(keyfile: str, force: bool = False) -> int:
    """Write a fresh agent static key pair and print the public key.

    Only the public key is printed; the private key goes to ``keyfile`` with
    mode 0600.  An existing ``keyfile`` or its ``.pub`` is refused unless
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
    os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(private.hex() + "\n")
    os.chmod(path, 0o600)
    public_path = path + ".pub"
    with open(public_path, "w", encoding="ascii") as handle:
        handle.write(public.hex() + "\n")
    os.chmod(public_path, 0o644)
    digest = hashlib.sha256(public).digest()
    fingerprint = base64.b64encode(digest).decode("ascii").rstrip("=")
    print(f"agent static private key written to {path} (mode 0600)")
    print(f"agent static public key written to {public_path}")
    print(f"agent static PUBLIC key (pin this on the receiver): {public.hex()}")
    print(f"SHA256:{fingerprint}")
    return 0


def tunnel_worker(host: str, port: int, path: str, name: str, pool: ShellPool) -> None:
    """Hold one tunnel to the receiver and serve whoever claims it.

    Each worker owns one connection to the receiver, so the agent can serve
    several operators at once: the operator arrives, the receiver pairs it
    with one of the queued tunnels, and the session runs on that worker's
    thread.  When the session ends the worker opens a fresh tunnel, so the
    receiver always has a spare waiting for the next operator.

    This is the tmux shape rather than the SSH one: the host holds the
    shells and every operator brings its own transport, instead of one
    transport carrying many channels (RFC 4254 section 5).
    """
    backoff = 2.0
    while not _stopping:
        try:
            outcome = serve_once(host, port, path, name, pool)
            backoff = 2.0
            if outcome == "closed":
                log("a shell exited; the others keep running")
            else:
                log("an operator detached; its shell keeps running")
        except Stop:
            break
        except AuthenticationError as exc:
            log(
                f"AUTHENTICATION FAILED: {exc} — refusing to retry for {int(AUTH_BACKOFF)}s"
            )
            time.sleep(AUTH_BACKOFF)
        except TransportEOF:
            log("transport ended without an authenticated close (abrupt EOF)")
            time.sleep(backoff)
            backoff = min(backoff * 2, NET_BACKOFF_MAX)
        except (ProtocolError, OSError) as exc:
            log(f"session failed: {exc!r}")
            time.sleep(backoff)
            backoff = min(backoff * 2, NET_BACKOFF_MAX)
    log("tunnel worker finished")


def main(argv: list[str] | None = None) -> int:
    """Run the agent until interrupted."""
    parser = argparse.ArgumentParser(description="moesh v2 host agent")
    parser.add_argument(
        "--generate-key",
        action="store_true",
        help="write a fresh agent static key pair and print the public key",
    )
    parser.add_argument(
        "--keyfile",
        default=DEFAULT_KEYFILE,
        help="where --generate-key writes the private key (default: %(default)s)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing key file when generating",
    )
    args = parser.parse_args(argv)
    if args.generate_key:
        return generate_key(args.keyfile, args.force)

    host = os.environ.get("MOESH_TUNNEL_V2_RECEIVER", DEFAULT_HOST).strip()
    if not host:
        raise SystemExit(
            "no receiver configured: set MOESH_TUNNEL_V2_RECEIVER (address or "
            "host name the agent dials) and, if it is not port 80, "
            "MOESH_TUNNEL_V2_RECEIVER_PORT"
        )
    port = int(os.environ.get("MOESH_TUNNEL_V2_RECEIVER_PORT", str(DEFAULT_PORT)))
    path = os.environ.get("MOESH_TUNNEL_V2_PATH", DEFAULT_PATH)
    name = host_name()

    signal.signal(signal.SIGTERM, _on_stop)
    signal.signal(signal.SIGINT, _on_stop)

    pool = ShellPool()
    sessions = max(1, int(os.environ.get("MOESH_TUNNEL_V2_SESSIONS", DEFAULT_SESSIONS)))
    log(f"serving up to {sessions} concurrent operator(s) for {name!r}")
    workers = [
        threading.Thread(
            target=tunnel_worker,
            args=(host, port, path, name, pool),
            name=f"moesh-tunnel-session-{index + 1}",
            daemon=True,
        )
        for index in range(sessions)
    ]
    for worker in workers:
        worker.start()
    try:
        while not _stopping:
            time.sleep(0.5)
            pool.reap()
    except Stop:
        pass
    finally:
        pool.terminate_all()
        log("agent stopped")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
