#!/usr/bin/env python3
"""HTTP-Upgrade bridge: the host shell tunnel — legacy plaintext (v1) and
encrypted (v2) — plus a public relay.

Preconditions:
    * A listener in front of the receiver (reverse proxy or direct) forwards
      one HTTP/1.1 route to the tunnel listen address (default
      ``127.0.0.1:9447``).  The v2 path is ``/__moesh/tunnel`` on that route.
    * A host dials in with an HTTP Upgrade handshake on ``/__moesh/tunnel``
      (shell) or ``/__relay/gpu`` (relay).  The v1 shell path
      ``/__tunnel/v1`` is the legacy plaintext product's path and is kept
      for rollback; it can be refused with ``MOESH_BRIDGE_ALLOW_V1=0`` and
      there is no automatic downgrade.
Postconditions:
    Once a 101 is sent, the connection becomes a raw byte pipe and is queued
    by path.  The operator socket on 127.0.0.1:44440 pops only the v1 shell
    queue; the operator socket on 127.0.0.1:44441 pops only the v2 shell
    queue; each connection on any of 0.0.0.0:26420-26430 only sees
    ``/__relay/gpu`` and is spliced to it.  Bytes are relayed both ways until
    either side closes.
Side effects:
    Listens on 127.0.0.1:9447 (tunnel), 127.0.0.1:44440 (operator v1),
    127.0.0.1:44441 (operator v2) and 0.0.0.0:26420-26430 (public
    relay).  Writes one log line per transition.  A port that is already bound
    is logged and skipped; the remaining listeners stay up.
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
import os
import queue
import socket
import threading
import time
from typing import TYPE_CHECKING

from moesh_wire import (
    DEFAULT_HOST,
    PRELUDE_PREFIX,
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
# the public side of the /__relay/gpu path, and the operator firewall is
# what limits it.
GPU_RELAY_HOST = "0.0.0.0"  # noqa: S104
ALLOW_V1 = os.environ.get("MOESH_BRIDGE_ALLOW_V1", "1") != "0"

GPU_PATH = "/__relay/gpu"
V1_TUNNEL_PATH = "/__tunnel/v1"
TUNNEL_PATH_PREFIX = TUNNEL_PATH + "/"
GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_shell: queue.Queue[socket.socket] = queue.Queue(maxsize=8)
_shell_v2: dict[str, queue.Queue[socket.socket]] = {}
_registry_lock = threading.Lock()
MAX_HOST_QUEUES = 256


def host_queue(name: str) -> queue.Queue[socket.socket]:
    """Return the queue of one host, creating it on first use."""
    with _registry_lock:
        item = _shell_v2.get(name)
        if item is not None:
            return item
        if len(_shell_v2) >= MAX_HOST_QUEUES:
            for k in list(_shell_v2.keys()):
                if _shell_v2[k].empty():
                    del _shell_v2[k]
                if len(_shell_v2) < MAX_HOST_QUEUES:
                    break
            if len(_shell_v2) >= MAX_HOST_QUEUES:
                for k in list(_shell_v2.keys()):
                    if _shell_v2[k].empty():
                        del _shell_v2[k]
                        break
        item = queue.Queue(maxsize=8)
        _shell_v2[name] = item
        return item


def valid_host(name: str) -> bool:
    """Return True when the name is safe to use as a routing label."""
    if not name or len(name) > 64:
        return False
    return all(ch.isalnum() or ch in "._-" for ch in name)


_gpu: queue.Queue[socket.socket] = queue.Queue(maxsize=64)


def split_hostport(value: str, default_host: str = "127.0.0.1") -> tuple[str, int]:
    """Split ``host:port`` into a tuple, defaulting the host when absent."""
    host, _, port = value.rpartition(":")
    if not host:
        host = default_host
    return host, int(port)


TUNNEL_LISTEN = split_hostport(_TUNNEL_LISTEN)
OPERATOR_LISTEN = split_hostport(_OPERATOR_LISTEN)
OPERATOR_V2_LISTEN = split_hostport(_OPERATOR_V2_LISTEN)


def log(msg: str) -> None:
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def read_headers(conn: socket.socket) -> bytes:
    """Read bytes through the end of the HTTP header block."""
    buf = b""
    conn.settimeout(15)
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            raise ConnectionError("closed during headers")
        buf += chunk
        if len(buf) > 65536:
            raise ConnectionError("header block too large")
    return buf


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


def refuse(conn: socket.socket, status: str, reason: str) -> None:
    """Answer a handshake refusal and close the connection."""
    with contextlib.suppress(OSError):
        conn.sendall(
            (
                f"HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            ).encode()
        )
    with contextlib.suppress(OSError):
        conn.close()
    log(f"refused handshake: {reason}")


def tunnel_conn(conn: socket.socket, addr: tuple[str, int]) -> None:
    """Accept one host tunnel: answer the Upgrade, then queue it by path.

    Two upgrade tokens are accepted:

    ``moesh-tunnel-v2``
        The encrypted shell tunnel.  The connection carries a Noise_XX session
        and framed records; the bridge relays the ciphertext opaquely and never
        terminates the session.
    ``websocket``
        The legacy v1 shell tunnel and the relay.  Kept for rollback;
        the v1 *shell* path can be refused with ``MOESH_BRIDGE_ALLOW_V1=0`` while
        ``/__relay/gpu`` stays available.
    """
    try:
        hdrs = read_headers(conn)
        path = request_path(hdrs)
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
        if "upgrade" not in conn_hdr:
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
            conn.sendall(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: " + UPGRADE_TOKEN.encode() + b"\r\n"
                b"Connection: Upgrade\r\n"
                b"X-Moesh-Tunnel-Version: 2\r\n"
                b"X-Moesh-Tunnel-Name: " + host.encode() + b"\r\n\r\n"
            )
            conn.settimeout(None)
            log(f"host tunnel v2 attached from {addr} host {host}")
            host_queue(host).put(conn, timeout=2.0)
            return
        if token != "websocket":  # noqa: S105 - a protocol identifier, not a secret
            refuse(conn, "400 Bad Request", f"unsupported upgrade token {token!r}")
            return
        # The v1 shell path and the relay path are the legacy product's
        # paths; only the v2 path is moesh's.
        if path == V1_TUNNEL_PATH:
            if not ALLOW_V1:
                refuse(
                    conn, "426 Upgrade Required", "v1 shell tunnel disabled by cutover"
                )
                return
            q = _shell
        elif path == GPU_PATH:
            q = _gpu
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
        conn.sendall(
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n"
        )
        conn.settimeout(None)
        log(f"host tunnel attached from {addr} path {path}")
        q.put(conn, timeout=120)
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


def pump(a: socket.socket, b: socket.socket) -> None:
    """Relay bytes both ways until either side closes."""

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

    t = threading.Thread(target=copy, args=(a, b, "host->peer"), daemon=True)
    t.start()
    copy(b, a, "peer->host")
    t.join(timeout=5)
    for s in (a, b):
        with contextlib.suppress(OSError):
            s.close()
    log("pair closed")


def pair(
    conn: socket.socket,
    q: queue.Queue[socket.socket],
    label: str,
    wait: int,
) -> None:
    """Pair one incoming connection with the oldest live tunnel in ``q``."""
    try:
        log(f"{label} attached from {conn.getpeername()}")
        while True:
            nb = q.get(timeout=wait)
            if alive(nb):
                break
            log(f"discarding stale {label} tunnel")
            with contextlib.suppress(OSError):
                nb.close()
        log(f"pairing {label} with a host")
        # Both legs are unbounded once paired: a session may sit idle for
        # hours, and a socket timeout left armed on either side would tear
        # the pair down without anyone noticing.
        conn.settimeout(None)
        nb.settimeout(None)
        pump(nb, conn)
    except queue.Empty:
        log(f"{label} connected but no {label} tunnel within {wait}s")
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
    """Pair one operator connection with the host it asked for."""
    host = read_host_label(conn)
    if not host or not valid_host(host):
        log(f"operator from {addr[0]}:{addr[1]} sent invalid host label; refusing")
        with contextlib.suppress(OSError):
            conn.close()
        return
    pair(conn, host_queue(host), f"operator-v2[{host}]", 120)


def relay_conn(conn: socket.socket, addr: tuple[str, int]) -> None:
    """Pair one public relay connection with the oldest /__relay/gpu tunnel."""
    port = conn.getsockname()[1]
    pair(conn, _gpu, f"gpu-public:{port}", 20)


def serve(
    listen: tuple[str, int],
    handler: Callable[[socket.socket, tuple[str, int]], None],
    name: str,
) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(listen)
        srv.listen(64)
    except OSError as exc:
        log(f"{name} bind {listen[0]}:{listen[1]} failed: {exc}")
        srv.close()
        return
    log(f"{name} listening on {listen[0]}:{listen[1]}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handler, args=(conn, addr), daemon=True).start()


def gpu_ports() -> tuple[int, ...]:
    """Return the public relay ports, expanding a ``first-last`` range."""
    out: list[int] = []
    for item in os.environ.get("MOESH_BRIDGE_GPU_PORTS", "26420-26430").split(","):
        item = item.strip()
        if not item:
            continue
        if "-" in item:
            first, _, last = item.partition("-")
            out.extend(range(int(first), int(last) + 1))
        else:
            out.append(int(item))
    return tuple(out)


if __name__ == "__main__":
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
        threading.Thread(
            target=serve,
            args=((GPU_RELAY_HOST, port), relay_conn, f"gpu-relay-{port}"),
            daemon=True,
        ).start()
    # No listener owns the main thread: a bind conflict on one port must not
    # take down the other ten. SIGTERM still ends the process.
    threading.Event().wait()
