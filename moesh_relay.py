#!/usr/bin/env python3
"""moesh_relay — Zero-dependency outbound TCP reverse tunnel client.

Exposes an inbound service on an accelerator machine (vLLM, Lemonade, GPU runner,
embedding generator) back to the receiver machine without requiring frpc/frps,
SSH, root privileges, or incoming open firewall ports.

How it works:
1. Dials outbound to the receiver's port 80 with an HTTP/1.1 Upgrade on `/__relay/<service>`.
2. The receiver bridge (moesh-bridge.py) answers 101 and queues the raw socket pipe.
3. When any client connects to the mapped port on the receiver (e.g. :26429 for vllm),
   the bridge pairs the incoming connection with this worker.
4. This worker connects to the local service on loopback (--target 127.0.0.1:8001)
   and splices raw bytes bi-directionally until closed.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import os
import socket
import threading
import time
from urllib.parse import urlsplit

DEFAULT_RECEIVER = os.environ.get("MOESH_RELAY_RECEIVER", "")
DEFAULT_RECEIVER_PORT = int(os.environ.get("MOESH_RELAY_PORT", "80"))
DEFAULT_TARGET = os.environ.get("MOESH_RELAY_TARGET", "127.0.0.1:8001")
DEFAULT_WORKERS = int(os.environ.get("MOESH_RELAY_WORKERS", "4"))
DEFAULT_IDLE = int(os.environ.get("MOESH_RELAY_IDLE", "900"))

_log_lock = threading.Lock()


def log(msg: str) -> None:
    """Write timestamped log message to stdout."""
    with _log_lock:
        print(f"{time.strftime('%H:%M:%S')} [relay] {msg}", flush=True)


def read_headers(sock: socket.socket) -> bytes:
    """Read bytes through the end of the HTTP header block."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("closed during upgrade handshake")
        buf += chunk
        if len(buf) > 65536:
            raise ConnectionError("header block exceeded 64KB")
    return buf


def splice(a: socket.socket, b: socket.socket) -> None:
    """Pump bytes bidirectionally between sockets a and b until EOF."""

    def copy(src: socket.socket, dst: socket.socket) -> None:
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

    t = threading.Thread(target=copy, args=(a, b), daemon=True)
    t.start()
    copy(b, a)
    t.join(timeout=5)
    for s in (a, b):
        with contextlib.suppress(OSError):
            s.close()


def connect_tunnel(host: str, port: int, path: str) -> socket.socket:
    """Dial receiver and perform HTTP/1.1 Upgrade to enter raw pipe mode."""
    sock = socket.create_connection((host, port), timeout=20)
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode()
    sock.sendall(req)
    headers = read_headers(sock)
    if not headers.startswith(b"HTTP/1.1 101"):
        first_line = headers.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        sock.close()
        raise ConnectionError(f"upgrade refused by receiver: {first_line}")
    return sock


def worker(
    index: int,
    host: str,
    port: int,
    path: str,
    target_host: str,
    target_port: int,
    idle: int,
) -> None:
    """Worker maintaining one queued tunnel at a time and forwarding active sessions."""
    while True:
        sock = None
        try:
            sock = connect_tunnel(host, port, path)
            sock.settimeout(idle)
            # Wait for peer bytes when receiver pairs this socket
            first = sock.recv(65536)
            if not first:
                raise ConnectionError("paired then immediately closed before data")
            sock.settimeout(None)

            try:
                target = socket.create_connection((target_host, target_port), timeout=10)
            except OSError as err:
                log(f"worker {index}: target {target_host}:{target_port} refused: {err}")
                sock.close()
                time.sleep(1)
                continue

            target.sendall(first)
            log(f"worker {index}: session active -> {target_host}:{target_port}")
            splice(sock, target)
            log(f"worker {index}: session finished")
        except TimeoutError:
            # Idle timeout without peer — redial fresh socket to keep queue alive
            if sock:
                with contextlib.suppress(OSError):
                    sock.close()
        except Exception:
            if sock:
                with contextlib.suppress(OSError):
                    sock.close()
            time.sleep(2)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="moesh outbound reverse relay for accelerator services"
    )
    ap.add_argument(
        "--service",
        default=os.environ.get("MOESH_RELAY_SERVICE", "gpu"),
        help="Service name (e.g. vllm, gpu, embed, qwen, lemonade)",
    )
    ap.add_argument(
        "--receiver",
        default=DEFAULT_RECEIVER,
        help="Receiver host (or set MOESH_RELAY_RECEIVER)",
    )
    ap.add_argument(
        "--port",
        type=int,
        default=DEFAULT_RECEIVER_PORT,
        help="Receiver HTTP port (default 80)",
    )
    ap.add_argument(
        "--url",
        default="",
        help="Full URL override (e.g. http://receiver.example.com/__relay/vllm)",
    )
    ap.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help="Target service on this accelerator machine (default 127.0.0.1:8001)",
    )
    ap.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help="Number of concurrent queued connections (default 4)",
    )
    ap.add_argument(
        "--idle",
        type=int,
        default=DEFAULT_IDLE,
        help="Idle timeout in seconds before refreshing tunnel (default 900)",
    )

    args = ap.parse_args(argv)

    if args.url:
        parts = urlsplit(args.url)
        host = parts.hostname or DEFAULT_RECEIVER
        port = parts.port or 80
        path = parts.path
    else:
        host = args.receiver
        port = args.port
        path = f"/__relay/{args.service.strip('/')}"

    if not host:
        ap.error("no receiver specified: provide --receiver or set MOESH_RELAY_RECEIVER")

    target_host, _, target_port_s = args.target.rpartition(":")
    if not target_host:
        target_host = "127.0.0.1"
    target_port = int(target_port_s)
    workers = max(1, args.workers)

    log(
        f"starting relay: service={args.service!r} path={path} "
        f"-> local {target_host}:{target_port} ({workers} workers) via {host}:{port}"
    )

    for i in range(workers):
        threading.Thread(
            target=worker,
            args=(i, host, port, path, target_host, target_port, args.idle),
            daemon=True,
        ).start()

    while True:
        time.sleep(3600)


if __name__ == "__main__":
    raise SystemExit(main())
