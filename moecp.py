#!/usr/bin/env python3
# moecp — secure file copy utility for moesh
# Pure Python, standard library + noiseprotocol/cryptography.
"""Secure remote file copy command mirroring scp over the moesh encrypted transport.

Copies files and directory trees between the local machine and remote agent hosts
connected to moesh. All transfers run inside an isolated, dedicated Noise_XX session
(fresh_session=True) so active interactive operator shells are never disturbed.

Usage:
    moecp [options] [[host:]src] ... [[host:]dst]

Examples:
    # Upload local file to remote host-3
    moecp local.txt host-3:/tmp/local.txt

    # Upload using -n host shortcut
    moecp -n 3 local.txt remote:/tmp/local.txt

    # Download remote file to local directory
    moecp host-3:/tmp/remote.txt ./local.txt

    # Recursively upload directory preserving permissions
    moecp -r -p ./models host-3:/opt/models
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import dataclasses
import hashlib
import json
import os
import select
import shutil
import socket
import sqlite3
import stat
import struct
import sys
import time
import zlib
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from collections.abc import Callable

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from moesh_proto import (
    MAX_DATA_PAYLOAD,
    Channel,
    Msg,
    NegotiationError,
    NoiseSession,
    ProtocolError,
    SecureChannel,
    SessionState,
    State,
    TransportEOF,
)
from moesh_shell import (
    DEFAULT_ADDR,
    DEFAULT_KEYFILE,
    handshake,
    negotiate,
    pinned_key,
    read_key,
    resolve_name,
)
from moesh_wire import PRELUDE_PREFIX

CHUNK_SIZE: int = 32768
"""Maximum uncompressed chunk size for file transfer streaming (32 KiB)."""

MAX_FRAME_HDR: int = 65536
"""Maximum allowed JSON metadata header size in bytes (64 KiB)."""

MAX_FRAME_PAYLOAD: int = 10485760
"""Maximum allowed chunk payload size in bytes (10 MiB)."""

MAGIC_READY: bytes = b"MOECP_READY_V1\n"
"""Handshake token emitted by the remote bootstrap worker once in raw mode."""

# ─────────────────────────────────────────────────────────────────────────────
# Remote Bootstrap Worker Code
# ─────────────────────────────────────────────────────────────────────────────
# This script is executed directly on the remote host via `exec python3 -u -c ...`
# on the dedicated PTY child. It turns off echo/line discipline and communicates
# in framed binary packets with the local moecp client.

_WORKER_CODE = """
import os, sys, struct, json, zlib, hashlib, stat, time

def set_raw():
    try:
        import termios
        fd = sys.stdin.fileno()
        mode = termios.tcgetattr(fd)
        mode[0] = 0
        mode[1] = 0
        mode[2] |= termios.CS8
        mode[3] &= ~(termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG | termios.IEXTEN)
        mode[6][termios.VMIN] = 1
        mode[6][termios.VTIME] = 0
        termios.tcsetattr(fd, termios.TCSADRAIN, mode)
    except Exception:
        pass

def read_exact(n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sys.stdin.buffer.read(n - len(buf))
        if not chunk:
            raise EOFError("stdin closed prematurely")
        buf.extend(chunk)
    return bytes(buf)

def send_frame(meta, payload=b""):
    hdr = json.dumps(meta).encode("utf-8")
    frame = struct.pack(">II", len(hdr), len(payload)) + hdr + payload
    sys.stdout.buffer.write(frame)
    sys.stdout.buffer.flush()

def recv_frame():
    hdr_len_b = read_exact(8)
    hlen, dlen = struct.unpack(">II", hdr_len_b)
    if hlen > 65536 or dlen > 10485760:
        raise ValueError(f"frame length bounds exceeded: hdr={hlen}, data={dlen}")
    meta = json.loads(read_exact(hlen).decode("utf-8"))
    payload = read_exact(dlen) if dlen > 0 else b""
    return meta, payload

def sanitize_relpath(path):
    if not path or "\\0" in path:
        raise ValueError(f"invalid path: {path!r}")
    if path.startswith("/") or path.startswith("\\\\"):
        raise ValueError(f"absolute path not allowed: {path!r}")
    normalized = os.path.normpath(path).replace("\\\\", "/").lstrip("/")
    parts = [p for p in normalized.split("/") if p and p != "."]
    if not parts or any(p == ".." for p in parts):
        raise ValueError(f"insecure path traversal: {path!r}")
    return "/".join(parts)

def run():
    set_raw()
    sys.stdout.buffer.write(b"MOECP_READY_V1\\n")
    sys.stdout.buffer.flush()

    meta, _ = recv_frame()
    direction = meta.get("direction")
    preserve = meta.get("preserve", False)

    if direction == "PUSH":
        target = os.path.expanduser(meta.get("target", "."))
        is_dir_upload = meta.get("is_dir", False)
        dest_is_dir = os.path.isdir(target)
        if is_dir_upload:
            os.makedirs(target, exist_ok=True)
        send_frame({"status": "OK", "target_is_dir": dest_is_dir})

        while True:
            msg, payload = recv_frame()
            op = msg.get("op")
            if op == "DONE":
                send_frame({"status": "DONE"})
                break
            if op != "FILE_START":
                send_frame({"status": "ERROR", "message": f"unexpected op: {op}"})
                return 1

            raw_rel = msg.get("rel_path", "")
            try:
                rel = sanitize_relpath(raw_rel)
            except ValueError as e:
                send_frame({"status": "ERROR", "message": str(e)})
                return 1

            target_abs = os.path.abspath(target)
            if is_dir_upload:
                dest_file = os.path.abspath(os.path.join(target, rel))
            elif dest_is_dir:
                dest_file = os.path.abspath(os.path.join(target, os.path.basename(rel)))
            else:
                dest_file = target_abs

            try:
                if os.path.commonpath([target_abs, dest_file]) != target_abs and dest_file != target_abs:
                    send_frame({"status": "ERROR", "message": f"path escapes target directory: {dest_file}"})
                    return 1
            except ValueError:
                send_frame({"status": "ERROR", "message": f"invalid target path: {dest_file}"})
                return 1

            size = msg.get("size", 0)
            mode = msg.get("mode", 0o644)
            mtime = msg.get("mtime", time.time())
            expected_sha = msg.get("sha256", "")

            dest_dir = os.path.dirname(dest_file) or "."
            os.makedirs(dest_dir, exist_ok=True)
            tmp_file = dest_file + ".part." + str(os.getpid())
            hasher = hashlib.sha256()

            try:
                with open(tmp_file, "wb") as f:
                    send_frame({"status": "READY"})
                    while True:
                        cmsg, cdata = recv_frame()
                        cop = cmsg.get("op")
                        if cop == "CHUNK":
                            enc = cmsg.get("encoding", "zlib")
                            if enc == "zlib":
                                raw = zlib.decompress(cdata)
                            elif enc == "raw":
                                raw = cdata
                            else:
                                raise ValueError(f"unsupported chunk encoding: {enc}")
                            f.write(raw)
                            hasher.update(raw)
                        elif cop == "FILE_END":
                            break
                        else:
                            send_frame({"status": "ERROR", "message": f"unexpected chunk op: {cop}"})
                            if os.path.exists(tmp_file):
                                os.remove(tmp_file)
                            return 1

                actual_sha = hasher.hexdigest()
                if not expected_sha or actual_sha != expected_sha:
                    if os.path.exists(tmp_file):
                        os.remove(tmp_file)
                    send_frame({"status": "ERROR", "message": f"checksum mismatch: {actual_sha} vs {expected_sha}"})
                    return 1

                os.replace(tmp_file, dest_file)

                if preserve:
                    try:
                        os.chmod(dest_file, stat.S_IMODE(mode))
                        os.utime(dest_file, (mtime, mtime))
                    except Exception:
                        pass

                send_frame({"status": "OK", "sha256": actual_sha})
            except Exception as e:
                if os.path.exists(tmp_file):
                    try:
                        os.remove(tmp_file)
                    except Exception:
                        pass
                send_frame({"status": "ERROR", "message": str(e)})
                return 1

    elif direction == "PULL":
        source = os.path.expanduser(meta.get("source", "."))
        recursive = meta.get("recursive", False)
        compression = meta.get("compression", "auto")

        if not os.path.exists(source):
            send_frame({"status": "ERROR", "message": f"{source}: No such file or directory"})
            return 1

        is_dir = os.path.isdir(source)
        if is_dir and not recursive:
            send_frame({"status": "ERROR", "message": f"{source}: Is a directory (not copied, use -r)"})
            return 1

        file_list = []
        if is_dir:
            base_dir = source.rstrip("/")
            for root, _, files in os.walk(base_dir):
                for fname in files:
                    full = os.path.join(root, fname)
                    with contextlib.suppress(Exception):
                        rel = sanitize_relpath(os.path.relpath(full, base_dir))
                        st = os.stat(full)
                        file_list.append({"rel": rel, "full": full, "size": st.st_size, "mode": st.st_mode, "mtime": st.st_mtime})
        else:
            try:
                st = os.stat(source)
                rel = sanitize_relpath(os.path.basename(source))
                file_list.append({"rel": rel, "full": source, "size": st.st_size, "mode": st.st_mode, "mtime": st.st_mtime})
            except Exception as e:
                send_frame({"status": "ERROR", "message": str(e)})
                return 1

        send_frame({"status": "OK", "is_dir": is_dir, "files": [{"rel": f["rel"], "size": f["size"], "mode": f["mode"], "mtime": f["mtime"]} for f in file_list]})

        file_map = {f["rel"]: f for f in file_list}
        file_iter = iter(file_list)
        while True:
            req, _ = recv_frame()
            op = req.get("op")
            if op == "DONE":
                send_frame({"status": "DONE"})
                break
            if op != "PULL_FILE":
                send_frame({"status": "ERROR", "message": f"expected PULL_FILE, got {op}"})
                return 1

            rel_req = req.get("rel")
            if rel_req and rel_req in file_map:
                item = file_map[rel_req]
            else:
                try:
                    item = next(file_iter)
                except StopIteration:
                    send_frame({"status": "ERROR", "message": "no more files in manifest"})
                    return 1

            full_path = item["full"]
            offset = int(req.get("offset", 0))
            if offset < 0 or offset > item["size"]:
                offset = 0

            hasher = hashlib.sha256()
            try:
                with open(full_path, "rb") as f:
                    if offset > 0:
                        while f.tell() < offset:
                            to_read = min(32768, offset - f.tell())
                            pbuf = f.read(to_read)
                            if not pbuf:
                                break
                            hasher.update(pbuf)
                        f.seek(offset)
                    while True:
                        buf = f.read(32768)
                        if not buf:
                            break
                        hasher.update(buf)
                        if compression == "raw":
                            send_frame({"op": "CHUNK", "encoding": "raw"}, buf)
                        elif compression == "zlib":
                            cdata = zlib.compress(buf, 6)
                            send_frame({"op": "CHUNK", "encoding": "zlib"}, cdata)
                        else:  # auto
                            if len(buf) > 1024:
                                cdata = zlib.compress(buf, 6)
                                if len(cdata) < len(buf):
                                    send_frame({"op": "CHUNK", "encoding": "zlib"}, cdata)
                                else:
                                    send_frame({"op": "CHUNK", "encoding": "raw"}, buf)
                            else:
                                send_frame({"op": "CHUNK", "encoding": "raw"}, buf)
                sha = hasher.hexdigest()
                send_frame({"op": "FILE_END", "sha256": sha})
                ack, _ = recv_frame()
                if ack.get("status") != "OK":
                    return 1
            except Exception as e:
                send_frame({"status": "ERROR", "message": str(e)})
                return 1

    return 0

if __name__ == "__main__":
    sys.exit(run())
"""

def generate_bootstrap_cmd() -> bytes:
    """Generate the compact exec command string to start the remote worker.

    Returns:
        Encoded bytes command ready to be sent to the remote shell.
    """
    compressed = zlib.compress(_WORKER_CODE.strip().encode("utf-8"), 9)
    b64 = base64.b64encode(compressed).decode("ascii")
    script = f"exec python3 -u -c \"import zlib,base64;exec(zlib.decompress(base64.b64decode('{b64}')))\"\n"
    return script.encode("utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# Path Parsing & Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclasses.dataclass(frozen=True)
class PathSpec:
    """Parsed path specification representing either local or remote targets."""

    is_remote: bool
    host: str
    path: str


@dataclasses.dataclass
class TransferSummary:
    """Summary metrics of a batch file transfer operation."""

    total: int = 0
    succeeded: int = 0
    failed: int = 0
    skipped: int = 0

    def print_summary(self) -> None:
        """Write concise summary line to stderr."""
        sys.stderr.write(
            f"moecp: transfer summary: {self.total} total, "
            f"{self.succeeded} succeeded, {self.failed} failed, {self.skipped} skipped\n"
        )


def sanitize_relpath(path: str) -> str:
    """Sanitize and validate a relative path against directory traversal.

    Rejects paths containing:
      - Embedded null bytes
      - Path traversal components ('..')
      - Empty components resolving outside target

    Args:
        path: Path string from incoming frame or local manifest.

    Returns:
        Clean normalized relative path safe for filesystem joining.

    Raises:
        ValueError: If path attempts directory traversal or contains invalid characters.
    """
    if not path or "\0" in path:
        raise ValueError(f"invalid path: {path!r}")
    if path.startswith("/") or path.startswith("\\"):
        raise ValueError(f"absolute path not allowed: {path!r}")
    normalized = os.path.normpath(path).replace("\\", "/").lstrip("/")
    parts = [p for p in normalized.split("/") if p and p != "."]
    if not parts or any(p == ".." for p in parts):
        raise ValueError(f"insecure path traversal detected: {path!r}")
    return "/".join(parts)


def parse_path_spec(spec: str, default_host: str = "") -> PathSpec:
    """Parse a command-line path specification into a local or remote target.

    Supports formats:
        - `host-3:/path/to/file` -> remote host-3
        - `3:/path/to/file` -> remote host-3
        - `remote:/path/to/file` -> remote default_host
        - `/path/to/local` -> local path

    Args:
        spec: Raw string argument from command line.
        default_host: Fallback host name when specified via `-n`.

    Returns:
        PathSpec dataclass detailing location and resolved host.
    """
    if ":" in spec:
        slash_idx = spec.find("/")
        colon_idx = spec.find(":")
        if slash_idx != -1 and slash_idx < colon_idx:
            # Slashes precede colon: local path containing a colon (e.g. ./a:b or /path/foo:bar)
            return PathSpec(is_remote=False, host="", path=spec)

        host_part, _, path_part = spec.partition(":")
        if not path_part:
            path_part = "."
        if host_part.lower() == "remote":
            host = default_host or "host-1"
        elif host_part.isdigit():
            host = f"host-{host_part}"
        else:
            host = resolve_name(host_part)
        return PathSpec(is_remote=True, host=host, path=path_part)

    if default_host and (spec.startswith("~") or spec.startswith("/") or spec.startswith("./")):
        # Ambiguous path when default_host is set: treated as local unless explicit remote prefix used
        pass

    return PathSpec(is_remote=False, host="", path=spec)


# ─────────────────────────────────────────────────────────────────────────────
# Transport & Framed Client Protocol
# ─────────────────────────────────────────────────────────────────────────────

class FramedStreamClient:
    """Framed binary protocol client operating over moesh SecureChannel."""

    def __init__(self, secure: SecureChannel, sock: socket.socket) -> None:
        """Initialize client on top of active SecureChannel.

        Args:
            secure: Established SecureChannel authenticated via Noise_XX.
            sock: Underlying network socket.
        """
        self.secure = secure
        self.sock = sock
        self._buf = bytearray()

    def send_frame(self, meta: dict[str, Any], payload: bytes = b"") -> None:
        """Send a length-prefixed JSON header with optional payload bytes.

        Args:
            meta: Metadata dictionary encoded to JSON.
            payload: Optional binary payload appended to the frame.
        """
        hdr = json.dumps(meta).encode("utf-8")
        raw = struct.pack(">II", len(hdr), len(payload)) + hdr + payload
        for idx in range(0, len(raw), MAX_DATA_PAYLOAD):
            chunk = raw[idx : idx + MAX_DATA_PAYLOAD]
            self.secure.send(Msg.DATA, chunk)

    def _read_more(self, deadline: float | None = None, timeout: float = 30.0) -> None:
        """Drain incoming data from SecureChannel into buffer.

        Args:
            deadline: Optional absolute monotonic deadline timestamp.
            timeout: Seconds to wait for socket readability before error if deadline not given.

        Raises:
            TimeoutError: If peer fails to respond within timeout or before deadline.
            TransportEOF: If connection is broken.
        """
        if deadline is None:
            deadline = time.monotonic() + timeout
        while True:
            records = self.secure.buffered()
            if records:
                for msg_type, data in records:
                    if msg_type == Msg.DATA:
                        self._buf.extend(data)
                if self._buf:
                    return

            rem = deadline - time.monotonic()
            if rem <= 0:
                raise TimeoutError("timed out waiting for remote response")

            ready, _, _ = select.select([self.sock], [], [], rem)
            if not ready or self.sock not in ready:
                raise TimeoutError("timed out waiting for remote response")

            records = self.secure.drain()
            for msg_type, data in records:
                if msg_type == Msg.DATA:
                    self._buf.extend(data)
            if self._buf:
                return

    def _read_exact(self, n: int, deadline: float | None = None, timeout: float = 30.0) -> bytes:
        """Read exactly n bytes from the accumulated buffer.

        Args:
            n: Number of bytes to consume.
            deadline: Optional absolute monotonic deadline timestamp.
            timeout: Timeout in seconds if deadline is not provided.

        Returns:
            Extracted bytes.
        """
        if deadline is None:
            deadline = time.monotonic() + timeout
        while len(self._buf) < n:
            self._read_more(deadline=deadline)
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def recv_frame(self, timeout: float = 30.0) -> tuple[dict[str, Any], bytes]:
        """Receive one complete framed message.

        Args:
            timeout: Seconds to wait for frame.

        Returns:
            Tuple of (metadata_dict, payload_bytes).
        """
        deadline = time.monotonic() + timeout
        prefix = self._read_exact(8, deadline=deadline)
        hlen, dlen = struct.unpack(">II", prefix)
        if hlen > MAX_FRAME_HDR or dlen > MAX_FRAME_PAYLOAD:
            raise ProtocolError(f"received frame exceeding safety bounds: hdr={hlen}, data={dlen}")
        hdr_bytes = self._read_exact(hlen, deadline=deadline)
        meta = json.loads(hdr_bytes.decode("utf-8"))
        payload = self._read_exact(dlen, deadline=deadline) if dlen > 0 else b""
        return meta, payload

    def wait_for_ready(self, timeout: float = 15.0) -> None:
        """Wait for the remote worker ready banner, discarding initial shell output.

        Args:
            timeout: Maximum seconds to wait for worker banner.

        Raises:
            ProtocolError: If worker fails to initialize within deadline.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            idx = self._buf.find(MAGIC_READY)
            if idx != -1:
                del self._buf[: idx + len(MAGIC_READY)]
                return
            self._read_more(timeout=1.0)
        raise ProtocolError("remote worker failed to send ready token within deadline")


# ─────────────────────────────────────────────────────────────────────────────
# Progress Meter
# ─────────────────────────────────────────────────────────────────────────────

class ProgressMeter:
    """Format and display real-time file transfer progress in terminal."""

    def __init__(self, filename: str, total_bytes: int, quiet: bool = False) -> None:
        """Initialize progress reporter.

        Args:
            filename: Name of file currently transferring.
            total_bytes: Total expected file size in bytes.
            quiet: If True, suppresses output completely.
        """
        self.filename = os.path.basename(filename)
        self.total_bytes = max(1, total_bytes)
        self.transferred = 0
        self.quiet = quiet or not sys.stderr.isatty()
        self.start_time = time.monotonic()

    def update(self, chunk_len: int) -> None:
        """Update transferred byte count and redraw status line.

        Args:
            chunk_len: Additional bytes transferred.
        """
        self.transferred += chunk_len
        if self.quiet:
            return

        pct = min(100, int((self.transferred / self.total_bytes) * 100))
        elapsed = max(0.001, time.monotonic() - self.start_time)
        rate = self.transferred / elapsed / 1024 / 1024  # MB/s

        msg = (
            f"\r{self.filename:<24} {pct:>3}% "
            f"{self.transferred / 1024 / 1024:>6.1f}MB "
            f"{rate:>5.1f}MB/s"
        )
        sys.stderr.write(msg)
        sys.stderr.flush()

    def finish(self) -> None:
        """Cleanly terminate the progress line."""
        if not self.quiet:
            sys.stderr.write("\n")
            sys.stderr.flush()


# ─────────────────────────────────────────────────────────────────────────────
# Core Transfer Operations (Upload & Download)
# ─────────────────────────────────────────────────────────────────────────────

def upload_files(
    client: FramedStreamClient,
    sources: list[str],
    target_spec: PathSpec,
    recursive: bool,
    preserve: bool,
    quiet: bool,
    compression: str = "auto",
    summary: TransferSummary | None = None,
) -> int:
    """Upload local source files to remote destination path.

    Args:
        client: Active FramedStreamClient.
        sources: List of local paths to upload.
        target_spec: Remote destination PathSpec.
        recursive: Whether directory recursion is enabled.
        preserve: Whether permissions and timestamps should be preserved.
        quiet: Whether to suppress progress bars.
        compression: Transfer compression strategy ("auto", "zlib", "raw").
        summary: Optional TransferSummary tracker for batch progress and outcome.

    Returns:
        0 on success, non-zero exit code on failure.
    """
    summary = summary or TransferSummary()

    for src in sources:
        if not os.path.exists(src):
            sys.stderr.write(f"moecp: {src}: No such file or directory\n")
            summary.failed += 1
            summary.print_summary()
            return 1

    is_dir_upload = len(sources) == 1 and os.path.isdir(sources[0])
    if is_dir_upload and not recursive:
        sys.stderr.write(f"moecp: {sources[0]}: Is a directory (not copied, use -r)\n")
        summary.failed += 1
        summary.print_summary()
        return 1

    file_manifest: list[tuple[str, str]] = []  # (abs_path, rel_path)
    if is_dir_upload:
        base = sources[0].rstrip("/")
        for root, _, files in os.walk(base):
            for fname in files:
                full = os.path.join(root, fname)
                try:
                    rel = sanitize_relpath(os.path.relpath(full, base))
                    file_manifest.append((full, rel))
                except (ValueError, OSError):
                    continue
    else:
        for src in sources:
            if os.path.isdir(src):
                if not recursive:
                    sys.stderr.write(f"moecp: {src}: Is a directory (not copied, use -r)\n")
                    summary.failed += 1
                    summary.print_summary()
                    return 1
                base = src.rstrip("/")
                prefix = os.path.basename(base)
                for root, _, files in os.walk(base):
                    for fname in files:
                        full = os.path.join(root, fname)
                        try:
                            rel = sanitize_relpath(os.path.join(prefix, os.path.relpath(full, base)))
                            file_manifest.append((full, rel))
                        except (ValueError, OSError):
                            continue
            else:
                try:
                    rel = sanitize_relpath(os.path.basename(src))
                    file_manifest.append((src, rel))
                except ValueError as err:
                    sys.stderr.write(f"moecp: invalid source filename {src!r}: {err}\n")
                    summary.failed += 1
                    summary.print_summary()
                    return 1

    summary.total = len(file_manifest)

    client.send_frame({
        "op": "INIT",
        "direction": "PUSH",
        "target": target_spec.path,
        "is_dir": is_dir_upload,
        "preserve": preserve,
    })
    init_ack, _ = client.recv_frame()
    if init_ack.get("status") != "OK":
        sys.stderr.write(f"moecp: remote init failed: {init_ack.get('message', 'unknown')}\n")
        summary.failed = summary.total
        summary.print_summary()
        return 1

    for full_path, rel_path in file_manifest:
        st = os.stat(full_path)
        hasher = hashlib.sha256()

        # Compute SHA256 before streaming
        with open(full_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        expected_sha = hasher.hexdigest()

        client.send_frame({
            "op": "FILE_START",
            "rel_path": rel_path,
            "size": st.st_size,
            "mode": st.st_mode,
            "mtime": st.st_mtime,
            "sha256": expected_sha,
        })
        ready_ack, _ = client.recv_frame()
        if ready_ack.get("status") == "COMMITTED":
            meter = ProgressMeter(rel_path, st.st_size, quiet=quiet)
            meter.update(st.st_size)
            meter.finish()
            summary.skipped += 1
            continue
        if ready_ack.get("status") != "READY":
            sys.stderr.write(f"moecp: remote refused file {rel_path}: {ready_ack.get('message')}\n")
            summary.failed += 1
            summary.print_summary()
            return 1

        resume_offset = int(ready_ack.get("offset", 0))
        meter = ProgressMeter(rel_path, st.st_size, quiet=quiet)
        if resume_offset > 0:
            meter.update(resume_offset)
        with open(full_path, "rb") as f:
            if resume_offset > 0:
                f.seek(resume_offset)
            while buf := f.read(CHUNK_SIZE):
                if compression == "raw":
                    client.send_frame({"op": "CHUNK", "encoding": "raw"}, buf)
                elif compression == "zlib":
                    cdata = zlib.compress(buf, 6)
                    client.send_frame({"op": "CHUNK", "encoding": "zlib"}, cdata)
                else:  # auto
                    if len(buf) > 1024:
                        cdata = zlib.compress(buf, 6)
                        if len(cdata) < len(buf):
                            client.send_frame({"op": "CHUNK", "encoding": "zlib"}, cdata)
                        else:
                            client.send_frame({"op": "CHUNK", "encoding": "raw"}, buf)
                    else:
                        client.send_frame({"op": "CHUNK", "encoding": "raw"}, buf)
                meter.update(len(buf))
        meter.finish()

        client.send_frame({"op": "FILE_END"})
        file_ack, _ = client.recv_frame()
        if file_ack.get("status") != "OK":
            sys.stderr.write(f"moecp: remote failed verification for {rel_path}: {file_ack.get('message')}\n")
            summary.failed += 1
            summary.print_summary()
            return 1

        summary.succeeded += 1

    client.send_frame({"op": "DONE"})
    done_ack, _ = client.recv_frame()
    summary.print_summary()
    return 0 if done_ack.get("status") == "DONE" else 1


def download_files(
    client: FramedStreamClient,
    source_spec: PathSpec,
    local_target: str,
    recursive: bool,
    preserve: bool,
    quiet: bool,
    compression: str = "auto",
    summary: TransferSummary | None = None,
) -> int:
    """Download remote source files to local target destination.

    Args:
        client: Active FramedStreamClient.
        source_spec: Remote source PathSpec.
        local_target: Destination directory or file path on local filesystem.
        recursive: Whether directory recursion is enabled.
        preserve: Whether permissions and timestamps should be preserved.
        quiet: Whether to suppress progress bars.
        compression: Transfer compression strategy ("auto", "zlib", "raw").
        summary: Optional TransferSummary tracker for batch progress and outcome.

    Returns:
        0 on success, non-zero exit code on failure.
    """
    summary = summary or TransferSummary()

    ledger_db = os.environ.get(
        "MOECP_CLIENT_LEDGER_PATH",
        os.environ.get(
            "MOECP_LEDGER_PATH",
            os.path.expanduser("~/.local/state/moesh/ledger.db"),
        ),
    )
    ledger = TransferLedger(ledger_db)
    with contextlib.suppress(sqlite3.Error, ValueError):
        ledger.prune_stale_transfers(days=int(os.environ.get("MOECP_LEDGER_TTL_DAYS", "7")))

    client.send_frame({
        "op": "INIT",
        "direction": "PULL",
        "source": source_spec.path,
        "recursive": recursive,
        "preserve": preserve,
        "compression": compression,
    })
    manifest, _ = client.recv_frame()
    if manifest.get("status") != "OK":
        sys.stderr.write(f"moecp: {manifest.get('message', 'remote error')}\n")
        summary.failed = 1
        summary.print_summary()
        return 1

    is_dir = manifest.get("is_dir", False)
    files = manifest.get("files", [])
    summary.total = len(files)
    target_is_dir = os.path.isdir(local_target)

    target_abs = os.path.abspath(local_target)
    if is_dir:
        os.makedirs(target_abs, exist_ok=True)

    for item in files:
        try:
            rel = sanitize_relpath(item["rel"])
        except ValueError as err:
            sys.stderr.write(f"moecp: remote path rejected: {err}\n")
            client.send_frame({"status": "ERROR"})
            summary.failed += 1
            summary.print_summary()
            return 1

        size = item["size"]
        mode = item["mode"]
        mtime = item["mtime"]

        if is_dir:
            dest_file = os.path.abspath(os.path.join(local_target, rel))
        elif target_is_dir:
            dest_file = os.path.abspath(os.path.join(local_target, os.path.basename(rel)))
        else:
            dest_file = target_abs

        try:
            if os.path.commonpath([target_abs, dest_file]) != target_abs and dest_file != target_abs:
                sys.stderr.write(f"moecp: remote path escapes local target: {dest_file}\n")
                client.send_frame({"status": "ERROR"})
                summary.failed += 1
                summary.print_summary()
                return 1
        except ValueError:
            sys.stderr.write(f"moecp: invalid target path: {dest_file}\n")
            client.send_frame({"status": "ERROR"})
            summary.failed += 1
            summary.print_summary()
            return 1

        dest_dir = os.path.dirname(dest_file) or "."
        os.makedirs(dest_dir, exist_ok=True)
        pull_id = hashlib.sha256(f"pull:{dest_file}:{size}:{mtime!r}".encode()).hexdigest()[:16]
        tmp_file = dest_file + f".part.{pull_id}"

        if ledger.is_committed(pull_id) and os.path.exists(dest_file):
            try:
                if os.path.getsize(dest_file) == size:
                    expected_sha = ledger.get_expected_sha256(pull_id)
                    disk_sha = compute_file_sha256(dest_file)
                    if not expected_sha or disk_sha == expected_sha:
                        if not expected_sha:
                            ledger.record_transfer(pull_id, dest_file, size, disk_sha)
                            ledger.mark_committed(pull_id, disk_sha)
                        meter = ProgressMeter(rel, size, quiet=quiet)
                        meter.finish()
                        summary.skipped += 1
                        continue
            except OSError:
                pass

        ledger.record_transfer(pull_id, dest_file, size, "")

        resume_offset = 0
        hasher = hashlib.sha256()
        if os.path.exists(tmp_file):
            range_rows = ledger.get_verified_range_hashes(pull_id)
            if range_rows:
                try:
                    with open(tmp_file, "rb") as rf:
                        for start_off, end_off, expected_chunk_sha in range_rows:
                            if start_off != resume_offset or end_off < start_off:
                                break
                            chunk_len = end_off - start_off
                            disk_bytes = rf.read(chunk_len)
                            if (
                                len(disk_bytes) != chunk_len
                                or hashlib.sha256(disk_bytes).hexdigest() != expected_chunk_sha
                            ):
                                break
                            hasher.update(disk_bytes)
                            resume_offset = end_off
                except OSError:
                    resume_offset = 0
                    hasher = hashlib.sha256()
            ledger.truncate_ranges_after(pull_id, resume_offset)
        else:
            ledger.truncate_ranges_after(pull_id, 0)

        offset = resume_offset
        client.send_frame({"op": "PULL_FILE", "rel": item["rel"], "offset": offset})

        meter = ProgressMeter(rel, size, quiet=quiet)
        if offset > 0:
            meter.update(offset)

        open_mode = "r+b" if offset > 0 else "wb"
        try:
            with open(tmp_file, open_mode) as f:
                if offset > 0:
                    f.seek(offset)
                    f.truncate(offset)
                while True:
                    cmsg, cdata = client.recv_frame()
                    cop = cmsg.get("op")
                    if cop == "CHUNK":
                        enc = cmsg.get("encoding", "zlib")
                        if enc == "zlib":
                            raw = zlib.decompress(cdata)
                        elif enc == "raw":
                            raw = cdata
                        else:
                            raise ValueError(f"unsupported chunk encoding: {enc}")
                        f.write(raw)
                        f.flush()
                        hasher.update(raw)
                        chunk_sha = hashlib.sha256(raw).hexdigest()
                        ledger.record_range(pull_id, offset, offset + len(raw), chunk_sha)
                        offset += len(raw)
                        meter.update(len(raw))
                    elif cop == "FILE_END":
                        expected_sha = cmsg.get("sha256", "")
                        meter.finish()
                        break
                    else:
                        sys.stderr.write(f"moecp: unexpected chunk op: {cop}\n")
                        if os.path.exists(tmp_file):
                            os.remove(tmp_file)
                        ledger.clear_ranges(pull_id)
                        summary.failed += 1
                        summary.print_summary()
                        return 1

                f.flush()
                os.fsync(f.fileno())

            actual_sha = hasher.hexdigest()
            if not expected_sha or actual_sha != expected_sha:
                if os.path.exists(tmp_file):
                    os.remove(tmp_file)
                ledger.clear_ranges(pull_id)
                sys.stderr.write(f"moecp: integrity failure on {rel}: {actual_sha} vs {expected_sha}\n")
                client.send_frame({"status": "ERROR"})
                summary.failed += 1
                summary.print_summary()
                return 1

            os.replace(tmp_file, dest_file)
            ledger.mark_committed(pull_id, actual_sha)
            ledger.purge_committed_ranges(pull_id)

            if preserve:
                with contextlib.suppress(Exception):
                    os.chmod(dest_file, stat.S_IMODE(mode))
                    os.utime(dest_file, (mtime, mtime))

            client.send_frame({"status": "OK"})
            summary.succeeded += 1
        except (TransportEOF, TimeoutError, OSError):
            # Preserve staging file for resumption on reconnect
            summary.failed += 1
            summary.print_summary()
            raise
        except Exception as e:
            if os.path.exists(tmp_file):
                with contextlib.suppress(Exception):
                    os.remove(tmp_file)
            sys.stderr.write(f"moecp: download failed for {rel}: {e}\n")
            client.send_frame({"status": "ERROR"})
            summary.failed += 1
            summary.print_summary()
            return 1

    client.send_frame({"op": "DONE"})
    done_ack, _ = client.recv_frame()
    summary.print_summary()
    return 0 if done_ack.get("status") == "DONE" else 1


# ─────────────────────────────────────────────────────────────────────────────
# Durable Ledger & Native Agent Transfer Handler
# ─────────────────────────────────────────────────────────────────────────────


def compute_file_sha256(path: str, block_size: int = 65536) -> str:
    """Compute SHA-256 digest of a local file in fixed blocks.

    Args:
        path: Path to the local file.
        block_size: Size of each read block in bytes.

    Returns:
        Hex-encoded SHA-256 digest string.

    Raises:
        OSError: If reading the file fails.
    """
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(block_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


class TransferLedger:
    """SQLite-backed transactional ledger for crash-consistent resumable transfers."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        parent = os.path.dirname(os.path.abspath(self.db_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA auto_vacuum = INCREMENTAL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS transfers (
                    transfer_id TEXT PRIMARY KEY,
                    rel_path TEXT,
                    total_size INTEGER,
                    expected_sha256 TEXT,
                    committed INTEGER DEFAULT 0,
                    updated_at REAL DEFAULT 0
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS verified_ranges (
                    transfer_id TEXT,
                    start_offset INTEGER,
                    end_offset INTEGER,
                    sha256 TEXT,
                    PRIMARY KEY (transfer_id, start_offset)
                );
            """)
            with contextlib.suppress(sqlite3.OperationalError):
                conn.execute("ALTER TABLE transfers ADD COLUMN updated_at REAL DEFAULT 0;")

    def record_transfer(
        self,
        transfer_id: str,
        rel_path: str,
        total_size: int,
        expected_sha256: str,
        updated_at: float | None = None,
    ) -> None:
        ts = time.time() if updated_at is None else updated_at
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO transfers (transfer_id, rel_path, total_size, expected_sha256, committed, updated_at) VALUES (?, ?, ?, ?, 0, ?)",
                (transfer_id, rel_path, total_size, expected_sha256, ts),
            )

    def record_range(
        self,
        transfer_id: str,
        start: int,
        end: int,
        sha256: str,
    ) -> None:
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO verified_ranges (transfer_id, start_offset, end_offset, sha256) VALUES (?, ?, ?, ?)",
                (transfer_id, start, end, sha256),
            )
            conn.execute(
                "UPDATE transfers SET updated_at=? WHERE transfer_id=?",
                (time.time(), transfer_id),
            )

    def mark_committed(self, transfer_id: str, sha256: str | None = None) -> None:
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            if sha256:
                conn.execute(
                    "UPDATE transfers SET committed=1, expected_sha256=?, updated_at=? WHERE transfer_id=?",
                    (sha256, time.time(), transfer_id),
                )
            else:
                conn.execute(
                    "UPDATE transfers SET committed=1, updated_at=? WHERE transfer_id=?",
                    (time.time(), transfer_id),
                )

    def get_expected_sha256(self, transfer_id: str) -> str:
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            cur = conn.execute(
                "SELECT expected_sha256 FROM transfers WHERE transfer_id=?",
                (transfer_id,),
            )
            row = cur.fetchone()
            return str(row[0]) if row and row[0] else ""

    def get_verified_ranges(self, transfer_id: str) -> list[tuple[int, int]]:
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            cur = conn.execute(
                "SELECT start_offset, end_offset FROM verified_ranges WHERE transfer_id=? ORDER BY start_offset",
                (transfer_id,),
            )
            return cur.fetchall()

    def get_verified_range_hashes(self, transfer_id: str) -> list[tuple[int, int, str]]:
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            cur = conn.execute(
                "SELECT start_offset, end_offset, sha256 FROM verified_ranges WHERE transfer_id=? ORDER BY start_offset",
                (transfer_id,),
            )
            return cur.fetchall()

    def clear_ranges(self, transfer_id: str) -> None:
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute(
                "DELETE FROM verified_ranges WHERE transfer_id=?",
                (transfer_id,),
            )

    def truncate_ranges_after(self, transfer_id: str, offset: int) -> None:
        """Purge chunk ranges starting at or after offset upon verification fault."""
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute(
                "DELETE FROM verified_ranges WHERE transfer_id=? AND start_offset >= ?",
                (transfer_id, offset),
            )

    def purge_committed_ranges(self, transfer_id: str) -> None:
        """Purge chunk ranges for a committed transfer to prevent unbounded ledger growth."""
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute(
                "DELETE FROM verified_ranges WHERE transfer_id=?",
                (transfer_id,),
            )
            with contextlib.suppress(sqlite3.Error):
                conn.execute("PRAGMA incremental_vacuum;")

    def prune_stale_transfers(self, days: int = 7) -> int:
        """Purge uncommitted transfers and orphaned chunk ranges older than TTL days."""
        cutoff = time.time() - (days * 86400.0)
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            cur = conn.execute(
                "SELECT transfer_id, rel_path FROM transfers WHERE committed=0 AND updated_at < ?",
                (cutoff,),
            )
            stale_rows = cur.fetchall()
            if not stale_rows:
                return 0
            for tid, rel_path in stale_rows:
                if rel_path:
                    part_file = f"{rel_path}.part.{tid}"
                    with contextlib.suppress(OSError):
                        if os.path.exists(part_file):
                            os.unlink(part_file)
                conn.execute("DELETE FROM verified_ranges WHERE transfer_id=?", (tid,))
                conn.execute("DELETE FROM transfers WHERE transfer_id=?", (tid,))
            with contextlib.suppress(sqlite3.Error):
                conn.execute("PRAGMA incremental_vacuum;")
            return len(stale_rows)

    def is_committed(self, transfer_id: str) -> bool:
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            cur = conn.execute(
                "SELECT committed FROM transfers WHERE transfer_id=?",
                (transfer_id,),
            )
            row = cur.fetchone()
            return bool(row and row[0] == 1)


def run_native_agent_transfer(
    sock: socket.socket,
    secure: SecureChannel,
    accepted: dict[str, Any],
) -> None:
    """Serve a native file transfer session over SecureChannel directly inside agent."""
    client = FramedStreamClient(secure, sock)
    meta, _ = client.recv_frame()
    direction = meta.get("direction")
    preserve = meta.get("preserve", False)

    ledger_db = os.environ.get(
        "MOECP_LEDGER_PATH",
        os.path.expanduser("~/.local/state/moesh/ledger.db"),
    )
    ledger = TransferLedger(ledger_db)
    with contextlib.suppress(sqlite3.Error, ValueError):
        ledger.prune_stale_transfers(days=int(os.environ.get("MOECP_LEDGER_TTL_DAYS", "7")))

    if direction == "PUSH":
        target = os.path.expanduser(meta.get("target", "."))
        is_dir_upload = meta.get("is_dir", False)
        dest_is_dir = os.path.isdir(target)
        if is_dir_upload:
            os.makedirs(target, exist_ok=True)
        client.send_frame({"status": "OK", "target_is_dir": dest_is_dir})

        while True:
            msg, _payload = client.recv_frame()
            op = msg.get("op")
            if op == "DONE":
                client.send_frame({"status": "DONE"})
                break
            if op != "FILE_START":
                client.send_frame({"status": "ERROR", "message": f"unexpected op: {op}"})
                return

            raw_rel = msg.get("rel_path", "")
            try:
                rel = sanitize_relpath(raw_rel)
            except ValueError as e:
                client.send_frame({"status": "ERROR", "message": str(e)})
                return

            target_abs = os.path.abspath(target)
            if is_dir_upload:
                dest_file = os.path.abspath(os.path.join(target, rel))
            elif dest_is_dir:
                dest_file = os.path.abspath(os.path.join(target, os.path.basename(rel)))
            else:
                dest_file = target_abs

            try:
                if os.path.commonpath([target_abs, dest_file]) != target_abs and dest_file != target_abs:
                    client.send_frame({"status": "ERROR", "message": f"path escapes target directory: {dest_file}"})
                    return
            except ValueError:
                client.send_frame({"status": "ERROR", "message": f"invalid target path: {dest_file}"})
                return

            size = msg.get("size", 0)
            mode = msg.get("mode", 0o644)
            mtime = msg.get("mtime", time.time())
            expected_sha = msg.get("sha256", "")
            transfer_id = hashlib.sha256(f"{dest_file}:{size}:{expected_sha}".encode()).hexdigest()[:16]

            if ledger.is_committed(transfer_id) and os.path.exists(dest_file):
                try:
                    if (
                        os.path.getsize(dest_file) == size
                        and compute_file_sha256(dest_file) == expected_sha
                    ):
                        client.send_frame({"status": "COMMITTED", "sha256": expected_sha})
                        continue
                except OSError:
                    pass

            ledger.record_transfer(transfer_id, dest_file, size, expected_sha)

            dest_dir = os.path.dirname(dest_file) or "."
            os.makedirs(dest_dir, exist_ok=True)
            tmp_file = dest_file + f".part.{transfer_id}"
            hasher = hashlib.sha256()

            resume_offset = 0
            if os.path.exists(tmp_file):
                range_rows = ledger.get_verified_range_hashes(transfer_id)
                if range_rows:
                    try:
                        with open(tmp_file, "rb") as rf:
                            for start_off, end_off, expected_chunk_sha in range_rows:
                                if start_off != resume_offset or end_off < start_off:
                                    break
                                chunk_len = end_off - start_off
                                disk_bytes = rf.read(chunk_len)
                                if (
                                    len(disk_bytes) != chunk_len
                                    or hashlib.sha256(disk_bytes).hexdigest() != expected_chunk_sha
                                ):
                                    break
                                hasher.update(disk_bytes)
                                resume_offset = end_off
                    except OSError:
                        resume_offset = 0
                        hasher = hashlib.sha256()
                ledger.truncate_ranges_after(transfer_id, resume_offset)
            else:
                ledger.truncate_ranges_after(transfer_id, 0)

            open_mode = "r+b" if resume_offset > 0 else "wb"
            try:
                with open(tmp_file, open_mode) as f:
                    if resume_offset > 0:
                        f.seek(resume_offset)
                        f.truncate(resume_offset)
                    client.send_frame(
                        {"status": "READY", "transfer_id": transfer_id, "offset": resume_offset}
                    )
                    offset = resume_offset
                    while True:
                        cmsg, cdata = client.recv_frame()
                        cop = cmsg.get("op")
                        if cop == "CHUNK":
                            encoding = cmsg.get("encoding", "zlib")
                            if encoding == "zlib":
                                raw = zlib.decompress(cdata)
                            elif encoding == "raw":
                                raw = cdata
                            else:
                                raise ValueError(f"unsupported chunk encoding: {encoding}")
                            f.write(raw)
                            f.flush()
                            hasher.update(raw)
                            chunk_sha = hashlib.sha256(raw).hexdigest()
                            ledger.record_range(transfer_id, offset, offset + len(raw), chunk_sha)
                            offset += len(raw)
                        elif cop == "FILE_END":
                            break
                        else:
                            client.send_frame({"status": "ERROR", "message": f"unexpected chunk op: {cop}"})
                            if os.path.exists(tmp_file):
                                os.remove(tmp_file)
                            ledger.clear_ranges(transfer_id)
                            return

                    f.flush()
                    os.fsync(f.fileno())

                actual_sha = hasher.hexdigest()
                if not expected_sha or actual_sha != expected_sha:
                    if os.path.exists(tmp_file):
                        os.remove(tmp_file)
                    ledger.clear_ranges(transfer_id)
                    client.send_frame({"status": "ERROR", "message": f"checksum mismatch: {actual_sha} vs {expected_sha}"})
                    return

                os.replace(tmp_file, dest_file)
                ledger.mark_committed(transfer_id, actual_sha)
                ledger.purge_committed_ranges(transfer_id)

                if preserve:
                    with contextlib.suppress(Exception):
                        os.chmod(dest_file, stat.S_IMODE(mode))
                        os.utime(dest_file, (mtime, mtime))

                client.send_frame({"status": "OK", "sha256": actual_sha})
            except (TransportEOF, TimeoutError, ConnectionError):
                # Preserve staging file and verified ranges on network drop for resumption
                return
            except Exception as e:
                if os.path.exists(tmp_file):
                    with contextlib.suppress(Exception):
                        os.remove(tmp_file)
                with contextlib.suppress(Exception):
                    ledger.clear_ranges(transfer_id)
                client.send_frame({"status": "ERROR", "message": str(e)})
                return

    elif direction == "PULL":
        source = os.path.expanduser(meta.get("source", "."))
        recursive = meta.get("recursive", False)
        compression = meta.get("compression", "auto")

        if not os.path.exists(source):
            client.send_frame({"status": "ERROR", "message": f"{source}: No such file or directory"})
            return

        is_dir = os.path.isdir(source)
        if is_dir and not recursive:
            client.send_frame({"status": "ERROR", "message": f"{source}: Is a directory (not copied, use -r)"})
            return

        file_list = []
        if is_dir:
            base_dir = source.rstrip("/")
            for root, _, files in os.walk(base_dir):
                for fname in files:
                    full = os.path.join(root, fname)
                    with contextlib.suppress(Exception):
                        rel = sanitize_relpath(os.path.relpath(full, base_dir))
                        st = os.stat(full)
                        file_list.append({"rel": rel, "full": full, "size": st.st_size, "mode": st.st_mode, "mtime": st.st_mtime})
        else:
            try:
                st = os.stat(source)
                rel = sanitize_relpath(os.path.basename(source))
                file_list.append({"rel": rel, "full": source, "size": st.st_size, "mode": st.st_mode, "mtime": st.st_mtime})
            except Exception as e:
                client.send_frame({"status": "ERROR", "message": str(e)})
                return

        client.send_frame({
            "status": "OK",
            "is_dir": is_dir,
            "files": [{"rel": f["rel"], "size": f["size"], "mode": f["mode"], "mtime": f["mtime"]} for f in file_list],
        })

        file_map = {f["rel"]: f for f in file_list}
        file_iter = iter(file_list)
        while True:
            req, _ = client.recv_frame()
            op = req.get("op")
            if op == "DONE":
                client.send_frame({"status": "DONE"})
                break
            if op != "PULL_FILE":
                client.send_frame({"status": "ERROR", "message": f"expected PULL_FILE, got {op}"})
                return

            rel_req = req.get("rel")
            if rel_req and rel_req in file_map:
                item = file_map[rel_req]
            else:
                try:
                    item = next(file_iter)
                except StopIteration:
                    client.send_frame({"status": "ERROR", "message": "no more files in manifest"})
                    return

            full_path = item["full"]
            offset = int(req.get("offset", 0))
            if offset < 0 or offset > item["size"]:
                offset = 0

            hasher = hashlib.sha256()
            try:
                with open(full_path, "rb") as f:
                    if offset > 0:
                        while f.tell() < offset:
                            to_read = min(CHUNK_SIZE, offset - f.tell())
                            pbuf = f.read(to_read)
                            if not pbuf:
                                break
                            hasher.update(pbuf)
                        f.seek(offset)
                    while True:
                        buf = f.read(CHUNK_SIZE)
                        if not buf:
                            break
                        hasher.update(buf)
                        if compression == "raw":
                            client.send_frame({"op": "CHUNK", "encoding": "raw"}, buf)
                        elif compression == "zlib":
                            cdata = zlib.compress(buf, 6)
                            client.send_frame({"op": "CHUNK", "encoding": "zlib"}, cdata)
                        else:  # auto
                            if len(buf) > 1024:
                                cdata = zlib.compress(buf, 6)
                                if len(cdata) < len(buf):
                                    client.send_frame({"op": "CHUNK", "encoding": "zlib"}, cdata)
                                else:
                                    client.send_frame({"op": "CHUNK", "encoding": "raw"}, buf)
                            else:
                                client.send_frame({"op": "CHUNK", "encoding": "raw"}, buf)
                sha = hasher.hexdigest()
                client.send_frame({"op": "FILE_END", "sha256": sha})
                ack, _ = client.recv_frame()
                if ack.get("status") != "OK":
                    return
            except Exception as e:
                client.send_frame({"status": "ERROR", "message": str(e)})
                return
    else:
        client.send_frame({"status": "ERROR", "message": f"unknown direction {direction!r}"})


# ─────────────────────────────────────────────────────────────────────────────
# Connection Setup & Main Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def connect_and_run(
    host: str,
    args: argparse.Namespace,
    action_fn: Callable[[FramedStreamClient], int],
) -> int:
    """Establish encrypted Noise_XX session to host and execute transfer action.

    Args:
        host: Target host name (e.g. "host-3").
        args: Parsed CLI namespace arguments.
        action_fn: Callable taking FramedStreamClient and returning exit code.

    Returns:
        Process exit code.
    """
    private = read_key(args.keyfile, "operator static private key")
    peer = pinned_key(host)

    addr_host, _, port_text = args.addr.rpartition(":")
    if not addr_host:
        sys.stderr.write(f"moecp: malformed address {args.addr!r}; expected host:port\n")
        return 1
    port = int(port_text)

    retries = max(1, getattr(args, "retry", 1))
    for attempt in range(retries):
        try:
            sock = socket.create_connection((addr_host, port), timeout=15)
        except OSError as exc:
            if attempt + 1 < retries:
                time.sleep(0.5 * (attempt + 1))
                continue
            sys.stderr.write(f"moecp: cannot connect to receiver bridge at {args.addr}: {exc}\n")
            return 1

        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.sendall(PRELUDE_PREFIX + host.encode("latin-1") + b"\n")

        try:
            channel = Channel(sock)
            session = NoiseSession("initiator", private, cast("bytes", peer))
            sock.settimeout(30.0)
            handshake(session, channel)

            machine = SessionState()
            machine.to(State.AUTHENTICATED)
            secure = SecureChannel(channel, session)
            agreed = negotiate(secure, machine, term="dumb", fresh=True, session_type="transfer")

            client = FramedStreamClient(secure, sock)
            if agreed.get("session_type") != "transfer":
                bootstrap_cmd = generate_bootstrap_cmd()
                secure.send(Msg.DATA, bootstrap_cmd)
                client.wait_for_ready(timeout=15.0)

            return action_fn(client)
        except (TimeoutError, TransportEOF, OSError) as exc:
            if attempt + 1 < retries:
                time.sleep(0.5 * (attempt + 1))
                continue
            sys.stderr.write(f"moecp: connection interrupted: {exc}\n")
            return 1
        finally:
            with contextlib.suppress(OSError):
                sock.close()
    return 1


def main(argv: list[str] | None = None) -> int:
    """Parse CLI arguments and coordinate file copy execution.

    Args:
        argv: Optional argument list override for testing.

    Returns:
        Integer exit code (0 on success, non-zero on failure).
    """
    parser = argparse.ArgumentParser(
        prog="moecp",
        description="Secure file copy utility mirroring scp over moesh encrypted transport.",
    )
    parser.add_argument(
        "-r", "--recursive",
        action="store_true",
        help="recursively copy entire directories",
    )
    parser.add_argument(
        "-p", "--preserve",
        action="store_true",
        help="preserves modification times, access times, and modes",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="quiet mode: disables progress meter and non-fatal warnings",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="verbose debug logging",
    )
    parser.add_argument(
        "--retry",
        type=int,
        default=3,
        help="maximum retry attempts on connection interruption",
    )
    parser.add_argument(
        "--compression",
        choices=["auto", "zlib", "raw"],
        default="auto",
        help="transfer compression strategy",
    )
    parser.add_argument(
        "-n", "--host",
        default="",
        help="designated remote host number or name (e.g. 3 or host-3)",
    )
    parser.add_argument(
        "--addr",
        default=os.environ.get("MOESH_SHELL_ADDR", DEFAULT_ADDR),
        help="receiver operator bridge address (default: %(default)s)",
    )
    parser.add_argument(
        "--keyfile",
        default=os.environ.get("MOESH_SHELL_KEYFILE", DEFAULT_KEYFILE),
        help="operator private key file path",
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="source path(s) followed by destination target",
    )

    args = parser.parse_args(argv)

    if len(args.paths) < 2:
        parser.error("must provide at least one source and one destination target")

    sources_raw = args.paths[:-1]
    target_raw = args.paths[-1]

    default_host = resolve_name(args.host) if args.host else ""

    src_specs = [parse_path_spec(s, default_host=default_host) for s in sources_raw]
    dst_spec = parse_path_spec(target_raw, default_host=default_host)

    any_src_remote = any(s.is_remote for s in src_specs)
    dst_remote = dst_spec.is_remote

    if any_src_remote and dst_remote:
        sys.stderr.write("moecp: remote-to-remote copy is not supported; use intermediate local copy\n")
        return 1

    if not any_src_remote and not dst_remote:
        # Local-to-local fallback (mirrors scp behavior)
        try:
            for s in sources_raw:
                if os.path.isdir(s):
                    if not args.recursive:
                        sys.stderr.write(f"moecp: {s}: Is a directory (not copied, use -r)\n")
                        return 1
                    dest_dir = os.path.join(target_raw, os.path.basename(s.rstrip("/"))) if os.path.isdir(target_raw) else target_raw
                    shutil.copytree(s, dest_dir, dirs_exist_ok=True)
                else:
                    shutil.copy2(s, target_raw)
            return 0
        except Exception as e:
            sys.stderr.write(f"moecp: {e}\n")
            return 1

    if dst_remote:
        # Upload / Push
        remote_host = dst_spec.host
        return connect_and_run(
            remote_host,
            args,
            lambda client: upload_files(
                client,
                sources_raw,
                dst_spec,
                recursive=args.recursive,
                preserve=args.preserve,
                quiet=args.quiet,
                compression=args.compression,
            ),
        )

    # Download / Pull
    if len(src_specs) > 1:
        sys.stderr.write("moecp: downloading multiple remote sources in one invocation is not supported\n")
        return 1
    src_spec = src_specs[0]
    remote_host = src_spec.host
    return connect_and_run(
        remote_host,
        args,
        lambda client: download_files(
            client,
            src_spec,
            target_raw,
            recursive=args.recursive,
            preserve=args.preserve,
            quiet=args.quiet,
            compression=args.compression,
        ),
    )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except (ProtocolError, TransportEOF, NegotiationError) as err:
        sys.stderr.write(f"moecp: {err}\n")
        sys.exit(1)
