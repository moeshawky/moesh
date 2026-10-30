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
import fcntl
import hashlib
import json
import os
import select
import shutil
import socket
import sqlite3 as sqlite3
import stat
import struct
import sys
import time
import zlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

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
    resolve_name,
    resolve_operator_keys,
)
from moesh_wire import PRELUDE_PREFIX

# Maximum uncompressed chunk size for file transfer streaming, fixed at 32768 bytes (32 KiB).
CHUNK_SIZE: int = 32768
"""Maximum uncompressed chunk size for file transfer streaming (32 KiB)."""

# Maximum allowed JSON metadata header size, fixed at 65536 bytes (64 KiB).
MAX_FRAME_HDR: int = 65536
"""Maximum allowed JSON metadata header size in bytes (64 KiB)."""

# Maximum allowed chunk payload size, fixed at 10485760 bytes (10 MiB).
MAX_FRAME_PAYLOAD: int = 10485760
"""Maximum allowed chunk payload size in bytes (10 MiB)."""

# Maximum bytes one compressed frame may decode to.  The sender slices files at
# CHUNK_SIZE, so a conforming peer never exceeds this; anything larger is a
# decompression bomb and is refused before the bytes are materialised.
MAX_DECOMPRESSED_CHUNK: int = CHUNK_SIZE
"""Upper bound on the decoded size of a single compressed frame."""

# A manifest that fits in this many JSON bytes is sent inline (one frame), which
# keeps an older peer working on ordinary trees.  Anything larger is paginated so
# no frame approaches MAX_FRAME_HDR.
MANIFEST_INLINE_LIMIT: int = 32768
"""Largest manifest JSON sent as a single inline frame."""

# Entries per paginated manifest frame; 256 long paths stay far below 64 KiB.
MANIFEST_PAGE_SIZE: int = 256
"""Number of manifest entries per paginated frame."""

# Suffix used for the advisory lock taken while a destination is being written.
DESTINATION_LOCK_SUFFIX = ".moecp-lock"
"""Suffix of the per-destination advisory lock file."""

# Handshake token bytes emitted by the remote bootstrap worker after switching to raw framed mode.
MAGIC_READY: bytes = b"MOECP_READY_V1\n"
"""Handshake token emitted by the remote bootstrap worker once in raw mode."""

# Pre-compressed file extensions where chunk compression is skipped under auto strategy.
PRECOMPRESSED_EXTS: frozenset[str] = frozenset({
    # Archives and compressed containers
    ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz", ".zst", ".tzst",
    ".7z", ".zip", ".rar", ".whl", ".jar",
    # Model weights, tensors, and serialized graphs
    ".pt", ".pth", ".bin", ".safetensors", ".gguf", ".onnx", ".tflite",
    # Media: image, video, audio
    ".png", ".jpg", ".jpeg", ".webp", ".gif", ".mp4", ".mov", ".webm",
    ".mkv", ".mp3", ".flac", ".ogg",
    # Compressed document formats
    ".pdf", ".docx", ".xlsx", ".pptx",
})
"""File extensions where payload compression is skipped under auto strategy."""


def is_precompressed(path: str) -> bool:
    """Return True if the given file path has an extension indicating pre-compressed data."""
    _, ext = os.path.splitext(path)
    return ext.lower() in PRECOMPRESSED_EXTS


class PathEscapeError(ValueError):
    """A transfer path would resolve outside its designated destination root."""


class TransferBusyError(RuntimeError):
    """Another writer currently holds the lease on the destination."""


def decompress_chunk(data: bytes, limit: int = MAX_DECOMPRESSED_CHUNK) -> bytes:
    """Decode one zlib frame with a hard output bound.

    ``zlib.decompress`` validates the stream but allocates however much the
    stream expands to, so a small frame can demand arbitrary memory.  The
    decoder is therefore driven with an explicit ``max_length`` and refuses a
    frame that would decode past ``limit`` instead of growing to fit it.

    Args:
        data: Compressed frame bytes from the peer.
        limit: Maximum accepted decoded size in bytes.

    Returns:
        The decoded bytes (never longer than ``limit``).

    Raises:
        ProtocolError: On a malformed stream, trailing bytes, truncation, or
            decoded output beyond ``limit``.
    """
    decoder = zlib.decompressobj()
    try:
        out = decoder.decompress(data, limit + 1)
    except zlib.error as err:
        raise ProtocolError(f"malformed compressed chunk: {err}") from err
    if len(out) > limit:
        raise ProtocolError(
            f"compressed frame decodes to more than {limit} bytes (bound refused)"
        )
    if decoder.unconsumed_tail:
        raise ProtocolError(
            f"compressed frame expands beyond the {limit}-byte chunk bound"
        )
    if not decoder.eof:
        raise ProtocolError("truncated compressed stream")
    if decoder.unused_data:
        raise ProtocolError("trailing bytes after the compressed stream")
    return out


def pull_transfer_id(dest_file: str, size: int, mtime: float, content_sha: str) -> str:
    """Return the ledger identity of one PULL destination.

    The identity includes the *current remote content digest*, so a source that
    changed while keeping its size and mtime cannot inherit an older commit.
    """
    return hashlib.sha256(
        f"pull:{dest_file}:{size}:{mtime!r}:{content_sha}".encode()
    ).hexdigest()[:16]


def _lock_directory() -> str:
    """Return the directory holding destination leases.

    Leases live outside the transferred tree: a destination directory is user
    data, and a transfer must not leave bookkeeping files in it (nor require it
    to be writable just to take the lease).
    """
    override = os.environ.get("MOECP_LOCK_DIR")
    if override:
        return override
    ledger = os.environ.get("MOECP_CLIENT_LEDGER_PATH") or os.environ.get(
        "MOECP_LEDGER_PATH"
    )
    if ledger:
        return os.path.join(os.path.dirname(os.path.abspath(ledger)), "locks")
    return os.path.expanduser("~/.local/state/moesh/locks")


@contextlib.contextmanager
def destination_lock(dest_file: str) -> Any:
    """Hold an exclusive advisory lease on one destination file.

    Staging files are keyed by destination and content, so two clients writing
    the same destination would otherwise interleave in the same staging file.
    The second writer is refused instead of corrupting the first transfer.

    Raises:
        TransferBusyError: When another process (or file description) holds it.
    """
    lock_dir = _lock_directory()
    os.makedirs(lock_dir, exist_ok=True)
    key = hashlib.sha256(os.path.abspath(dest_file).encode()).hexdigest()[:32]
    lock_fd = os.open(
        os.path.join(lock_dir, key + ".lock"),
        os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW,
        0o600,
    )
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as err:
            raise TransferBusyError(
                f"destination {dest_file} is busy with another transfer"
            ) from err
        yield
    finally:
        os.close(lock_fd)


def _open_dir_chain(root: str, parts: list[str]) -> tuple[int, str]:
    """Open the parent directory of ``parts`` under ``root`` without following symlinks.

    Lexical containment (``abspath``/``commonpath``) does not establish
    containment: an intermediate component that is a symlink carries every
    later write outside the root.  Each component is therefore opened with
    ``O_NOFOLLOW`` relative to its parent descriptor, which both refuses a
    symlinked component and closes the check-then-create race.

    Args:
        root: Destination root; it is resolved once and is the trust anchor.
        parts: Relative path components below ``root``.

    Returns:
        ``(dir_fd, final_name)`` where ``dir_fd`` is an open directory
        descriptor for the parent and the caller owns it.

    Raises:
        PathEscapeError: If a component is a symlink, not a directory, or the
            path is malformed.
    """
    if not parts:
        raise PathEscapeError("empty destination path")
    for part in parts:
        if part in ("", ".", "..") or "/" in part or "\\" in part or "\0" in part:
            raise PathEscapeError(f"unsafe path component: {part!r}")
    root_real = os.path.realpath(root)
    try:
        fd = os.open(root_real, os.O_RDONLY | os.O_DIRECTORY)
    except OSError as err:
        raise PathEscapeError(f"destination root {root!r} is not a directory: {err}") from err
    try:
        for part in parts[:-1]:
            try:
                child = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
                )
            except FileNotFoundError:
                os.mkdir(part, 0o755, dir_fd=fd)
                child = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
                )
            except OSError as err:
                raise PathEscapeError(
                    f"path component {part!r} is not a real directory: {err}"
                ) from err
            os.close(fd)
            fd = child
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise


class StagedFile:
    """A destination file written through a verified staging file.

    Bytes are only ever written to ``<name>.part.<id>`` inside a directory
    descriptor that was opened without following symlinks.  ``commit`` renames
    inside that descriptor and fsyncs it, so neither a symlinked component nor
    a crash exposes a partial file under the final name.
    """

    def __init__(self, root: str, rel_parts: list[str], transfer_id: str) -> None:
        """Resolve the destination directory and staging name."""
        self.dir_fd, self.name = _open_dir_chain(root, rel_parts)
        self.tmp_name = f"{self.name}.part.{transfer_id}"
        self.root = root

    def open(self, resume: bool = False) -> Any:
        """Open the staging file, never following a symlink at its name."""
        fd = os.open(
            self.tmp_name,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
            0o600,
            dir_fd=self.dir_fd,
        )
        if not resume:
            os.ftruncate(fd, 0)
        return os.fdopen(fd, "r+b")

    def lock(self) -> Any:
        """Return the exclusive destination lease for this staged file."""
        return destination_lock(
            os.path.join(os.path.realpath(self.root), self.name)
        )

    def commit(self) -> None:
        """Atomically move staging to the final name and persist the directory entry."""
        os.replace(
            self.tmp_name, self.name, src_dir_fd=self.dir_fd, dst_dir_fd=self.dir_fd
        )
        os.fsync(self.dir_fd)

    def discard(self) -> None:
        """Remove the staging file, if any, without touching the final name."""
        with contextlib.suppress(OSError):
            os.unlink(self.tmp_name, dir_fd=self.dir_fd)

    def close(self) -> None:
        """Release the directory descriptor."""
        with contextlib.suppress(OSError):
            os.close(self.dir_fd)


@contextlib.contextmanager
def _discard_on_error(
    staged: StagedFile, ledger: TransferLedger, transfer_id: str
) -> Any:
    """Discard staging on a contract failure while keeping it on a transport drop."""
    try:
        yield
    except (TransportEOF, TimeoutError, OSError):
        raise
    except BaseException:
        staged.discard()
        ledger.clear_ranges(transfer_id)
        raise

# ─────────────────────────────────────────────────────────────────────────────
# Remote Bootstrap Worker Code
# ─────────────────────────────────────────────────────────────────────────────
# This script is executed directly on the remote host via `exec python3 -u -c ...`
# on the dedicated PTY child. It turns off echo/line discipline and communicates
# in framed binary packets with the local moecp client.

_WORKER_CODE = """
import os, sys, struct, json, zlib, hashlib, stat, time

PRECOMPRESSED_EXTS = {
    ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz", ".zst", ".tzst",
    ".7z", ".zip", ".rar", ".whl", ".jar",
    ".pt", ".pth", ".bin", ".safetensors", ".gguf", ".onnx", ".tflite",
    ".png", ".jpg", ".jpeg", ".webp", ".gif", ".mp4", ".mov", ".webm",
    ".mkv", ".mp3", ".flac", ".ogg",
    ".pdf", ".docx", ".xlsx", ".pptx",
}

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

def decode_chunk(cdata, limit=32768):
    dec = zlib.decompressobj()
    out = dec.decompress(cdata, limit + 1)
    if len(out) > limit or dec.unconsumed_tail or not dec.eof or dec.unused_data:
        raise ValueError("compressed chunk exceeds the decoded chunk bound")
    return out

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

        files_received = 0
        while True:
            msg, payload = recv_frame()
            op = msg.get("op")
            if op == "DONE":
                send_frame({"status": "DONE"})
                break
            if op != "FILE_START":
                send_frame({"status": "ERROR", "message": f"unexpected op: {op}"})
                return 1

            if files_received > 0 and not dest_is_dir and not is_dir_upload:
                send_frame({"status": "ERROR", "message": f"destination '{target}' is not a directory"})
                return 1
            files_received += 1

            raw_rel = msg.get("rel_path", "")
            try:
                rel = sanitize_relpath(raw_rel)
            except ValueError as e:
                send_frame({"status": "ERROR", "message": str(e)})
                return 1

            target_abs = os.path.realpath(os.path.abspath(target))
            if is_dir_upload:
                root = target_abs
                dest_file = os.path.join(target_abs, rel)
            elif dest_is_dir:
                root = target_abs
                dest_file = os.path.join(target_abs, os.path.basename(rel))
            else:
                # Single-file upload containment root is the destination's parent (October 2026)
                root = os.path.dirname(target_abs) or "/"
                dest_file = target_abs

            # Containment through the resolved filesystem, not lexically: an
            # intermediate symlink must not carry the write outside the root.
            dest_dir = os.path.dirname(dest_file) or "."
            try:
                os.makedirs(dest_dir, exist_ok=True)
                parent_real = os.path.realpath(dest_dir)
            except OSError as exc:
                send_frame({"status": "ERROR", "message": f"invalid target path: {exc}"})
                return 1
            root_real = os.path.realpath(root)
            if parent_real != root_real and not parent_real.startswith(root_real.rstrip(os.sep) + os.sep):
                send_frame({"status": "ERROR", "message": f"path escapes target directory: {dest_file}"})
                return 1
            if os.path.islink(dest_file):
                send_frame({"status": "ERROR", "message": f"refusing to replace symlink: {dest_file}"})
                return 1

            size = msg.get("size", 0)
            mode = msg.get("mode", 0o644)
            mtime = msg.get("mtime", time.time())
            expected_sha = msg.get("sha256", "")

            tmp_file = dest_file + ".part." + str(os.getpid())
            hasher = hashlib.sha256()
            written = 0

            try:
                with open(tmp_file, "wb") as f:
                    send_frame({"status": "READY"})
                    while True:
                        cmsg, cdata = recv_frame()
                        cop = cmsg.get("op")
                        if cop == "CHUNK":
                            enc = cmsg.get("encoding", "zlib")
                            if enc == "zlib":
                                raw = decode_chunk(cdata)
                            elif enc == "raw":
                                raw = cdata
                            else:
                                raise ValueError(f"unsupported chunk encoding: {enc}")
                            if written + len(raw) > size:
                                raise ValueError("received more than the declared file size")
                            f.write(raw)
                            hasher.update(raw)
                            written += len(raw)
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

            skip_comp = os.path.splitext(full_path)[1].lower() in PRECOMPRESSED_EXTS
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
                        if compression == "raw" or (compression == "auto" and skip_comp):
                            send_frame({"op": "CHUNK", "encoding": "raw"}, buf)
                        elif compression == "zlib":
                            cdata = zlib.compress(buf, 1)
                            send_frame({"op": "CHUNK", "encoding": "zlib"}, cdata)
                        else:  # auto
                            if len(buf) > 1024:
                                cdata = zlib.compress(buf, 1)
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
        - `[user@]host-3:/path/to/file` -> remote host-3
        - `[user@]3:/path/to/file` -> remote host-3
        - `[user@]remote:/path/to/file` -> remote default_host
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
        # Strip optional user@ prefix before label validation (DEF-09, October 2026)
        _, _, host_part = host_part.rpartition("@")
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

        Inspects incoming records (DEF-10, October 2026):
          - Msg.ERROR: raises ProtocolError with decoded remote message.
          - Msg.CLOSE: raises TransportEOF on authenticated remote close.
          - Msg.DATA: appends payload bytes to internal buffer.

        Args:
            deadline: Optional absolute monotonic deadline timestamp.
            timeout: Seconds to wait for socket readability before error if deadline not given.

        Raises:
            TimeoutError: If peer fails to respond within timeout or before deadline.
            TransportEOF: If connection is broken or remote closed session.
            ProtocolError: If peer reports an application error.
        """
        if deadline is None:
            deadline = time.monotonic() + timeout

        def _consume_records(records: list[tuple[int, bytes]]) -> None:
            for msg_type, data in records:
                if msg_type == Msg.ERROR:
                    raise ProtocolError(f"remote error: {data.decode('utf-8', 'replace')}")
                if msg_type == Msg.CLOSE:
                    raise TransportEOF("remote closed session")
                if msg_type == Msg.DATA:
                    self._buf.extend(data)

        while True:
            records = self.secure.buffered()
            if records:
                _consume_records(records)
                if self._buf:
                    return

            rem = deadline - time.monotonic()
            if rem <= 0:
                raise TimeoutError("timed out waiting for remote response")

            ready, _, _ = select.select([self.sock], [], [], rem)
            if not ready or self.sock not in ready:
                raise TimeoutError("timed out waiting for remote response")

            records = self.secure.drain()
            _consume_records(records)
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

    def iter_manifest(self, manifest: dict[str, Any]) -> Any:
        """Yield manifest entries from an inline or paginated PULL response.

        A tree whose metadata does not fit one 64 KiB frame is paged by the
        sender; the receiver asks for one page at a time so its memory is
        bounded by a page rather than by the whole tree.

        Args:
            manifest: The ``OK`` frame that opened the PULL session.

        Yields:
            One entry dict per file (``rel``, ``size``, ``mode``, ``mtime``,
            ``sha256``).
        """
        if not manifest.get("paginated"):
            for item in manifest.get("files", []):
                yield item
            return
        count = int(manifest.get("count", 0))
        page_size = int(manifest.get("page_size", MANIFEST_PAGE_SIZE))
        if page_size <= 0:
            raise ProtocolError("manifest page_size must be positive")
        page = 0
        seen = 0
        max_pages = (count // page_size) + 2
        while True:
            if page > max_pages:
                raise ProtocolError(
                    "manifest pagination ran past the declared entry count"
                )
            self.send_frame({"op": "LIST", "page": page})
            reply, _ = self.recv_frame()
            if reply.get("op") != "MANIFEST":
                raise ProtocolError(
                    f"expected MANIFEST, got {reply.get('op')!r}"
                )
            for item in reply.get("files", []):
                seen += 1
                yield item
            if not reply.get("more"):
                break
            page += 1
        if seen != count:
            raise ProtocolError(
                f"manifest declared {count} entries but delivered {seen}"
            )

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
        if not os.path.lexists(src):
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

    # Standard scp requirement: when uploading multiple source files, verify destination is an existing directory (DEF-07, October 2026)
    if len(sources) > 1 and not init_ack.get("target_is_dir", False):
        raise ProtocolError(f"destination '{target_spec.path}' is not a directory")

    for full_path, rel_path in file_manifest:
        try:
            st = os.stat(full_path)
            hasher = hashlib.sha256()

            # Compute SHA256 before streaming
            with open(full_path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            expected_sha = hasher.hexdigest()
        except OSError as err:
            sys.stderr.write(f"moecp: cannot access '{full_path}': {err}\n")
            summary.skipped += 1
            continue

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
        skip_comp = is_precompressed(rel_path)
        with open(full_path, "rb") as f:
            if resume_offset > 0:
                f.seek(resume_offset)
            while buf := f.read(CHUNK_SIZE):
                if compression == "raw" or (compression == "auto" and skip_comp):
                    client.send_frame({"op": "CHUNK", "encoding": "raw"}, buf)
                elif compression == "zlib":
                    cdata = zlib.compress(buf, 1)
                    client.send_frame({"op": "CHUNK", "encoding": "zlib"}, cdata)
                else:  # auto
                    if len(buf) > 1024:
                        cdata = zlib.compress(buf, 1)
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
    if done_ack.get("status") == "DONE":
        with contextlib.suppress(Exception):
            client.secure.send_control(Msg.CLOSE, {"reason": "transfer complete"})
    summary.print_summary()
    return 0 if done_ack.get("status") == "DONE" else 1


def _verified_prefix(
    ledger: TransferLedger, staged: StagedFile, transfer_id: str
) -> tuple[int, Any]:
    """Re-hash the staged prefix and return ``(resume_offset, hasher)``.

    Recorded progress is never trusted on its own: each ledger range is
    re-hashed against the bytes actually on disk, and the first mismatch
    truncates the range list at that offset.
    """
    hasher = hashlib.sha256()
    try:
        os.stat(staged.tmp_name, dir_fd=staged.dir_fd)
    except OSError:
        ledger.truncate_ranges_after(transfer_id, 0)
        return 0, hasher
    resume = 0
    rows = ledger.get_verified_range_hashes(transfer_id)
    if rows:
        try:
            read_fd = os.open(
                staged.tmp_name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=staged.dir_fd
            )
            with os.fdopen(read_fd, "rb") as staged_reader:
                for start_off, end_off, expected_chunk_sha in rows:
                    if start_off != resume or end_off < start_off:
                        break
                    chunk_len = end_off - start_off
                    disk_bytes = staged_reader.read(chunk_len)
                    if (
                        len(disk_bytes) != chunk_len
                        or hashlib.sha256(disk_bytes).hexdigest() != expected_chunk_sha
                    ):
                        break
                    hasher.update(disk_bytes)
                    resume = end_off
        except OSError:
            ledger.truncate_ranges_after(transfer_id, 0)
            return 0, hashlib.sha256()
    ledger.truncate_ranges_after(transfer_id, resume)
    return resume, hasher


def _receive_pull_file(
    client: FramedStreamClient,
    ledger: TransferLedger,
    item: dict[str, Any],
    *,
    root: str,
    rel_parts: list[str],
    dest_file: str,
    preserve: bool,
    quiet: bool,
) -> str:
    """Receive one PULL entry into its destination root.

    Returns:
        ``"skipped"`` when the destination already holds the *current* remote
        content digest, or ``"committed"`` after a verified commit.

    Raises:
        TransferBusyError: Another writer holds the destination lease.
        ProtocolError: Bounds, digest, or frame contract violated.
        TransportEOF/TimeoutError/OSError: Keep staging for a later resume.
    """
    size = int(item["size"])
    mode = int(item["mode"])
    mtime = float(item["mtime"])
    content_sha = str(item.get("sha256", ""))

    if content_sha:
        committed_id = pull_transfer_id(dest_file, size, mtime, content_sha)
        if ledger.is_committed(committed_id) and os.path.exists(dest_file):
            try:
                if (
                    os.path.getsize(dest_file) == size
                    and compute_file_sha256(dest_file) == content_sha
                ):
                    return "skipped"
            except OSError:
                pass

    pull_id = pull_transfer_id(dest_file, size, mtime, content_sha)
    staged = StagedFile(root, rel_parts, pull_id)
    with contextlib.ExitStack() as stack:
        # Register close before acquiring lock so dir_fd is closed even if TransferBusyError is raised (October 2026)
        stack.callback(staged.close)
        stack.enter_context(staged.lock())
        ledger.record_transfer(pull_id, dest_file, size, content_sha)
        try:
            resume_offset, hasher = _verified_prefix(ledger, staged, pull_id)
            client.send_frame(
                {"op": "PULL_FILE", "rel": item["rel"], "offset": resume_offset}
            )
            meter = ProgressMeter(item["rel"], size, quiet=quiet)
            if resume_offset > 0:
                meter.update(resume_offset)
            offset = resume_offset
            try:
                with staged.open(resume=resume_offset > 0) as handle:
                    if resume_offset > 0:
                        handle.seek(resume_offset)
                        handle.truncate(resume_offset)
                    while True:
                        cmsg, cdata = client.recv_frame()
                        cop = cmsg.get("op")
                        if cop == "CHUNK":
                            enc = cmsg.get("encoding", "zlib")
                            if enc == "zlib":
                                raw = decompress_chunk(cdata)
                            elif enc == "raw":
                                raw = cdata
                            else:
                                raise ProtocolError(
                                    f"unsupported chunk encoding: {enc}"
                                )
                            if offset + len(raw) > size:
                                raise ProtocolError(
                                    f"received more than the declared {size} bytes"
                                )
                            handle.write(raw)
                            handle.flush()
                            hasher.update(raw)
                            chunk_sha = hashlib.sha256(raw).hexdigest()
                            ledger.record_range(
                                pull_id, offset, offset + len(raw), chunk_sha
                            )
                            offset += len(raw)
                            meter.update(len(raw))
                        elif cop == "FILE_END":
                            expected_sha = str(cmsg.get("sha256", ""))
                            meter.finish()
                            break
                        else:
                            raise ProtocolError(f"unexpected chunk op: {cop}")
                    handle.flush()
                    os.fsync(handle.fileno())

                actual_sha = hasher.hexdigest()
                if not expected_sha or actual_sha != expected_sha:
                    raise ProtocolError(
                        f"integrity failure on {item['rel']}: "
                        f"{actual_sha} vs {expected_sha}"
                    )
                if content_sha and actual_sha != content_sha:
                    raise ProtocolError(
                        f"remote content for {item['rel']} changed during the transfer"
                    )
                if offset != size:
                    raise ProtocolError(
                        f"received {offset} bytes, expected {size} for {item['rel']}"
                    )

                staged.commit()
                ledger.mark_committed(pull_id, actual_sha)
                ledger.purge_committed_ranges(pull_id)

                if preserve:
                    with contextlib.suppress(Exception):
                        os.chmod(dest_file, stat.S_IMODE(mode))
                        os.utime(dest_file, (mtime, mtime))

                client.send_frame({"status": "OK"})
            except (TransportEOF, TimeoutError, OSError):
                # Staging and verified ranges survive for the next attempt.
                raise
        except (TransportEOF, TimeoutError, OSError):
            raise
        except BaseException:
            staged.discard()
            ledger.clear_ranges(pull_id)
            raise
    return "committed"


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
    summary.total = int(
        manifest.get("count", 0)
        if manifest.get("paginated")
        else len(manifest.get("files", []))
    )
    target_abs = os.path.realpath(os.path.abspath(local_target))
    if is_dir:
        os.makedirs(target_abs, exist_ok=True)
    target_is_dir = os.path.isdir(target_abs)

    for item in client.iter_manifest(manifest):
        try:
            rel = sanitize_relpath(str(item["rel"]))
            root, rel_parts = _pull_destination_layout(
                target_abs, rel, is_dir=is_dir, target_is_dir=target_is_dir
            )
            dest_file = os.path.join(root, *rel_parts)
        except (KeyError, TypeError, ValueError) as err:
            sys.stderr.write(f"moecp: remote path rejected: {err}\n")
            client.send_frame({"status": "ERROR"})
            summary.failed += 1
            summary.print_summary()
            return 1

        try:
            outcome = _receive_pull_file(
                client,
                ledger,
                item,
                root=root,
                rel_parts=rel_parts,
                dest_file=dest_file,
                preserve=preserve,
                quiet=quiet,
            )
        except TransferBusyError as err:
            sys.stderr.write(f"moecp: {err}\n")
            client.send_frame({"status": "ERROR"})
            summary.failed += 1
            summary.print_summary()
            return 1
        except (TransportEOF, TimeoutError):
            summary.failed += 1
            summary.print_summary()
            raise
        except OSError as err:
            # A socket-level failure is recoverable by reconnecting.  A local
            # filesystem failure is not, but it must not be mistaken for a
            # successful transfer either; connect_and_run retries and the
            # next attempt reports the same error rather than claiming success.
            sys.stderr.write(f"moecp: download interrupted for {rel}: {err}\n")
            summary.failed += 1
            summary.print_summary()
            raise
        except Exception as err:
            sys.stderr.write(f"moecp: download failed for {rel}: {err}\n")
            client.send_frame({"status": "ERROR"})
            summary.failed += 1
            summary.print_summary()
            return 1

        if outcome == "skipped":
            summary.skipped += 1
        else:
            summary.succeeded += 1

    client.send_frame({"op": "DONE"})
    done_ack, _ = client.recv_frame()
    if done_ack.get("status") == "DONE":
        with contextlib.suppress(Exception):
            client.secure.send_control(Msg.CLOSE, {"reason": "transfer complete"})
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
        """Stores db_path and creates the parent directory, SQLite database, WAL mode, auto_vacuum, and transfers and verified_ranges tables."""
        self.db_path = db_path
        self._init_db()

    @contextlib.contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        """Yield a database connection wrapped in a transaction, ensuring it is closed."""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        parent = os.path.dirname(os.path.abspath(self.db_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with self._conn() as conn:
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
        """Inserts or replaces a transfer row with committed=0, total size, expected SHA-256, relative path, and timestamp (current time or updated_at)."""
        ts = time.time() if updated_at is None else updated_at
        with self._conn() as conn:
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
        """Inserts or replaces a verified range row for transfer_id and updates that transfer's updated_at timestamp."""
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO verified_ranges (transfer_id, start_offset, end_offset, sha256) VALUES (?, ?, ?, ?)",
                (transfer_id, start, end, sha256),
            )
            conn.execute(
                "UPDATE transfers SET updated_at=? WHERE transfer_id=?",
                (time.time(), transfer_id),
            )

    def mark_committed(self, transfer_id: str, sha256: str | None = None) -> None:
        """Sets committed=1 and updated_at to the current time for transfer_id; when sha256 is provided it also updates expected_sha256."""
        with self._conn() as conn:
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
        """Returns the stored expected SHA-256 string for transfer_id, or an empty string when the row or value is missing."""
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT expected_sha256 FROM transfers WHERE transfer_id=?",
                (transfer_id,),
            )
            row = cur.fetchone()
            return str(row[0]) if row and row[0] else ""

    def get_verified_ranges(self, transfer_id: str) -> list[tuple[int, int]]:
        """Returns verified (start_offset, end_offset) tuples for transfer_id ordered by start_offset."""
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT start_offset, end_offset FROM verified_ranges WHERE transfer_id=? ORDER BY start_offset",
                (transfer_id,),
            )
            return cur.fetchall()

    def get_verified_range_hashes(self, transfer_id: str) -> list[tuple[int, int, str]]:
        """Returns verified (start_offset, end_offset, sha256) tuples for transfer_id ordered by start_offset."""
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT start_offset, end_offset, sha256 FROM verified_ranges WHERE transfer_id=? ORDER BY start_offset",
                (transfer_id,),
            )
            return cur.fetchall()

    def clear_ranges(self, transfer_id: str) -> None:
        """Deletes all verified_ranges rows associated with transfer_id."""
        with self._conn() as conn:
            conn.execute(
                "DELETE FROM verified_ranges WHERE transfer_id=?",
                (transfer_id,),
            )

    def truncate_ranges_after(self, transfer_id: str, offset: int) -> None:
        """Purge chunk ranges starting at or after offset upon verification fault."""
        with self._conn() as conn:
            conn.execute(
                "DELETE FROM verified_ranges WHERE transfer_id=? AND start_offset >= ?",
                (transfer_id, offset),
            )

    def purge_committed_ranges(self, transfer_id: str) -> None:
        """Purge chunk ranges for a committed transfer to prevent unbounded ledger growth."""
        with self._conn() as conn:
            conn.execute(
                "DELETE FROM verified_ranges WHERE transfer_id=?",
                (transfer_id,),
            )
            with contextlib.suppress(sqlite3.Error):
                conn.execute("PRAGMA incremental_vacuum;")

    def prune_stale_transfers(self, days: int = 7) -> int:
        """Purge uncommitted transfers and orphaned chunk ranges older than TTL days."""
        cutoff = time.time() - (days * 86400.0)
        with self._conn() as conn:
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
        """Returns True only when a transfers row exists for transfer_id with committed equal to 1."""
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT committed FROM transfers WHERE transfer_id=?",
                (transfer_id,),
            )
            row = cur.fetchone()
            return bool(row and row[0] == 1)


def _pull_destination_layout(
    target_abs: str, rel: str, *, is_dir: bool, target_is_dir: bool
) -> tuple[str, list[str]]:
    """Return the containment root and relative components for one PULL entry."""
    parts = rel.split("/")
    if is_dir:
        return target_abs, parts
    if target_is_dir:
        return target_abs, [parts[-1]]
    return os.path.dirname(target_abs) or os.sep, [os.path.basename(target_abs)]


def _receive_push_file(
    client: FramedStreamClient,
    ledger: TransferLedger,
    *,
    root: str,
    rel_parts: list[str],
    dest_file: str,
    size: int,
    mode: int,
    mtime: float,
    expected_sha: str,
    preserve: bool,
) -> str:
    """Receive one PUSH file into a verified staging file and commit it.

    Returns:
        ``"committed"`` after a verified commit, or ``"skipped"`` when the
        destination already holds the exact expected digest.

    Raises:
        TransferBusyError: Another writer holds the destination lease.
        ProtocolError: Bounds, digest, or frame contract violated.
        TransportEOF/TimeoutError/OSError: Keep staging for a later resume.
    """
    transfer_id = hashlib.sha256(
        f"{dest_file}:{size}:{expected_sha}".encode()
    ).hexdigest()[:16]

    staged = StagedFile(root, rel_parts, transfer_id)
    with contextlib.ExitStack() as stack:
        # Register close before acquiring lock so dir_fd is closed even if TransferBusyError is raised (October 2026)
        stack.callback(staged.close)
        stack.enter_context(staged.lock())
        stack.enter_context(_discard_on_error(staged, ledger, transfer_id))
        if expected_sha and ledger.is_committed(transfer_id) and os.path.exists(dest_file):
            try:
                if (
                    os.path.getsize(dest_file) == size
                    and compute_file_sha256(dest_file) == expected_sha
                ):
                    client.send_frame({"status": "COMMITTED", "sha256": expected_sha})
                    return "skipped"
            except OSError:
                pass

        ledger.record_transfer(transfer_id, dest_file, size, expected_sha)
        resume_offset, hasher = _verified_prefix(ledger, staged, transfer_id)
        received = resume_offset
        with staged.open(resume=resume_offset > 0) as handle:
            if resume_offset > 0:
                handle.seek(resume_offset)
                handle.truncate(resume_offset)
            client.send_frame(
                {
                    "status": "READY",
                    "transfer_id": transfer_id,
                    "offset": resume_offset,
                }
            )
            while True:
                cmsg, cdata = client.recv_frame()
                cop = cmsg.get("op")
                if cop == "CHUNK":
                    encoding = cmsg.get("encoding", "zlib")
                    if encoding == "zlib":
                        raw = decompress_chunk(cdata)
                    elif encoding == "raw":
                        raw = cdata
                    else:
                        raise ProtocolError(
                            f"unsupported chunk encoding: {encoding}"
                        )
                    if received + len(raw) > size:
                        raise ProtocolError(
                            f"received more than the declared {size} bytes"
                        )
                    handle.write(raw)
                    handle.flush()
                    hasher.update(raw)
                    chunk_sha = hashlib.sha256(raw).hexdigest()
                    ledger.record_range(
                        transfer_id, received, received + len(raw), chunk_sha
                    )
                    received += len(raw)
                elif cop == "FILE_END":
                    break
                else:
                    raise ProtocolError(f"unexpected chunk op: {cop}")
            handle.flush()
            os.fsync(handle.fileno())

        actual_sha = hasher.hexdigest()
        if not expected_sha or actual_sha != expected_sha:
            raise ProtocolError(
                f"checksum mismatch: {actual_sha} vs {expected_sha}"
            )
        if received != size:
            raise ProtocolError(f"received {received} bytes, expected {size}")

        staged.commit()
        ledger.mark_committed(transfer_id, actual_sha)
        ledger.purge_committed_ranges(transfer_id)

        if preserve:
            with contextlib.suppress(Exception):
                os.chmod(dest_file, stat.S_IMODE(mode))
                os.utime(dest_file, (mtime, mtime))

        client.send_frame({"status": "OK", "sha256": actual_sha})
        return "committed"


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

        files_received = 0
        while True:
            msg, _payload = client.recv_frame()
            op = msg.get("op")
            if op == "DONE":
                client.send_frame({"status": "DONE"})
                break
            if op != "FILE_START":
                client.send_frame({"status": "ERROR", "message": f"unexpected op: {op}"})
                return

            # Abort if multiple files sent to non-directory target (DEF-07, October 2026)
            if files_received > 0 and not dest_is_dir and not is_dir_upload:
                client.send_frame({"status": "ERROR", "message": f"destination '{target}' is not a directory"})
                return
            files_received += 1

            raw_rel = msg.get("rel_path", "")
            try:
                rel = sanitize_relpath(raw_rel)
            except ValueError as e:
                client.send_frame({"status": "ERROR", "message": str(e)})
                return

            size = int(msg.get("size", 0))
            mode = int(msg.get("mode", 0o644))
            mtime = float(msg.get("mtime", time.time()))
            expected_sha = str(msg.get("sha256", ""))
            if size < 0:
                client.send_frame({"status": "ERROR", "message": "negative size"})
                return

            target_abs = os.path.realpath(os.path.abspath(target))
            if is_dir_upload:
                root = target_abs
                rel_parts = rel.split("/")
            elif dest_is_dir:
                root = target_abs
                rel_parts = [os.path.basename(rel)]
            else:
                root = os.path.dirname(target_abs) or os.sep
                rel_parts = [os.path.basename(target_abs)]
            dest_file = os.path.join(root, *rel_parts)

            try:
                _receive_push_file(
                    client,
                    ledger,
                    root=root,
                    rel_parts=rel_parts,
                    dest_file=dest_file,
                    size=size,
                    mode=mode,
                    mtime=mtime,
                    expected_sha=expected_sha,
                    preserve=preserve,
                )
            except TransferBusyError as err:
                client.send_frame({"status": "ERROR", "message": str(err)})
                return
            except (TransportEOF, TimeoutError, ConnectionError):
                # Preserve staging file and verified ranges for resumption.
                return
            except OSError as err:
                with contextlib.suppress(Exception):
                    client.send_frame({"status": "ERROR", "message": str(err)})
                return
            except Exception as err:
                client.send_frame({"status": "ERROR", "message": str(err)})
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

        entries = [
            {"rel": f["rel"], "size": f["size"], "mode": f["mode"], "mtime": f["mtime"]}
            for f in file_list
        ]
        # Decide inline vs paged before hashing: a placeholder digest has the
        # same width as the real one, so the size decision is exact.
        probe = [{**entry, "sha256": "0" * 64} for entry in entries]
        inline = (
            len(json.dumps({"is_dir": is_dir, "files": probe}))
            <= MANIFEST_INLINE_LIMIT
        )
        if inline:
            for entry, source_entry in zip(entries, file_list, strict=True):
                digest = compute_file_sha256(source_entry["full"])
                entry["sha256"] = digest
                source_entry["sha256"] = digest
            client.send_frame({"status": "OK", "is_dir": is_dir, "files": entries})
        else:
            client.send_frame(
                {
                    "status": "OK",
                    "is_dir": is_dir,
                    "paginated": True,
                    "count": len(entries),
                    "page_size": MANIFEST_PAGE_SIZE,
                }
            )

        file_map = {f["rel"]: f for f in file_list}
        file_iter = iter(file_list)
        while True:
            req, _ = client.recv_frame()
            op = req.get("op")
            if op == "DONE":
                client.send_frame({"status": "DONE"})
                break
            if op == "LIST":
                page = max(0, int(req.get("page", 0)))
                start = page * MANIFEST_PAGE_SIZE
                page_entries = entries[start : start + MANIFEST_PAGE_SIZE]
                page_sources = file_list[start : start + MANIFEST_PAGE_SIZE]
                for entry, source_entry in zip(
                    page_entries, page_sources, strict=True
                ):
                    digest = compute_file_sha256(source_entry["full"])
                    entry["sha256"] = digest
                    source_entry["sha256"] = digest
                client.send_frame(
                    {
                        "op": "MANIFEST",
                        "page": page,
                        "files": page_entries,
                        "more": start + len(page_entries) < len(entries),
                    }
                )
                continue
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

            try:
                current = os.stat(full_path)
            except OSError as err:
                client.send_frame({"status": "ERROR", "message": str(err)})
                return
            if current.st_size != item["size"] or current.st_mtime != item["mtime"]:
                client.send_frame(
                    {
                        "status": "ERROR",
                        "message": f"{full_path}: source changed since the manifest",
                    }
                )
                return

            skip_comp = is_precompressed(full_path)
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
                        if compression == "raw" or (compression == "auto" and skip_comp):
                            client.send_frame({"op": "CHUNK", "encoding": "raw"}, buf)
                        elif compression == "zlib":
                            cdata = zlib.compress(buf, 1)
                            client.send_frame({"op": "CHUNK", "encoding": "zlib"}, cdata)
                        else:  # auto
                            if len(buf) > 1024:
                                cdata = zlib.compress(buf, 1)
                                if len(cdata) < len(buf):
                                    client.send_frame({"op": "CHUNK", "encoding": "zlib"}, cdata)
                                else:
                                    client.send_frame({"op": "CHUNK", "encoding": "raw"}, buf)
                            else:
                                client.send_frame({"op": "CHUNK", "encoding": "raw"}, buf)
                sha = hasher.hexdigest()
                expected_sha = str(item.get("sha256", ""))
                if expected_sha and sha != expected_sha:
                    client.send_frame(
                        {
                            "status": "ERROR",
                            "message": f"{full_path}: content changed during the transfer",
                        }
                    )
                    return
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
    explicit_kf = (
        bool(os.environ.get("MOESH_SHELL_KEYFILE"))
        or bool(os.environ.get("MOESH_SHELL_V2_KEYFILE"))
        or (args.keyfile != DEFAULT_KEYFILE)
    )
    op_keys = resolve_operator_keys(args.keyfile, host, explicit_keyfile=explicit_kf)
    peer = pinned_key(host)

    addr_host, _, port_text = args.addr.rpartition(":")
    if not addr_host:
        sys.stderr.write(f"moecp: malformed address {args.addr!r}; expected host:port\n")
        return 1
    port = int(port_text)

    retries = max(1, getattr(args, "retry", 1), len(op_keys))
    for attempt in range(retries):
        private = op_keys[attempt % len(op_keys)]
        try:
            sock = socket.create_connection((addr_host, port), timeout=15)
        except OSError as exc:
            if attempt + 1 < retries:
                time.sleep(0.5 * (attempt + 1))
                continue
            sys.stderr.write(f"moecp: cannot connect to receiver bridge at {args.addr}: {exc}\n")
            return 1

        with contextlib.suppress(OSError):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.sendall(PRELUDE_PREFIX + host.encode("latin-1") + b"\n")

        try:
            channel = Channel(sock)
            session = NoiseSession("initiator", private, peer)
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
        except (TimeoutError, TransportEOF, OSError, ProtocolError) as exc:
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
        help="transfer compression strategy (auto=zlib-1 with precompressed bypass, zlib=zlib-1, raw=uncompressed)",
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
        if len(sources_raw) > 1 and not os.path.isdir(target_raw):
            sys.stderr.write(f"moecp: destination '{target_raw}' is not a directory\n")
            return 1
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
