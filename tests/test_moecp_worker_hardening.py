#!/usr/bin/env python3
"""Acceptance and regression tests for remote moecp worker hardening.

Measures:
1. Isolated execution: _WORKER_CODE imports contextlib explicitly; remote workers
   never fail with NameError on contextlib.suppress.
2. Manifest pagination: _WORKER_CODE pages directories exceeding the inline bound,
   answering LIST with MANIFEST frames matching client iter_manifest().
3. Push staging durability:
   - Staging filenames use cryptographically random 16-hex nonces instead of predictable PID.
   - Files are created with O_CREAT | O_EXCL and permissions 0o600.
   - Pre-existing destination symlinks are refused.
   - Integrity checksum mismatch or transfer aborts clean up staging files immediately.
4. Symlink handling topology:
   - PULL uses lstat, safely skipping broken or directory symlinks without crashing enumeration.
   - Good symlinks pointing to regular files stream target content accurately.
   - Single-file pull of broken symlinks is refused.
5. Chunk-level resumption:
   - PULL resumes stream from offset > 0 and validates whole-file SHA-256.
   - PUSH unlinks .part staging file on premature disconnect, preventing leaked disk space.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import socket
import struct
import subprocess
import sys
from typing import TYPE_CHECKING, Any

import moecp

if TYPE_CHECKING:
    from pathlib import Path


def _send(sock: socket.socket, meta: dict[str, Any], payload: bytes = b"") -> None:
    hdr = json.dumps(meta).encode("utf-8")
    frame = struct.pack(">II", len(hdr), len(payload)) + hdr + payload
    sock.sendall(frame)


def _recv(sock: socket.socket) -> tuple[dict[str, Any], bytes]:
    def read_exact(n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise EOFError("socket closed prematurely")
            buf.extend(chunk)
        return bytes(buf)

    hdr_bytes = read_exact(8)
    hlen, dlen = struct.unpack(">II", hdr_bytes)
    meta = json.loads(read_exact(hlen).decode("utf-8"))
    payload = read_exact(dlen) if dlen > 0 else b""
    return meta, payload


def test_worker_code_imports_contextlib_explicitly() -> None:
    """_WORKER_CODE string imports contextlib in its top-level imports."""
    assert "import os, sys, struct, json, zlib, hashlib, stat, time, contextlib" in moecp._WORKER_CODE

    # Verify execution in isolated namespace without parent contextlib in globals
    isolated_globals: dict[str, Any] = {"__builtins__": __builtins__}
    # Execute imports from _WORKER_CODE
    import_line = moecp._WORKER_CODE.strip().splitlines()[0]
    exec(import_line, isolated_globals)  # noqa: S102
    assert "contextlib" in isolated_globals
    # Test contextlib.suppress in the isolated namespace
    empty_map: dict[str, str] = {}
    with isolated_globals["contextlib"].suppress(KeyError):
        _ = empty_map["missing"]


def test_worker_code_paginated_manifest_pull(tmp_path: Path) -> None:
    """_WORKER_CODE PULL paginates file lists when manifest exceeds the inline bound."""
    src_dir = tmp_path / "large_tree"
    src_dir.mkdir()
    # Create 300 files with 30-char names so manifest probe JSON exceeds 32 KiB
    file_names = [f"file_{i:04d}_{'y' * 30}.txt" for i in range(300)]
    for fname in file_names:
        (src_dir / fname).write_bytes(b"data")

    s1, s2 = socket.socketpair()
    s2_fd = s2.fileno()
    proc = subprocess.Popen(
        [sys.executable, "-u", "-c", moecp._WORKER_CODE],
        stdin=s2_fd,
        stdout=s2_fd,
    )
    s2.close()

    try:
        # Read ready banner
        banner = s1.recv(len(moecp.MAGIC_READY))
        assert banner == moecp.MAGIC_READY

        # Open PULL session
        _send(s1, {"direction": "PULL", "source": str(src_dir), "recursive": True})
        manifest, _ = _recv(s1)

        assert manifest["status"] == "OK"
        assert manifest["is_dir"] is True
        assert manifest.get("paginated") is True
        assert manifest["count"] == 300
        assert manifest["page_size"] == 256

        # Pull page 0
        _send(s1, {"op": "LIST", "page": 0})
        page0, _ = _recv(s1)
        assert page0["op"] == "MANIFEST"
        assert page0["page"] == 0
        assert len(page0["files"]) == 256
        assert page0["more"] is True
        assert "sha256" in page0["files"][0]

        # Pull page 1
        _send(s1, {"op": "LIST", "page": 1})
        page1, _ = _recv(s1)
        assert page1["op"] == "MANIFEST"
        assert page1["page"] == 1
        assert len(page1["files"]) == 44
        assert page1["more"] is False
        assert "sha256" in page1["files"][0]

        # Close session
        _send(s1, {"op": "DONE"})
        done_ack, _ = _recv(s1)
        assert done_ack["status"] == "DONE"
    finally:
        with contextlib.suppress(OSError):
            s1.close()
        if proc.poll() is None:
            proc.kill()


def test_worker_code_push_staging_durability(tmp_path: Path) -> None:
    """_WORKER_CODE PUSH stages files using secure nonces, 0600 mode, and atomic rename."""
    dest_dir = tmp_path / "push_dest"
    dest_dir.mkdir()

    s1, s2 = socket.socketpair()
    s2_fd = s2.fileno()
    proc = subprocess.Popen(
        [sys.executable, "-u", "-c", moecp._WORKER_CODE],
        stdin=s2_fd,
        stdout=s2_fd,
    )
    s2.close()

    try:
        banner = s1.recv(len(moecp.MAGIC_READY))
        assert banner == moecp.MAGIC_READY

        # Open PUSH session
        _send(s1, {"direction": "PUSH", "target": str(dest_dir), "is_dir": True})
        ready_ack, _ = _recv(s1)
        assert ready_ack["status"] == "OK"

        payload = b"transactional durability test content"
        sha = hashlib.sha256(payload).hexdigest()

        # Start file transfer
        _send(
            s1,
            {
                "op": "FILE_START",
                "rel_path": "durable_file.bin",
                "size": len(payload),
                "mode": 0o644,
                "sha256": sha,
            },
        )
        file_ready, _ = _recv(s1)
        assert file_ready["status"] == "READY"

        # While file is open, inspect the staging file in dest_dir
        parts = [f for f in os.listdir(dest_dir) if "durable_file.bin.part." in f]
        assert len(parts) == 1
        part_name = parts[0]

        # Verify nonce format (16 hex chars, NOT a pid)
        match = re.search(r"durable_file\.bin\.part\.([0-9a-f]{16})$", part_name)
        assert match is not None, f"staging file {part_name} does not use 16-hex nonce"

        # Verify mode 0o600
        st = os.stat(dest_dir / part_name)
        assert oct(st.st_mode & 0o777) == oct(0o600)

        # Stream chunk and finish
        _send(s1, {"op": "CHUNK", "encoding": "raw"}, payload)
        _send(s1, {"op": "FILE_END"})

        commit_ack, _ = _recv(s1)
        assert commit_ack["status"] == "OK"
        assert commit_ack["sha256"] == sha

        # Staging file replaced with final file
        assert not os.path.exists(dest_dir / part_name)
        final_file = dest_dir / "durable_file.bin"
        assert final_file.exists()
        assert final_file.read_bytes() == payload

        _send(s1, {"op": "DONE"})
        done_ack, _ = _recv(s1)
        assert done_ack["status"] == "DONE"
    finally:
        with contextlib.suppress(OSError):
            s1.close()
        if proc.poll() is None:
            proc.kill()


def test_worker_code_push_refuses_symlink_destination(tmp_path: Path) -> None:
    """_WORKER_CODE PUSH refuses to replace an existing symlink."""
    dest_dir = tmp_path / "symlink_dest"
    dest_dir.mkdir()

    target_file = tmp_path / "outside.txt"
    target_file.write_bytes(b"original")

    link_path = dest_dir / "link.txt"
    link_path.symlink_to(target_file)

    s1, s2 = socket.socketpair()
    s2_fd = s2.fileno()
    proc = subprocess.Popen(
        [sys.executable, "-u", "-c", moecp._WORKER_CODE],
        stdin=s2_fd,
        stdout=s2_fd,
    )
    s2.close()

    try:
        s1.recv(len(moecp.MAGIC_READY))
        _send(s1, {"direction": "PUSH", "target": str(dest_dir), "is_dir": True})
        _recv(s1)

        _send(
            s1,
            {
                "op": "FILE_START",
                "rel_path": "link.txt",
                "size": 5,
                "sha256": "0" * 64,
            },
        )
        reply, _ = _recv(s1)
        assert reply["status"] == "ERROR"
        assert "refusing to replace symlink" in reply["message"]

        # Ensure original file and link were untouched
        assert target_file.read_bytes() == b"original"
        assert link_path.is_symlink()
    finally:
        with contextlib.suppress(OSError):
            s1.close()
        if proc.poll() is None:
            proc.kill()


def test_worker_code_push_checksum_mismatch_cleans_up_staging(
    tmp_path: Path,
) -> None:
    """_WORKER_CODE PUSH unlinks the staging file on checksum mismatch."""
    dest_dir = tmp_path / "cleanup_dest"
    dest_dir.mkdir()

    s1, s2 = socket.socketpair()
    s2_fd = s2.fileno()
    proc = subprocess.Popen(
        [sys.executable, "-u", "-c", moecp._WORKER_CODE],
        stdin=s2_fd,
        stdout=s2_fd,
    )
    s2.close()

    try:
        s1.recv(len(moecp.MAGIC_READY))
        _send(s1, {"direction": "PUSH", "target": str(dest_dir), "is_dir": True})
        _recv(s1)

        _send(
            s1,
            {
                "op": "FILE_START",
                "rel_path": "corrupted.txt",
                "size": 5,
                "sha256": "0" * 64,  # Intentionally wrong expected checksum
            },
        )
        _recv(s1)

        _send(s1, {"op": "CHUNK", "encoding": "raw"}, b"hello")
        _send(s1, {"op": "FILE_END"})

        reply, _ = _recv(s1)
        assert reply["status"] == "ERROR"
        assert "checksum mismatch" in reply["message"]

        proc.wait(timeout=2.0)
        assert proc.returncode == 1

        # Check that no temporary staging files remain
        remaining = os.listdir(dest_dir)
        assert not remaining, f"staging files leaked after error: {remaining}"
    finally:
        with contextlib.suppress(OSError):
            s1.close()
        if proc.poll() is None:
            proc.kill()


def test_worker_code_pull_symlink_handling_topology(tmp_path: Path) -> None:
    """_WORKER_CODE PULL uses lstat, skips broken or directory symlinks safely, and pulls good symlinks."""
    tree = tmp_path / "sym_tree"
    tree.mkdir()

    # 1. Regular file
    reg_file = tree / "regular.txt"
    reg_file.write_bytes(b"regular content")

    # 2. Good symlink to regular file
    good_sym = tree / "good_sym.txt"
    good_sym.symlink_to(reg_file.name)

    # 3. Broken symlink
    broken_sym = tree / "broken_sym.txt"
    broken_sym.symlink_to("nonexistent.txt")

    # 4. Symlink to directory
    sub_dir = tree / "subdir"
    sub_dir.mkdir()
    dir_sym = tree / "dir_sym"
    dir_sym.symlink_to("subdir")

    s1, s2 = socket.socketpair()
    s2_fd = s2.fileno()
    proc = subprocess.Popen(
        [sys.executable, "-u", "-c", moecp._WORKER_CODE],
        stdin=s2_fd,
        stdout=s2_fd,
    )
    s2.close()

    try:
        banner = s1.recv(len(moecp.MAGIC_READY))
        assert banner == moecp.MAGIC_READY

        # Request recursive PULL
        _send(s1, {"direction": "PULL", "source": str(tree), "recursive": True})
        manifest, _ = _recv(s1)

        assert manifest["status"] == "OK"
        assert manifest["is_dir"] is True
        files = {f["rel"]: f for f in manifest["files"]}

        # regular.txt and good_sym.txt must be in manifest
        assert "regular.txt" in files
        assert "good_sym.txt" in files
        assert files["regular.txt"]["size"] == len(b"regular content")
        assert files["good_sym.txt"]["size"] == len(b"regular content")

        # broken_sym.txt and dir_sym must be excluded, not crashed
        assert "broken_sym.txt" not in files
        assert "dir_sym" not in files

        # Verify pulling good_sym.txt streams the target file content
        _send(s1, {"op": "PULL_FILE", "rel": "good_sym.txt"})
        chunk_hdr, chunk_data = _recv(s1)
        assert chunk_hdr["op"] == "CHUNK"
        assert chunk_data == b"regular content"

        end_hdr, _ = _recv(s1)
        assert end_hdr["op"] == "FILE_END"
        _send(s1, {"status": "OK"})

        # Finish session
        _send(s1, {"op": "DONE"})
        done_ack, _ = _recv(s1)
        assert done_ack["status"] == "DONE"
    finally:
        with contextlib.suppress(OSError):
            s1.close()
        if proc.poll() is None:
            proc.kill()


def test_worker_code_pull_single_broken_symlink_refused(tmp_path: Path) -> None:
    """_WORKER_CODE PULL refuses single file that is a broken symlink."""
    broken = tmp_path / "dangling.txt"
    broken.symlink_to("missing.txt")

    s1, s2 = socket.socketpair()
    s2_fd = s2.fileno()
    proc = subprocess.Popen(
        [sys.executable, "-u", "-c", moecp._WORKER_CODE],
        stdin=s2_fd,
        stdout=s2_fd,
    )
    s2.close()

    try:
        banner = s1.recv(len(moecp.MAGIC_READY))
        assert banner == moecp.MAGIC_READY

        _send(s1, {"direction": "PULL", "source": str(broken), "recursive": False})
        reply, _ = _recv(s1)
        assert reply["status"] == "ERROR"
        assert "No such file or directory" in reply["message"] or "not a regular file" in reply["message"].lower()
    finally:
        with contextlib.suppress(OSError):
            s1.close()
        if proc.poll() is None:
            proc.kill()


def test_worker_code_pull_resumption_with_offset(tmp_path: Path) -> None:
    """_WORKER_CODE PULL resumes file transfer from offset and validates whole-file SHA-256."""
    src_file = tmp_path / "resumable.bin"
    # 100 KB payload of deterministic pseudorandom data
    payload = bytes((i * 37) % 256 for i in range(100_000))
    src_file.write_bytes(payload)
    full_sha = hashlib.sha256(payload).hexdigest()

    s1, s2 = socket.socketpair()
    s2_fd = s2.fileno()
    proc = subprocess.Popen(
        [sys.executable, "-u", "-c", moecp._WORKER_CODE],
        stdin=s2_fd,
        stdout=s2_fd,
    )
    s2.close()

    try:
        banner = s1.recv(len(moecp.MAGIC_READY))
        assert banner == moecp.MAGIC_READY

        _send(s1, {"direction": "PULL", "source": str(src_file), "recursive": False, "compression": "raw"})
        manifest, _ = _recv(s1)
        assert manifest["status"] == "OK"

        # Resume from byte offset 40,000
        offset = 40_000
        _send(s1, {"op": "PULL_FILE", "rel": src_file.name, "offset": offset})

        received = bytearray()
        while True:
            chunk_hdr, chunk_data = _recv(s1)
            op = chunk_hdr.get("op")
            if op == "CHUNK":
                received.extend(chunk_data)
            elif op == "FILE_END":
                assert chunk_hdr["sha256"] == full_sha
                break
            else:
                raise AssertionError(f"unexpected op: {op}")

        # Received data must equal the remaining 60,000 bytes exactly
        assert len(received) == 60_000
        assert received == payload[offset:]

        _send(s1, {"status": "OK"})
        _send(s1, {"op": "DONE"})
        done_ack, _ = _recv(s1)
        assert done_ack["status"] == "DONE"
    finally:
        with contextlib.suppress(OSError):
            s1.close()
        if proc.poll() is None:
            proc.kill()


def test_worker_code_push_premature_disconnect_unlinks_part(tmp_path: Path) -> None:
    """_WORKER_CODE PUSH unlinks .part staging file when client disconnects mid-stream."""
    dest_dir = tmp_path / "push_abort_dest"
    dest_dir.mkdir()

    s1, s2 = socket.socketpair()
    s2_fd = s2.fileno()
    proc = subprocess.Popen(
        [sys.executable, "-u", "-c", moecp._WORKER_CODE],
        stdin=s2_fd,
        stdout=s2_fd,
    )
    s2.close()

    try:
        banner = s1.recv(len(moecp.MAGIC_READY))
        assert banner == moecp.MAGIC_READY

        _send(s1, {"direction": "PUSH", "target": str(dest_dir), "is_dir": True})
        ack, _ = _recv(s1)
        assert ack["status"] == "OK"

        # Start uploading a 50 KB file
        _send(
            s1,
            {
                "op": "FILE_START",
                "rel_path": "aborted.bin",
                "size": 50_000,
                "sha256": "0" * 64,
            },
        )
        ready_ack, _ = _recv(s1)
        assert ready_ack["status"] == "READY"

        # Send only 10 KB then abruptly close the connection
        _send(s1, {"op": "CHUNK", "encoding": "raw"}, b"x" * 10_000)
        s1.close()

        proc.wait(timeout=2.0)
        assert proc.returncode == 1

        # Verify no .part.* files leaked in destination directory
        leaked = os.listdir(dest_dir)
        assert not leaked, f"orphaned staging files leaked on disconnect: {leaked}"
    finally:
        if proc.poll() is None:
            proc.kill()
