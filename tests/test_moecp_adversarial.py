#!/usr/bin/env python3
"""Adversarial, boundary, and fault-injection test suite for moecp.

Implements the testing discipline mandated by test-framework-creation and llm-testing-patterns:
- G-SEC: Path traversal injection (Zip Slip), frame-length bombs, null bytes, sandbox escapes.
- G-EDGE: Zero-byte files, multi-chunk streams (512 KiB), special characters, spaces, unicode.
- G-ERR: In-flight SHA-256 mismatch rollback, corrupted zlib streams, missing sources, permission bounds.
- C1-C6: Framing contracts, state-machine ordering, atomic cleanup on failure.
- T-* Verification: Mutation-resistant, strict oracles with exact byte, checksum, and file state assertions.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import struct
import subprocess
import threading
import zlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

import pytest

import moecp
from moesh_proto import Msg, ProtocolError
from tests.harness import AGENT_PYTHON, TUNNEL_DIR
from tests.test_moecp import MoecpHosts, moecp_test_env

_ALPHA = "alpha"

# Prevent pytest from thinking moecp_test_env is unused in this module
_ = moecp_test_env


# ─────────────────────────────────────────────────────────────────────────────
# Test Helpers for Worker & Protocol Verification
# ─────────────────────────────────────────────────────────────────────────────

class _DummySecure:
    """Mock SecureChannel backing a FramedStreamClient over a raw socket."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock

    def buffered(self) -> list[tuple[int, bytes]]:
        return []

    def drain(self) -> list[tuple[int, bytes]]:
        data = self.sock.recv(65536)
        if not data:
            from moesh_proto import TransportEOF
            raise TransportEOF("closed")
        return [(Msg.DATA, data)]

    def send(self, msg_type: int, data: bytes) -> None:
        self.sock.sendall(data)


def _send_proc_frame(proc: subprocess.Popen[bytes], meta: dict[str, Any], payload: bytes = b"") -> None:
    """Send length-prefixed frame to a running subprocess worker."""
    assert proc.stdin is not None
    hdr = json.dumps(meta).encode("utf-8")
    frame = struct.pack(">II", len(hdr), len(payload)) + hdr + payload
    proc.stdin.write(frame)
    proc.stdin.flush()


def _recv_proc_frame(proc: subprocess.Popen[bytes]) -> tuple[dict[str, Any], bytes]:
    """Receive length-prefixed frame from a running subprocess worker."""
    assert proc.stdout is not None
    prefix = proc.stdout.read(8)
    assert len(prefix) == 8, f"expected 8 bytes header length, got {len(prefix)}"
    hlen, dlen = struct.unpack(">II", prefix)
    hdr_bytes = proc.stdout.read(hlen)
    meta = json.loads(hdr_bytes.decode("utf-8"))
    payload = proc.stdout.read(dlen) if dlen > 0 else b""
    return meta, payload


# ─────────────────────────────────────────────────────────────────────────────
# 1. Unit & Protocol Invariant Tests (Fast execution, direct engine analysis)
# ─────────────────────────────────────────────────────────────────────────────

def test_sanitize_relpath_adversarial_traversals() -> None:
    """G-SEC: Path traversal sequences and absolute roots must raise ValueError."""
    adversarial_payloads = [
        "../etc/passwd",
        "../../shadow",
        "a/../../b",
        "nested/../../../root",
        "/absolute/path/file.txt",
        "\\\\server\\share\\file.txt",
        "..",
        "./..",
        "foo/../..",
        "bad\0byte.txt",
        "normal/path\0/evil.txt",
        "",
        ".",
    ]
    for payload in adversarial_payloads:
        with pytest.raises(ValueError):
            moecp.sanitize_relpath(payload)


def test_sanitize_relpath_valid_edge_cases() -> None:
    """G-EDGE: Clean relative paths with spaces, unicode, and symbols are accepted."""
    valid_paths = [
        "normal.txt",
        "folder/child.bin",
        "deep/nested/sub/dir/data.json",
        "file with spaces.txt",
        "файл_тест_🚀.dat",
        "file-with-dashes_and_underscores.tar.gz",
        "./explicit_relative/file.txt",
        "a/b/c/d/e.txt",
    ]
    for p in valid_paths:
        sanitized = moecp.sanitize_relpath(p)
        assert not sanitized.startswith("/")
        assert not sanitized.startswith("..")
        assert ".." not in sanitized.split("/")
        assert "\0" not in sanitized


def test_parse_path_spec_colon_in_local_filename() -> None:
    """G-SEM: Colons in local filenames preceded by slashes must not be treated as remote hosts."""
    spec1 = moecp.parse_path_spec("./model:v1.pt")
    assert spec1.is_remote is False
    assert spec1.path == "./model:v1.pt"

    spec2 = moecp.parse_path_spec("/var/log/dataset:2026.csv")
    assert spec2.is_remote is False
    assert spec2.path == "/var/log/dataset:2026.csv"

    spec3 = moecp.parse_path_spec("host-3:/opt/model:v1.pt")
    assert spec3.is_remote is True
    assert spec3.host == "host-3"
    assert spec3.path == "/opt/model:v1.pt"


def test_framed_client_rejects_oversized_frame_header() -> None:
    """G-SEC / G-ERR: Frame headers exceeding MAX_FRAME_HDR must be rejected to prevent OOM."""
    s1, s2 = socket.socketpair()
    try:
        client = moecp.FramedStreamClient(_DummySecure(s1), s1)  # type: ignore[arg-type]
        bad_len_prefix = struct.pack(">II", 70000, 0)
        s2.sendall(bad_len_prefix)

        with pytest.raises(ProtocolError, match="exceeding safety bounds"):
            client.recv_frame(timeout=2.0)
    finally:
        s1.close()
        s2.close()


def test_framed_client_rejects_oversized_payload() -> None:
    """G-SEC / G-ERR: Frame payloads exceeding MAX_FRAME_PAYLOAD must be rejected."""
    s1, s2 = socket.socketpair()
    try:
        client = moecp.FramedStreamClient(_DummySecure(s1), s1)  # type: ignore[arg-type]
        bad_len_prefix = struct.pack(">II", 10, 15 * 1024 * 1024)
        s2.sendall(bad_len_prefix)

        with pytest.raises(ProtocolError, match="exceeding safety bounds"):
            client.recv_frame(timeout=2.0)
    finally:
        s1.close()
        s2.close()


def test_worker_rejects_path_traversal_on_upload(tmp_path: Path) -> None:
    """G-SEC: Worker must reject path traversal attempts and never write outside target."""
    sandbox = tmp_path / "worker_sandbox"
    sandbox.mkdir()

    proc = subprocess.Popen(
        [AGENT_PYTHON, "-u", "-c", moecp._WORKER_CODE],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    try:
        assert proc.stdout is not None
        assert proc.stdout.readline() == b"MOECP_READY_V1\n"

        _send_proc_frame(proc, {"direction": "PUSH", "target": str(sandbox)})
        ack, _ = _recv_proc_frame(proc)
        assert ack["status"] == "OK"

        # Inject traversal in rel_path
        _send_proc_frame(
            proc,
            {
                "op": "FILE_START",
                "rel_path": "../../../escaped_target.txt",
                "size": 10,
                "mode": 0o644,
                "mtime": 100,
                "sha256": "fake_sha",
            },
        )
        resp, _ = _recv_proc_frame(proc)
        assert resp["status"] == "ERROR"
        assert "traversal" in resp["message"].lower() or "insecure" in resp["message"].lower()

        # Invariant: file was NOT created outside sandbox
        escaped_file = tmp_path / "escaped_target.txt"
        assert not escaped_file.exists()
    finally:
        proc.terminate()
        proc.wait()


def test_worker_handles_tampered_payload_rollback(tmp_path: Path) -> None:
    """G-ERR: Worker must detect checksum mismatch, delete partial file, and report ERROR."""
    target_dir = tmp_path / "worker_target"
    target_dir.mkdir()

    proc = subprocess.Popen(
        [AGENT_PYTHON, "-u", "-c", moecp._WORKER_CODE],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    try:
        assert proc.stdout is not None
        assert proc.stdout.readline() == b"MOECP_READY_V1\n"

        _send_proc_frame(proc, {"direction": "PUSH", "target": str(target_dir)})
        ack, _ = _recv_proc_frame(proc)
        assert ack["status"] == "OK"

        dest_file = target_dir / "tampered.bin"
        _send_proc_frame(
            proc,
            {
                "op": "FILE_START",
                "rel_path": "tampered.bin",
                "size": 11,
                "mode": 0o644,
                "mtime": 100,
                "sha256": "expected_valid_sha256_that_does_not_match",
            },
        )
        ready, _ = _recv_proc_frame(proc)
        assert ready["status"] == "READY"

        # Send chunk
        chunk_data = zlib.compress(b"tampered content")
        _send_proc_frame(proc, {"op": "CHUNK"}, chunk_data)
        _send_proc_frame(proc, {"op": "FILE_END"})

        resp, _ = _recv_proc_frame(proc)
        assert resp["status"] == "ERROR"
        assert "checksum mismatch" in resp["message"]

        # Atomic rollback verification: corrupt file deleted, no leftover .part files
        assert not dest_file.exists()
        assert len(os.listdir(target_dir)) == 0, f"leftover temporary files: {os.listdir(target_dir)}"
    finally:
        proc.terminate()
        proc.wait()


def test_worker_handles_corrupt_zlib_chunk(tmp_path: Path) -> None:
    """G-ERR: Worker must handle corrupted compressed stream cleanly with rollback."""
    target_dir = tmp_path / "zlib_target"
    target_dir.mkdir()

    proc = subprocess.Popen(
        [AGENT_PYTHON, "-u", "-c", moecp._WORKER_CODE],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    try:
        assert proc.stdout is not None
        assert proc.stdout.readline() == b"MOECP_READY_V1\n"

        _send_proc_frame(proc, {"direction": "PUSH", "target": str(target_dir)})
        ack, _ = _recv_proc_frame(proc)
        assert ack["status"] == "OK"

        dest_file = target_dir / "corrupt_zlib.bin"
        _send_proc_frame(
            proc,
            {
                "op": "FILE_START",
                "rel_path": "corrupt_zlib.bin",
                "size": 100,
                "mode": 0o644,
                "mtime": 100,
                "sha256": "any",
            },
        )
        ready, _ = _recv_proc_frame(proc)
        assert ready["status"] == "READY"

        # Send invalid zlib bytes
        _send_proc_frame(proc, {"op": "CHUNK"}, b"GARBAGE_NON_ZLIB_DATA")

        resp, _ = _recv_proc_frame(proc)
        assert resp["status"] == "ERROR"
        assert not dest_file.exists()
        assert len(os.listdir(target_dir)) == 0
    finally:
        proc.terminate()
        proc.wait()


def test_worker_handles_out_of_order_op(tmp_path: Path) -> None:
    """C4: Worker must enforce op ordering invariant (reject CHUNK without FILE_START)."""
    target_dir = tmp_path / "order_target"
    target_dir.mkdir()

    proc = subprocess.Popen(
        [AGENT_PYTHON, "-u", "-c", moecp._WORKER_CODE],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    try:
        assert proc.stdout is not None
        assert proc.stdout.readline() == b"MOECP_READY_V1\n"

        _send_proc_frame(proc, {"direction": "PUSH", "target": str(target_dir)})
        ack, _ = _recv_proc_frame(proc)
        assert ack["status"] == "OK"

        # Send CHUNK directly without FILE_START
        _send_proc_frame(proc, {"op": "CHUNK"}, b"data")
        resp, _ = _recv_proc_frame(proc)
        assert resp["status"] == "ERROR"
        assert "unexpected op" in resp["message"]
    finally:
        proc.terminate()
        proc.wait()


def test_client_rejects_malicious_remote_manifest(tmp_path: Path) -> None:
    """G-SEC: Client downloading files must reject directory traversal in remote manifests."""
    s1, s2 = socket.socketpair()
    try:
        client = moecp.FramedStreamClient(_DummySecure(s1), s1)  # type: ignore[arg-type]
        ret: list[int] = []

        def run_client() -> None:
            r = moecp.download_files(
                client,
                moecp.PathSpec(is_remote=True, host="host-1", path="/src"),
                str(tmp_path),
                recursive=True,
                preserve=False,
                quiet=True,
            )
            ret.append(r)

        t = threading.Thread(target=run_client)
        t.start()

        # Read INIT from client
        p = s2.recv(8)
        hl, _ = struct.unpack(">II", p)
        meta = json.loads(s2.recv(hl))
        assert meta["op"] == "INIT"

        # Send malicious manifest with traversal in rel
        manifest = {
            "status": "OK",
            "is_dir": True,
            "files": [{"rel": "../../../escaped_client.txt", "size": 10, "mode": 0o644, "mtime": 100}],
        }
        hdr = json.dumps(manifest).encode("utf-8")
        s2.sendall(struct.pack(">II", len(hdr), 0) + hdr)

        # Read client's error response
        p = s2.recv(8)
        hl, _ = struct.unpack(">II", p)
        resp = json.loads(s2.recv(hl))
        assert resp["status"] == "ERROR"

        t.join()
        assert ret[0] == 1, f"client returned {ret[0]}, expected exit code 1"
        escaped_target = tmp_path.parent / "escaped_client.txt"
        assert not escaped_target.exists()
    finally:
        s1.close()
        s2.close()


def test_client_download_integrity_failure_rollback(tmp_path: Path) -> None:
    """G-ERR: Client downloading files must delete partial file on SHA-256 mismatch."""
    s1, s2 = socket.socketpair()
    try:
        client = moecp.FramedStreamClient(_DummySecure(s1), s1)  # type: ignore[arg-type]
        local_dest = tmp_path / "corrupted_download.bin"
        ret: list[int] = []

        def run_client() -> None:
            r = moecp.download_files(
                client,
                moecp.PathSpec(is_remote=True, host="host-1", path="/src"),
                str(local_dest),
                recursive=False,
                preserve=False,
                quiet=True,
            )
            ret.append(r)

        t = threading.Thread(target=run_client)
        t.start()

        # Read INIT
        p = s2.recv(8)
        hl, _ = struct.unpack(">II", p)
        assert json.loads(s2.recv(hl))["op"] == "INIT"

        # Send valid manifest
        manifest = {
            "status": "OK",
            "is_dir": False,
            "files": [{"rel": "corrupted_download.bin", "size": 11, "mode": 0o644, "mtime": 100}],
        }
        hdr = json.dumps(manifest).encode("utf-8")
        s2.sendall(struct.pack(">II", len(hdr), 0) + hdr)

        # Read PULL_FILE request
        p = s2.recv(8)
        hl, _ = struct.unpack(">II", p)
        assert json.loads(s2.recv(hl))["op"] == "PULL_FILE"

        # Send chunk + mismatched sha in FILE_END
        cdata = zlib.compress(b"valid content")
        chdr = json.dumps({"op": "CHUNK"}).encode("utf-8")
        s2.sendall(struct.pack(">II", len(chdr), len(cdata)) + chdr + cdata)

        ehdr = json.dumps({"op": "FILE_END", "sha256": "mismatched_sha256"}).encode("utf-8")
        s2.sendall(struct.pack(">II", len(ehdr), 0) + ehdr)

        # Client should report error
        p = s2.recv(8)
        hl, _ = struct.unpack(">II", p)
        resp = json.loads(s2.recv(hl))
        assert resp["status"] == "ERROR"

        t.join()
        assert ret[0] == 1
        # Invariant: corrupted file must not be committed to disk
        assert not local_dest.exists()
        assert len(os.listdir(tmp_path)) == 0
    finally:
        s1.close()
        s2.close()


# ─────────────────────────────────────────────────────────────────────────────
# 2. End-to-End Adversarial & Boundary Integration Tests (Live over Noise_XX)
# ─────────────────────────────────────────────────────────────────────────────

def test_e2e_zero_byte_file_transfer(moecp_test_env: MoecpHosts, tmp_path: Path) -> None:
    """G-EDGE: 0-byte file upload and download must succeed with exact empty digest."""
    empty_src = tmp_path / "empty_file.bin"
    empty_src.write_bytes(b"")
    assert empty_src.stat().st_size == 0

    remote_dest = tmp_path / "remote_empty.bin"
    env = moecp_test_env["client_env"](_ALPHA)

    # 1. Upload 0-byte file
    up_cmd = [
        AGENT_PYTHON,
        os.path.join(TUNNEL_DIR, "moecp.py"),
        "-q",
        str(empty_src),
        f"{_ALPHA}:{remote_dest}",
    ]
    proc_up = subprocess.run(up_cmd, env=env, capture_output=True, text=True, timeout=30)
    assert proc_up.returncode == 0, f"0-byte upload failed: {proc_up.stderr}"
    assert remote_dest.exists(), "remote 0-byte destination was not created"
    assert remote_dest.stat().st_size == 0
    assert hashlib.sha256(remote_dest.read_bytes()).hexdigest() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    # 2. Download 0-byte file back
    local_download = tmp_path / "downloaded_empty.bin"
    down_cmd = [
        AGENT_PYTHON,
        os.path.join(TUNNEL_DIR, "moecp.py"),
        "-q",
        f"{_ALPHA}:{remote_dest}",
        str(local_download),
    ]
    proc_down = subprocess.run(down_cmd, env=env, capture_output=True, text=True, timeout=30)
    assert proc_down.returncode == 0, f"0-byte download failed: {proc_down.stderr}"
    assert local_download.exists()
    assert local_download.stat().st_size == 0


def test_e2e_special_characters_filename(moecp_test_env: MoecpHosts, tmp_path: Path) -> None:
    """G-EDGE: Filenames with spaces, quotes, brackets, and unicode symbols transfer cleanly."""
    weird_name = "test file (1) [copy] & 'quote' #1 🚀.txt"
    src_file = tmp_path / weird_name
    test_content = b"Special filename payload with symbols & unicode: \xf0\x9f\x9a\x80"
    src_file.write_bytes(test_content)

    remote_dest = tmp_path / f"remote_{weird_name}"
    env = moecp_test_env["client_env"](_ALPHA)

    # Upload
    up_cmd = [
        AGENT_PYTHON,
        os.path.join(TUNNEL_DIR, "moecp.py"),
        "-q",
        str(src_file),
        f"{_ALPHA}:{remote_dest}",
    ]
    proc_up = subprocess.run(up_cmd, env=env, capture_output=True, text=True, timeout=30)
    assert proc_up.returncode == 0, f"special filename upload failed: {proc_up.stderr}"
    assert remote_dest.exists()
    assert remote_dest.read_bytes() == test_content

    # Download back
    download_dir = tmp_path / "download_special"
    download_dir.mkdir()
    down_dest = download_dir / weird_name
    down_cmd = [
        AGENT_PYTHON,
        os.path.join(TUNNEL_DIR, "moecp.py"),
        "-q",
        f"{_ALPHA}:{remote_dest}",
        str(down_dest),
    ]
    proc_down = subprocess.run(down_cmd, env=env, capture_output=True, text=True, timeout=30)
    assert proc_down.returncode == 0, f"special filename download failed: {proc_down.stderr}"
    assert down_dest.exists()
    assert down_dest.read_bytes() == test_content


def test_e2e_large_multichunk_file_transfer(moecp_test_env: MoecpHosts, tmp_path: Path) -> None:
    """G-PERF / G-EDGE: Transfer a 512 KiB file spanning 16+ chunks of 32 KiB each."""
    src_file = tmp_path / "large_file.bin"
    # Deterministic pseudo-random pattern to verify exact byte sequence
    pattern = bytearray()
    for i in range(512 * 1024):
        pattern.append((i * 31 + 17) & 0xFF)
    test_data = bytes(pattern)
    src_file.write_bytes(test_data)
    expected_sha = hashlib.sha256(test_data).hexdigest()

    remote_dest = tmp_path / "remote_large.bin"
    env = moecp_test_env["client_env"](_ALPHA)

    # Upload
    up_cmd = [
        AGENT_PYTHON,
        os.path.join(TUNNEL_DIR, "moecp.py"),
        "-q",
        str(src_file),
        f"{_ALPHA}:{remote_dest}",
    ]
    proc_up = subprocess.run(up_cmd, env=env, capture_output=True, text=True, timeout=45)
    assert proc_up.returncode == 0, f"large file upload failed: {proc_up.stderr}"
    assert remote_dest.exists()
    assert hashlib.sha256(remote_dest.read_bytes()).hexdigest() == expected_sha

    # Download
    local_down = tmp_path / "downloaded_large.bin"
    down_cmd = [
        AGENT_PYTHON,
        os.path.join(TUNNEL_DIR, "moecp.py"),
        "-q",
        f"{_ALPHA}:{remote_dest}",
        str(local_down),
    ]
    proc_down = subprocess.run(down_cmd, env=env, capture_output=True, text=True, timeout=45)
    assert proc_down.returncode == 0, f"large file download failed: {proc_down.stderr}"
    assert hashlib.sha256(local_down.read_bytes()).hexdigest() == expected_sha


def test_e2e_deeply_nested_directory_tree(moecp_test_env: MoecpHosts, tmp_path: Path) -> None:
    """G-EDGE: 6-level deeply nested directory hierarchy transfer."""
    nested_root = tmp_path / "nested_hierarchy"
    deep_dir = nested_root / "l1" / "l2" / "l3" / "l4" / "l5" / "l6"
    deep_dir.mkdir(parents=True)
    deep_file = deep_dir / "deep_file.txt"
    deep_file.write_text("depth level 6 content", encoding="utf-8")

    remote_tree = tmp_path / "remote_nested_hierarchy"
    env = moecp_test_env["client_env"](_ALPHA)

    # Recursive upload
    up_cmd = [
        AGENT_PYTHON,
        os.path.join(TUNNEL_DIR, "moecp.py"),
        "-r",
        "-q",
        str(nested_root),
        f"{_ALPHA}:{remote_tree}",
    ]
    proc_up = subprocess.run(up_cmd, env=env, capture_output=True, text=True, timeout=35)
    assert proc_up.returncode == 0, f"deep directory upload failed: {proc_up.stderr}"

    remote_deep_file = remote_tree / "l1" / "l2" / "l3" / "l4" / "l5" / "l6" / "deep_file.txt"
    assert remote_deep_file.exists()
    assert remote_deep_file.read_text(encoding="utf-8") == "depth level 6 content"


def test_e2e_nonexistent_remote_source_fails(moecp_test_env: MoecpHosts, tmp_path: Path) -> None:
    """G-ERR: Downloading a missing remote file must return exit code 1 with clear stderr message."""
    missing_remote = tmp_path / "this_file_does_not_exist_at_all.bin"
    local_dest = tmp_path / "failed_download.bin"
    env = moecp_test_env["client_env"](_ALPHA)

    down_cmd = [
        AGENT_PYTHON,
        os.path.join(TUNNEL_DIR, "moecp.py"),
        "-q",
        f"{_ALPHA}:{missing_remote}",
        str(local_dest),
    ]
    proc = subprocess.run(down_cmd, env=env, capture_output=True, text=True, timeout=20)
    assert proc.returncode != 0
    assert not local_dest.exists(), "destination file must not exist on failed transfer"
    assert "no such file" in proc.stderr.lower() or "error" in proc.stderr.lower()


def test_e2e_unwritable_destination_fails_cleanly(moecp_test_env: MoecpHosts, tmp_path: Path) -> None:
    """G-ERR: Uploading to an unwritable remote path must fail cleanly without hanging."""
    src_file = tmp_path / "test_unwritable.bin"
    src_file.write_bytes(b"sample data")

    unwritable_dest = "/proc/moecp_illegal_write.bin"
    env = moecp_test_env["client_env"](_ALPHA)

    up_cmd = [
        AGENT_PYTHON,
        os.path.join(TUNNEL_DIR, "moecp.py"),
        "-q",
        str(src_file),
        f"{_ALPHA}:{unwritable_dest}",
    ]
    proc = subprocess.run(up_cmd, env=env, capture_output=True, text=True, timeout=20)
    assert proc.returncode != 0
    assert not os.path.exists(unwritable_dest)
