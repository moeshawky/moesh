#!/usr/bin/env python3
"""Wave 5 regression tests for moecp copy fixes.

Validates DEF-07, DEF-08, DEF-09, DEF-10, DEF-11, and FD leak / symlink hygiene.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

import pytest

import moecp
from moecp import (
    FramedStreamClient,
    PathSpec,
    StagedFile,
    TransferBusyError,
    parse_path_spec,
    upload_files,
)
from moesh_proto import Msg, ProtocolError, TransportEOF


def _pack_frame(meta: dict[str, Any], payload: bytes = b"") -> bytes:
    hdr = json.dumps(meta).encode("utf-8")
    return struct.pack(">II", len(hdr), len(payload)) + hdr + payload


# ─────────────────────────────────────────────────────────────────────────────
# DEF-09: [user@]host:path syntax in parse_path_spec
# ─────────────────────────────────────────────────────────────────────────────

def test_parse_path_spec_user_at_host() -> None:
    """DEF-09: parse_path_spec must accept user@ prefix without failing label check."""
    spec1 = parse_path_spec("ubuntu@host-3:/var/data/foo")
    assert spec1.is_remote is True
    assert spec1.host == "host-3"
    assert spec1.path == "/var/data/foo"

    spec2 = parse_path_spec("root@3:/var/data/bar")
    assert spec2.is_remote is True
    assert spec2.host == "host-3"
    assert spec2.path == "/var/data/bar"

    spec3 = parse_path_spec("operator@remote:/data", default_host="host-9")
    assert spec3.is_remote is True
    assert spec3.host == "host-9"
    assert spec3.path == "/data"

    spec4 = parse_path_spec("user.name-1@host-5:file.txt")
    assert spec4.is_remote is True
    assert spec4.host == "host-5"
    assert spec4.path == "file.txt"

    # Local path with colon preceded by slash must remain local
    spec5 = parse_path_spec("/local/user@host:path")
    assert spec5.is_remote is False
    assert spec5.path == "/local/user@host:path"


# ─────────────────────────────────────────────────────────────────────────────
# DEF-10: FramedStreamClient._read_more inspects record types
# ─────────────────────────────────────────────────────────────────────────────

class _MockSecureChannel:
    def __init__(self, records: list[tuple[int, bytes]]) -> None:
        self._records = list(records)

    def buffered(self) -> list[tuple[int, bytes]]:
        recs = self._records[:]
        self._records.clear()
        return recs

    def drain(self) -> list[tuple[int, bytes]]:
        return []


def test_framed_client_read_more_raises_protocol_error_on_msg_error() -> None:
    """DEF-10: FramedStreamClient._read_more must raise ProtocolError on Msg.ERROR."""
    s1, s2 = socket.socketpair()
    try:
        mock_secure = _MockSecureChannel([(Msg.ERROR, b"permission denied on destination")])
        client = FramedStreamClient(mock_secure, s1)  # type: ignore[arg-type]
        with pytest.raises(ProtocolError, match="remote error: permission denied on destination"):
            client._read_more(timeout=1.0)
    finally:
        s1.close()
        s2.close()


def test_framed_client_read_more_raises_transport_eof_on_msg_close() -> None:
    """DEF-10: FramedStreamClient._read_more must raise TransportEOF on Msg.CLOSE."""
    s1, s2 = socket.socketpair()
    try:
        mock_secure = _MockSecureChannel([(Msg.CLOSE, b"")])
        client = FramedStreamClient(mock_secure, s1)  # type: ignore[arg-type]
        with pytest.raises(TransportEOF, match="remote closed session"):
            client._read_more(timeout=1.0)
    finally:
        s1.close()
        s2.close()


# ─────────────────────────────────────────────────────────────────────────────
# DEF-07: Silent data destruction on multiple file upload to non-directory
# ─────────────────────────────────────────────────────────────────────────────

class _FakeSecureForUpload:
    def __init__(self, s: socket.socket) -> None:
        self.s = s

    def send(self, msg_type: int, payload: bytes) -> None:
        self.s.sendall(payload)

    def send_control(self, msg_type: int, obj: dict[str, Any]) -> None:
        pass

    def buffered(self) -> list[tuple[int, bytes]]:
        return []

    def drain(self) -> list[tuple[int, bytes]]:
        data = self.s.recv(65536)
        if not data:
            raise TransportEOF("closed")
        return [(Msg.DATA, data)]


def test_upload_multiple_files_to_non_dir_raises_protocol_error(tmp_path: Path) -> None:
    """DEF-07: upload_files aborts with ProtocolError when target_is_dir is False for multiple files."""
    f1 = tmp_path / "a.txt"
    f2 = tmp_path / "b.txt"
    f1.write_text("hello")
    f2.write_text("world")

    s_client, s_server = socket.socketpair()
    client = FramedStreamClient(_FakeSecureForUpload(s_client), s_client)  # type: ignore[arg-type]

    def server_thread() -> None:
        # Read INIT frame
        raw_len = s_server.recv(8)
        hlen, plen = struct.unpack(">II", raw_len)
        _ = s_server.recv(hlen + plen)
        # Respond with target_is_dir = False
        resp = _pack_frame({"status": "OK", "target_is_dir": False})
        s_server.sendall(resp)

    t = subprocess.threading.Thread(target=server_thread, daemon=True)
    t.start()

    dest_path = str(tmp_path / "existing_file")
    try:
        target = PathSpec(is_remote=True, host="host-1", path=dest_path)
        with pytest.raises(ProtocolError, match=f"destination '{dest_path}' is not a directory"):
            upload_files(client, [str(f1), str(f2)], target, recursive=False, preserve=False, quiet=True)
    finally:
        s_client.close()
        s_server.close()
        t.join(timeout=1.0)


def test_local_copy_multiple_files_to_non_dir_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """DEF-07: Local-to-local fallback rejects copying multiple files to a non-directory."""
    f1 = tmp_path / "f1.txt"
    f2 = tmp_path / "f2.txt"
    dest = tmp_path / "dest_file.txt"
    f1.write_text("file 1")
    f2.write_text("file 2")
    dest.write_text("existing content")

    rc = moecp.main([str(f1), str(f2), str(dest)])
    assert rc == 1
    captured = capsys.readouterr()
    assert f"destination '{dest}' is not a directory" in captured.err
    # Verify destination file was not overwritten
    assert dest.read_text() == "existing content"


# ─────────────────────────────────────────────────────────────────────────────
# DEF-08: _WORKER_CODE single file upload containment
# ─────────────────────────────────────────────────────────────────────────────

def test_worker_code_single_file_upload_success(tmp_path: Path) -> None:
    """DEF-08: Single-file upload in PTY worker code must succeed without path escape error."""
    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    target_file = dest_dir / "uploaded.txt"
    content = b"content for single file upload"
    content_sha = hashlib.sha256(content).hexdigest()

    proc = subprocess.Popen(
        [sys.executable, "-c", moecp._WORKER_CODE],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        assert proc.stdin is not None
        assert proc.stdout is not None

        # Consume the startup banner emitted by _WORKER_CODE
        banner = proc.stdout.readline()
        assert banner == b"MOECP_READY_V1\n"

        # 1. Send INIT
        init_frame = _pack_frame({
            "direction": "PUSH",
            "target": str(target_file),
            "is_dir": False,
            "preserve": False,
        })
        proc.stdin.write(init_frame)
        proc.stdin.flush()

        # Read INIT ACK
        raw_hdr = proc.stdout.read(8)
        hlen, plen = struct.unpack(">II", raw_hdr)
        ack_data = proc.stdout.read(hlen + plen)
        meta = json.loads(ack_data[:hlen].decode("utf-8"))
        assert meta.get("status") == "OK"
        assert meta.get("target_is_dir") is False

        # 2. Send FILE_START
        start_frame = _pack_frame({
            "op": "FILE_START",
            "rel_path": "uploaded.txt",
            "size": len(content),
            "mode": 0o644,
            "sha256": content_sha,
        })
        proc.stdin.write(start_frame)
        proc.stdin.flush()

        # Read READY ACK
        raw_hdr = proc.stdout.read(8)
        hlen, plen = struct.unpack(">II", raw_hdr)
        ready_data = proc.stdout.read(hlen + plen)
        meta = json.loads(ready_data[:hlen].decode("utf-8"))
        assert meta.get("status") == "READY", f"Worker failed: {meta}"

        # 3. Send CHUNK
        chunk_frame = _pack_frame({"op": "CHUNK", "encoding": "raw"}, content)
        proc.stdin.write(chunk_frame)
        proc.stdin.flush()

        # 4. Send FILE_END
        end_frame = _pack_frame({"op": "FILE_END"})
        proc.stdin.write(end_frame)
        proc.stdin.flush()

        # Read OK ACK
        raw_hdr = proc.stdout.read(8)
        hlen, plen = struct.unpack(">II", raw_hdr)
        end_data = proc.stdout.read(hlen + plen)
        meta = json.loads(end_data[:hlen].decode("utf-8"))
        assert meta.get("status") == "OK"

        # 5. Send DONE
        done_frame = _pack_frame({"op": "DONE"})
        proc.stdin.write(done_frame)
        proc.stdin.flush()

        # Read DONE ACK
        raw_hdr = proc.stdout.read(8)
        hlen, plen = struct.unpack(">II", raw_hdr)
        done_data = proc.stdout.read(hlen + plen)
        meta = json.loads(done_data[:hlen].decode("utf-8"))
        assert meta.get("status") == "DONE"

        proc.stdin.close()
        proc.wait(timeout=2.0)
        assert target_file.read_bytes() == content
    finally:
        if proc.poll() is None:
            proc.kill()


# ─────────────────────────────────────────────────────────────────────────────
# DEF-11: ProtocolError in connect_and_run and clean Msg.CLOSE
# ─────────────────────────────────────────────────────────────────────────────

def test_connect_and_run_catches_protocol_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """DEF-11: connect_and_run must catch ProtocolError and return 1 without traceback."""
    args = type("Args", (), {
        "addr": "127.0.0.1:9999",
        "keyfile": str(tmp_path / "nonexistent-key"),
        "retry": 1,
    })()

    monkeypatch.setattr(moecp, "resolve_operator_keys", lambda *a, **k: [b"\x00" * 32])
    monkeypatch.setattr(moecp, "pinned_key", lambda *a: b"\x00" * 32)

    s1, s2 = socket.socketpair()

    def fake_connect(*a: Any, **kw: Any) -> socket.socket:
        return s1

    monkeypatch.setattr(socket, "create_connection", fake_connect)
    monkeypatch.setattr(moecp, "handshake", lambda *a: None)
    monkeypatch.setattr(moecp, "negotiate", lambda *a, **kw: {"session_type": "transfer"})

    def failing_action(client: Any) -> int:
        raise ProtocolError("remote closed with fatal error")

    rc = moecp.connect_and_run("test-host", args, failing_action)
    assert rc == 1
    captured = capsys.readouterr()
    assert "moecp: connection interrupted: remote closed with fatal error" in captured.err
    s2.close()


def test_clean_transfer_sends_msg_close(tmp_path: Path) -> None:
    """DEF-11: upload_files transmits authenticated Msg.CLOSE when transfer completes cleanly."""
    f = tmp_path / "sample.txt"
    f.write_text("sample content")

    s_client, s_server = socket.socketpair()
    closed_received = False

    class _TrackingSecure:
        def __init__(self, s: socket.socket) -> None:
            self.s = s

        def send(self, msg_type: int, payload: bytes) -> None:
            self.s.sendall(payload)

        def send_control(self, msg_type: int, obj: dict[str, Any]) -> None:
            nonlocal closed_received
            if msg_type == Msg.CLOSE and obj.get("reason") == "transfer complete":
                closed_received = True

        def buffered(self) -> list[tuple[int, bytes]]:
            return []

        def drain(self) -> list[tuple[int, bytes]]:
            data = self.s.recv(65536)
            if not data:
                raise TransportEOF("closed")
            return [(Msg.DATA, data)]

    client = FramedStreamClient(_TrackingSecure(s_client), s_client)  # type: ignore[arg-type]

    def read_exact(s: socket.socket, n: int) -> bytes:
        b = bytearray()
        while len(b) < n:
            c = s.recv(n - len(b))
            if not c:
                raise EOFError("socket closed")
            b.extend(c)
        return bytes(b)

    def server_thread() -> None:
        # INIT
        raw = read_exact(s_server, 8)
        hl, pl = struct.unpack(">II", raw)
        _ = read_exact(s_server, hl + pl)
        s_server.sendall(_pack_frame({"status": "OK", "target_is_dir": False}))

        # FILE_START
        raw = read_exact(s_server, 8)
        hl, pl = struct.unpack(">II", raw)
        _ = read_exact(s_server, hl + pl)
        s_server.sendall(_pack_frame({"status": "READY", "offset": 0}))

        # CHUNK
        raw = read_exact(s_server, 8)
        hl, pl = struct.unpack(">II", raw)
        _ = read_exact(s_server, hl + pl)

        # FILE_END
        raw = read_exact(s_server, 8)
        hl, pl = struct.unpack(">II", raw)
        _ = read_exact(s_server, hl + pl)
        s_server.sendall(_pack_frame({"status": "OK"}))

        # DONE
        raw = read_exact(s_server, 8)
        hl, pl = struct.unpack(">II", raw)
        _ = read_exact(s_server, hl + pl)
        s_server.sendall(_pack_frame({"status": "DONE"}))

    t = subprocess.threading.Thread(target=server_thread, daemon=True)
    t.start()

    try:
        dest_path = str(tmp_path / "sample_dest.txt")
        target = PathSpec(is_remote=True, host="host-1", path=dest_path)
        rc = upload_files(client, [str(f)], target, False, False, quiet=True)
        assert rc == 0
        assert closed_received is True
    finally:
        s_client.close()
        s_server.close()
        t.join(timeout=1.0)


# ─────────────────────────────────────────────────────────────────────────────
# FD Leak & Broken Symlink Hygiene
# ─────────────────────────────────────────────────────────────────────────────

def test_staged_file_closes_dir_fd_on_transfer_busy(tmp_path: Path) -> None:
    """StagedFile dir_fd must not leak if staged.lock() raises TransferBusyError."""
    staged = StagedFile(str(tmp_path), ["sub", "target.txt"], "test_id")
    dir_fd = staged.dir_fd

    # Verify fd is valid
    st = os.fstat(dir_fd)
    assert st is not None

    with pytest.raises(TransferBusyError), contextlib.ExitStack() as stack:
        stack.callback(staged.close)
        raise TransferBusyError("destination is busy")

    # Verify fd is closed
    with pytest.raises(OSError) as excinfo:
        os.fstat(dir_fd)
    assert excinfo.value.errno == 9  # EBADF: Bad file descriptor


def test_upload_skips_broken_symlink_without_crashing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """upload_files must skip broken symlinks or unreadable files and continue with remaining files."""
    good_file = tmp_path / "good.txt"
    good_file.write_text("valid content")

    broken_link = tmp_path / "broken.txt"
    broken_link.symlink_to(tmp_path / "nonexistent_target.txt")

    s_client, s_server = socket.socketpair()

    class _SimpleSecure:
        def __init__(self, s: socket.socket) -> None:
            self.s = s

        def send(self, msg_type: int, payload: bytes) -> None:
            self.s.sendall(payload)

        def send_control(self, msg_type: int, obj: dict[str, Any]) -> None:
            pass

        def buffered(self) -> list[tuple[int, bytes]]:
            return []

        def drain(self) -> list[tuple[int, bytes]]:
            data = self.s.recv(65536)
            if not data:
                raise TransportEOF("closed")
            return [(Msg.DATA, data)]

    client = FramedStreamClient(_SimpleSecure(s_client), s_client)  # type: ignore[arg-type]

    def read_exact(s: socket.socket, n: int) -> bytes:
        b = bytearray()
        while len(b) < n:
            c = s.recv(n - len(b))
            if not c:
                raise EOFError("socket closed")
            b.extend(c)
        return bytes(b)

    def server_thread() -> None:
        # INIT
        raw = read_exact(s_server, 8)
        hl, pl = struct.unpack(">II", raw)
        _ = read_exact(s_server, hl + pl)
        s_server.sendall(_pack_frame({"status": "OK", "target_is_dir": True}))

        # FILE_START for good_file only (broken_link is skipped before sending FILE_START)
        raw = read_exact(s_server, 8)
        hl, pl = struct.unpack(">II", raw)
        _ = read_exact(s_server, hl + pl)
        s_server.sendall(_pack_frame({"status": "READY", "offset": 0}))

        # CHUNK
        raw = read_exact(s_server, 8)
        hl, pl = struct.unpack(">II", raw)
        _ = read_exact(s_server, hl + pl)

        # FILE_END
        raw = read_exact(s_server, 8)
        hl, pl = struct.unpack(">II", raw)
        _ = read_exact(s_server, hl + pl)
        s_server.sendall(_pack_frame({"status": "OK"}))

        # DONE
        raw = read_exact(s_server, 8)
        hl, pl = struct.unpack(">II", raw)
        _ = read_exact(s_server, hl + pl)
        s_server.sendall(_pack_frame({"status": "DONE"}))

    t = subprocess.threading.Thread(target=server_thread, daemon=True)
    t.start()

    try:
        dest_dir = str(tmp_path / "upload_dest")
        target = PathSpec(is_remote=True, host="host-1", path=dest_dir)
        summary = moecp.TransferSummary()
        rc = upload_files(client, [str(broken_link), str(good_file)], target, False, False, summary=summary, quiet=True)
        assert rc == 0
        assert summary.succeeded == 1
        assert summary.skipped == 1
        captured = capsys.readouterr()
        assert "moecp: cannot access" in captured.err
    finally:
        s_client.close()
        s_server.close()
        t.join(timeout=1.0)
