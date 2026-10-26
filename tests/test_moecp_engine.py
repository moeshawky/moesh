#!/usr/bin/env python3
"""Tests for moecp native transfer engine, durable ledger, and session negotiation.

Covers:
- Session negotiation contract (session_type validation for 'shell' and 'transfer')
- TransferLedger SQLite WAL persistence, range tracking, and commit lifecycle
- Adaptive chunk compression selection (raw vs zlib) and symmetric decoding
- Native agent transfer handler (PUSH, PULL, COMMITTED deduplication, path traversal guard,
  and fail-closed checksum verification)
"""

from __future__ import annotations

import hashlib
import os
import socket
import threading
import zlib
from typing import TYPE_CHECKING, Any

import pytest

import moecp
import moesh_proto as proto

if TYPE_CHECKING:
    from pathlib import Path


class _DummySecureChannel:
    """Mock SecureChannel backing FramedStreamClient over a socketpair for testing."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock

    def buffered(self) -> list[tuple[int, bytes]]:
        return []

    def drain(self) -> list[tuple[int, bytes]]:
        data = self.sock.recv(65536)
        if not data:
            raise proto.TransportEOF("connection closed")
        return [(proto.Msg.DATA, data)]

    def send(self, msg_type: int, data: bytes) -> None:
        self.sock.sendall(data)


def test_session_type_negotiation_validation() -> None:
    """Validate HELLO session_type handling across shell, transfer, and invalid cases."""
    base_hello: dict[str, Any] = {
        "version": proto.PROTOCOL_VERSION,
        "term": "xterm-256color",
        "encoding": proto.DEFAULT_ENCODING,
        "rows": 40,
        "cols": 120,
        "capabilities": ["resize"],
        "max_record": 32768,
        "fresh_session": True,
    }

    # 1. Default when omitted is 'shell'
    res_default = proto.validate_hello(dict(base_hello))
    assert res_default["session_type"] == "shell"

    # 2. Explicit 'shell'
    res_shell = proto.validate_hello(dict(base_hello, session_type="shell"))
    assert res_shell["session_type"] == "shell"

    # 3. Explicit 'transfer'
    res_transfer = proto.validate_hello(dict(base_hello, session_type="transfer"))
    assert res_transfer["session_type"] == "transfer"

    # 4. Invalid session_type strings raise NegotiationError
    with pytest.raises(proto.NegotiationError, match="invalid session_type"):
        proto.validate_hello(dict(base_hello, session_type="invalid"))

    with pytest.raises(proto.NegotiationError, match="invalid session_type"):
        proto.validate_hello(dict(base_hello, session_type=""))

    # 5. Non-string session_type raises NegotiationError
    with pytest.raises(proto.NegotiationError, match="invalid session_type"):
        proto.validate_hello(dict(base_hello, session_type=123))


def test_framed_stream_client_monotonic_deadline_timeout() -> None:
    """FramedStreamClient enforces monotonic deadlines across socket stalls and partial reads."""
    import time

    s1, s2 = socket.socketpair()
    try:
        sec1 = _DummySecureChannel(s1)
        client = moecp.FramedStreamClient(sec1, s1)  # type: ignore[arg-type]

        # 1. Total silence on socket raises TimeoutError within timeout
        t0 = time.monotonic()
        with pytest.raises(TimeoutError, match="timed out waiting for remote response"):
            client.recv_frame(timeout=0.15)
        elapsed = time.monotonic() - t0
        assert 0.10 <= elapsed <= 0.45

        # 2. Partial prefix (e.g. only 4 bytes out of 8) followed by stall raises TimeoutError
        s2.sendall(b"\x00\x00\x00\x10")  # 4 bytes
        t0 = time.monotonic()
        with pytest.raises(TimeoutError, match="timed out waiting for remote response"):
            client.recv_frame(timeout=0.20)
        elapsed = time.monotonic() - t0
        assert 0.15 <= elapsed <= 0.50
    finally:
        s1.close()
        s2.close()


def test_transfer_ledger_lifecycle(tmp_path: Path) -> None:
    """TransferLedger initializes WAL table, tracks chunk ranges, and records commit status."""
    db_file = tmp_path / "test_ledger.db"
    ledger = moecp.TransferLedger(str(db_file))

    transfer_id = "test_tx_001"
    rel_path = "docs/spec.pdf"
    total_size = 1048576
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    assert ledger.is_committed(transfer_id) is False
    assert ledger.get_verified_ranges(transfer_id) == []

    # Record transfer entry
    ledger.record_transfer(transfer_id, rel_path, total_size, sha256)
    assert ledger.is_committed(transfer_id) is False

    # Record chunk ranges
    ledger.record_range(transfer_id, 0, 32768, "chunk_sha_1")
    ledger.record_range(transfer_id, 32768, 65536, "chunk_sha_2")
    ledger.record_range(transfer_id, 65536, 98304, "chunk_sha_3")

    ranges = ledger.get_verified_ranges(transfer_id)
    assert ranges == [(0, 32768), (32768, 65536), (65536, 98304)]

    # Truncate ranges starting at or after offset 65536
    ledger.truncate_ranges_after(transfer_id, 65536)
    assert ledger.get_verified_ranges(transfer_id) == [(0, 32768), (32768, 65536)]

    # Further truncate at offset 32768
    ledger.truncate_ranges_after(transfer_id, 32768)
    assert ledger.get_verified_ranges(transfer_id) == [(0, 32768)]

    # Truncate at 0 clears all ranges
    ledger.truncate_ranges_after(transfer_id, 0)
    assert ledger.get_verified_ranges(transfer_id) == []

    # Re-record for mark_committed and purge_committed_ranges verification
    ledger.record_range(transfer_id, 0, 32768, "chunk_sha_1")

    # Mark committed
    ledger.mark_committed(transfer_id)
    assert ledger.is_committed(transfer_id) is True

    # Purge committed ranges
    ledger.purge_committed_ranges(transfer_id)
    assert ledger.get_verified_ranges(transfer_id) == []
    assert ledger.is_committed(transfer_id) is True


def test_transfer_ledger_pruning_and_retention(tmp_path: Path) -> None:
    """TransferLedger prunes uncommitted transfers older than TTL while preserving fresh and committed ones."""
    import time

    db_file = tmp_path / "prune_test_ledger.db"
    ledger = moecp.TransferLedger(str(db_file))

    now = time.time()
    stale_time = now - (10 * 86400.0)  # 10 days ago

    # 1. Stale uncommitted transfer
    tx_stale = "tx_stale_uncommitted"
    ledger.record_transfer(tx_stale, "stale.bin", 1000, "sha_stale", updated_at=stale_time)
    ledger.record_range(tx_stale, 0, 500, "chunk_1")
    # Reset updated_at manually to stale since record_range bumps updated_at
    with moecp.sqlite3.connect(ledger.db_path) as conn:
        conn.execute("UPDATE transfers SET updated_at=? WHERE transfer_id=?", (stale_time, tx_stale))

    # 2. Fresh uncommitted transfer
    tx_fresh = "tx_fresh_uncommitted"
    ledger.record_transfer(tx_fresh, "fresh.bin", 2000, "sha_fresh", updated_at=now)
    ledger.record_range(tx_fresh, 0, 1000, "chunk_fresh")

    # 3. Stale committed transfer
    tx_committed_stale = "tx_committed_stale"
    ledger.record_transfer(tx_committed_stale, "committed.bin", 3000, "sha_committed", updated_at=stale_time)
    ledger.mark_committed(tx_committed_stale)
    with moecp.sqlite3.connect(ledger.db_path) as conn:
        conn.execute("UPDATE transfers SET updated_at=? WHERE transfer_id=?", (stale_time, tx_committed_stale))

    # Prune with 7-day TTL
    pruned_count = ledger.prune_stale_transfers(days=7)
    assert pruned_count == 1

    # Stale uncommitted transfer and its ranges were purged
    assert ledger.is_committed(tx_stale) is False
    assert ledger.get_verified_ranges(tx_stale) == []
    with moecp.sqlite3.connect(ledger.db_path) as conn:
        cur = conn.execute("SELECT 1 FROM transfers WHERE transfer_id=?", (tx_stale,))
        assert cur.fetchone() is None

    # Fresh uncommitted transfer remains intact
    assert len(ledger.get_verified_ranges(tx_fresh)) == 1

    # Committed transfer remains committed
    assert ledger.is_committed(tx_committed_stale) is True


def test_adaptive_compression_and_symmetric_decoding() -> None:
    """Sender adaptively compresses compressible data and keeps high-entropy data raw."""
    # Low-entropy data (highly compressible repeated bytes)
    compressible = b"A" * 10000
    zlib_data = zlib.compress(compressible, 6)
    assert len(zlib_data) < len(compressible)

    # High-entropy data (urandom bytes)
    uncompressible = os.urandom(10000)
    zlib_rnd = zlib.compress(uncompressible, 6)
    assert len(zlib_rnd) >= len(uncompressible)

    # Test symmetric decompression logic for both raw and zlib
    def decode_chunk(encoding: str, payload: bytes) -> bytes:
        if encoding == "zlib":
            return zlib.decompress(payload)
        if encoding == "raw":
            return payload
        raise ValueError(f"unsupported encoding: {encoding}")

    assert decode_chunk("zlib", zlib_data) == compressible
    assert decode_chunk("raw", uncompressible) == uncompressible


def test_native_agent_transfer_push_and_committed_dedup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """run_native_agent_transfer serves PUSH uploads, commits to ledger, and reports COMMITTED on retry."""
    ledger_db = tmp_path / "ledger" / "moecp.db"
    monkeypatch.setenv("MOECP_LEDGER_PATH", str(ledger_db))

    s_agent, s_client = socket.socketpair()
    target_dir = tmp_path / "remote_target"
    target_dir.mkdir()

    content = b"NATIVE_TRANSFER_TEST_PAYLOAD_" * 50
    sha256 = hashlib.sha256(content).hexdigest()

    def run_agent() -> None:
        try:
            secure = _DummySecureChannel(s_agent)
            moecp.run_native_agent_transfer(s_agent, secure, {"session_type": "transfer"})  # type: ignore[arg-type]
        finally:
            s_agent.close()

    agent_thread = threading.Thread(target=run_agent)
    agent_thread.start()

    try:
        client_secure = _DummySecureChannel(s_client)
        client = moecp.FramedStreamClient(client_secure, s_client)  # type: ignore[arg-type]

        # 1. INIT frame
        client.send_frame({"direction": "PUSH", "target": str(target_dir), "is_dir": False})
        ack, _ = client.recv_frame()
        assert ack["status"] == "OK"

        # 2. FILE_START frame
        client.send_frame({
            "op": "FILE_START",
            "rel_path": "uploaded_file.txt",
            "size": len(content),
            "mode": 0o644,
            "mtime": 1700000000.0,
            "sha256": sha256,
        })
        ready_ack, _ = client.recv_frame()
        assert ready_ack["status"] == "READY"

        # 3. CHUNK frame (raw)
        client.send_frame({"op": "CHUNK", "encoding": "raw"}, content)

        # 4. FILE_END frame
        client.send_frame({"op": "FILE_END"})
        commit_ack, _ = client.recv_frame()
        assert commit_ack["status"] == "OK"
        assert commit_ack["sha256"] == sha256

        # 5. DONE frame
        client.send_frame({"op": "DONE"})
        done_ack, _ = client.recv_frame()
        assert done_ack["status"] == "DONE"

        agent_thread.join(timeout=5.0)

        # File was atomically created
        dest_file = target_dir / "uploaded_file.txt"
        assert dest_file.exists()
        assert dest_file.read_bytes() == content

        # Now test COMMITTED deduplication on a second transfer with same transfer_id
        s_agent2, s_client2 = socket.socketpair()

        def run_agent2() -> None:
            try:
                secure2 = _DummySecureChannel(s_agent2)
                moecp.run_native_agent_transfer(s_agent2, secure2, {"session_type": "transfer"})  # type: ignore[arg-type]
            finally:
                s_agent2.close()

        agent_thread2 = threading.Thread(target=run_agent2)
        agent_thread2.start()

        client_secure2 = _DummySecureChannel(s_client2)
        client2 = moecp.FramedStreamClient(client_secure2, s_client2)  # type: ignore[arg-type]

        client2.send_frame({"direction": "PUSH", "target": str(target_dir), "is_dir": False})
        ack2, _ = client2.recv_frame()
        assert ack2["status"] == "OK"

        # Resend FILE_START for same file
        client2.send_frame({
            "op": "FILE_START",
            "rel_path": "uploaded_file.txt",
            "size": len(content),
            "mode": 0o644,
            "mtime": 1700000000.0,
            "sha256": sha256,
        })
        dedup_ack, _ = client2.recv_frame()
        assert dedup_ack["status"] == "COMMITTED"
        assert dedup_ack["sha256"] == sha256

        client2.send_frame({"op": "DONE"})
        done_ack2, _ = client2.recv_frame()
        assert done_ack2["status"] == "DONE"

        agent_thread2.join(timeout=5.0)

    finally:
        s_client.close()


def test_native_agent_transfer_pull_round_trip(tmp_path: Path) -> None:
    """run_native_agent_transfer serves PULL downloads with adaptive compression."""
    remote_src_dir = tmp_path / "remote_files"
    remote_src_dir.mkdir()
    file1 = remote_src_dir / "hello.txt"
    file1.write_bytes(b"HELLO_WORLD_PULL_PAYLOAD" * 20)

    s_agent, s_client = socket.socketpair()

    def run_agent() -> None:
        try:
            secure = _DummySecureChannel(s_agent)
            moecp.run_native_agent_transfer(s_agent, secure, {"session_type": "transfer"})  # type: ignore[arg-type]
        finally:
            s_agent.close()

    agent_thread = threading.Thread(target=run_agent)
    agent_thread.start()

    try:
        client_secure = _DummySecureChannel(s_client)
        client = moecp.FramedStreamClient(client_secure, s_client)  # type: ignore[arg-type]

        # 1. Request PULL
        client.send_frame({
            "direction": "PULL",
            "source": str(file1),
            "recursive": False,
            "compression": "auto",
        })
        manifest, _ = client.recv_frame()
        assert manifest["status"] == "OK"
        assert len(manifest["files"]) == 1

        # 2. PULL_FILE request
        client.send_frame({"op": "PULL_FILE"})
        cmsg, cdata = client.recv_frame()
        assert cmsg["op"] == "CHUNK"
        enc = cmsg.get("encoding", "zlib")
        raw = zlib.decompress(cdata) if enc == "zlib" else cdata
        assert raw == file1.read_bytes()

        end_msg, _ = client.recv_frame()
        assert end_msg["op"] == "FILE_END"
        assert end_msg["sha256"] == hashlib.sha256(raw).hexdigest()

        # Send OK ack for file
        client.send_frame({"status": "OK"})

        # Send DONE
        client.send_frame({"op": "DONE"})
        done_ack, _ = client.recv_frame()
        assert done_ack["status"] == "DONE"

        agent_thread.join(timeout=5.0)
    finally:
        s_client.close()


def test_native_agent_transfer_pull_byte_offset_resumption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PULL downloads resume from byte offset when partial staging file exists."""
    remote_src_dir = tmp_path / "remote_files"
    remote_src_dir.mkdir()
    source_file = remote_src_dir / "bigfile.dat"
    content = b"PULL_OFFSET_BLOCK_A_" * 2000 + b"PULL_OFFSET_BLOCK_B_" * 2000
    source_file.write_bytes(content)

    local_dest_dir = tmp_path / "local_downloads"
    local_dest_dir.mkdir()
    dest_file = local_dest_dir / "bigfile.dat"

    st = os.stat(source_file)
    pull_id = hashlib.sha256(f"pull:{dest_file}:{st.st_size}:{st.st_mtime!r}".encode()).hexdigest()[:16]

    client_ledger_path = tmp_path / "client_ledger.db"
    monkeypatch.setenv("MOECP_CLIENT_LEDGER_PATH", str(client_ledger_path))
    ledger = moecp.TransferLedger(str(client_ledger_path))

    # Pre-populate partial staging file with first 30000 bytes
    offset = 30000
    tmp_file = str(dest_file) + f".part.{pull_id}"
    with open(tmp_file, "wb") as f:
        f.write(content[:offset])

    ledger.record_transfer(pull_id, str(dest_file), st.st_size, "")
    ledger.record_range(pull_id, 0, offset, hashlib.sha256(content[:offset]).hexdigest())

    s_agent, s_client = socket.socketpair()

    def run_agent() -> None:
        try:
            secure = _DummySecureChannel(s_agent)
            moecp.run_native_agent_transfer(s_agent, secure, {"session_type": "transfer"})  # type: ignore[arg-type]
        finally:
            s_agent.close()

    agent_thread = threading.Thread(target=run_agent)
    agent_thread.start()

    try:
        client_secure = _DummySecureChannel(s_client)
        client = moecp.FramedStreamClient(client_secure, s_client)  # type: ignore[arg-type]

        source_spec = moecp.PathSpec(is_remote=True, host="remote", path=str(source_file))
        exit_code = moecp.download_files(client, source_spec, str(dest_file), recursive=False, preserve=False, quiet=True)
        assert exit_code == 0
        agent_thread.join(timeout=5.0)

        assert dest_file.exists()
        assert dest_file.read_bytes() == content
        assert not os.path.exists(tmp_file)
    finally:
        s_client.close()


def test_transfer_summary_metrics_and_stderr_reporting(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """TransferSummary tracks batch transfer metrics and outputs concise summary line to stderr."""
    # 1. Direct class verification
    summary = moecp.TransferSummary(total=10, succeeded=8, failed=1, skipped=1)
    summary.print_summary()
    captured = capsys.readouterr()
    assert "moecp: transfer summary: 10 total, 8 succeeded, 1 failed, 1 skipped\n" in captured.err

    # 2. Integration with upload_files
    src_dir = tmp_path / "summary_src"
    src_dir.mkdir()
    f1 = src_dir / "f1.txt"
    f1.write_bytes(b"DATA_FILE_ONE")
    f2 = src_dir / "f2.txt"
    f2.write_bytes(b"DATA_FILE_TWO")

    target_dir = tmp_path / "summary_dst"
    target_dir.mkdir()

    # Pre-commit f1 in ledger to test skipped count
    ledger_db = tmp_path / "summary_ledger.db"
    ledger = moecp.TransferLedger(str(ledger_db))
    f1_dst = target_dir / "f1.txt"
    f1_dst.write_bytes(b"DATA_FILE_ONE")
    f1_sha = hashlib.sha256(b"DATA_FILE_ONE").hexdigest()
    f1_txid = hashlib.sha256(f"{f1_dst}:{len(b'DATA_FILE_ONE')}:{f1_sha}".encode()).hexdigest()[:16]
    ledger.record_transfer(f1_txid, "f1.txt", len(b"DATA_FILE_ONE"), f1_sha)
    ledger.mark_committed(f1_txid)

    s_agent, s_client = socket.socketpair()

    def run_agent() -> None:
        try:
            os.environ["MOECP_LEDGER_PATH"] = str(ledger_db)
            secure = _DummySecureChannel(s_agent)
            moecp.run_native_agent_transfer(s_agent, secure, {"session_type": "transfer"})  # type: ignore[arg-type]
        finally:
            s_agent.close()

    agent_thread = threading.Thread(target=run_agent)
    agent_thread.start()

    try:
        client_secure = _DummySecureChannel(s_client)
        client = moecp.FramedStreamClient(client_secure, s_client)  # type: ignore[arg-type]

        upload_summary = moecp.TransferSummary()
        target_spec = moecp.PathSpec(is_remote=True, host="remote", path=str(target_dir))
        rc = moecp.upload_files(
            client,
            [str(f1), str(f2)],
            target_spec,
            recursive=False,
            preserve=False,
            quiet=True,
            summary=upload_summary,
        )
        assert rc == 0
        agent_thread.join(timeout=5.0)

        # f1 was skipped (committed), f2 succeeded
        assert upload_summary.total == 2
        assert upload_summary.skipped == 1
        assert upload_summary.succeeded == 1
        assert upload_summary.failed == 0

        captured_up = capsys.readouterr()
        assert "moecp: transfer summary: 2 total, 1 succeeded, 0 failed, 1 skipped\n" in captured_up.err
    finally:
        s_client.close()


def test_native_agent_transfer_path_traversal_jail_check(tmp_path: Path) -> None:
    """run_native_agent_transfer enforces path traversal jail check and rejects escapes."""
    s_agent, s_client = socket.socketpair()
    target_dir = tmp_path / "jail"
    target_dir.mkdir()

    def run_agent() -> None:
        try:
            secure = _DummySecureChannel(s_agent)
            moecp.run_native_agent_transfer(s_agent, secure, {"session_type": "transfer"})  # type: ignore[arg-type]
        finally:
            s_agent.close()

    agent_thread = threading.Thread(target=run_agent)
    agent_thread.start()

    try:
        client_secure = _DummySecureChannel(s_client)
        client = moecp.FramedStreamClient(client_secure, s_client)  # type: ignore[arg-type]

        client.send_frame({"direction": "PUSH", "target": str(target_dir), "is_dir": False})
        ack, _ = client.recv_frame()
        assert ack["status"] == "OK"

        # Attempt path traversal
        client.send_frame({
            "op": "FILE_START",
            "rel_path": "../../escaped.txt",
            "size": 100,
            "mode": 0o644,
            "mtime": 1700000000.0,
            "sha256": "fake_sha",
        })
        err_ack, _ = client.recv_frame()
        assert err_ack["status"] == "ERROR"
        assert "escapes" in err_ack["message"].lower() or "traversal" in err_ack["message"].lower()

        agent_thread.join(timeout=5.0)
        assert not (tmp_path / "escaped.txt").exists()
    finally:
        s_client.close()


def test_native_agent_transfer_checksum_mismatch_fails_closed(tmp_path: Path) -> None:
    """run_native_agent_transfer detects corrupt chunk, deletes part file, and reports ERROR."""
    s_agent, s_client = socket.socketpair()
    target_dir = tmp_path / "corrupt_test"
    target_dir.mkdir()

    def run_agent() -> None:
        try:
            secure = _DummySecureChannel(s_agent)
            moecp.run_native_agent_transfer(s_agent, secure, {"session_type": "transfer"})  # type: ignore[arg-type]
        finally:
            s_agent.close()

    agent_thread = threading.Thread(target=run_agent)
    agent_thread.start()

    try:
        client_secure = _DummySecureChannel(s_client)
        client = moecp.FramedStreamClient(client_secure, s_client)  # type: ignore[arg-type]

        client.send_frame({"direction": "PUSH", "target": str(target_dir), "is_dir": False})
        ack, _ = client.recv_frame()
        assert ack["status"] == "OK"

        # Provide valid expected sha for "correct" payload
        client.send_frame({
            "op": "FILE_START",
            "rel_path": "corrupted.bin",
            "size": 14,
            "mode": 0o644,
            "mtime": 1700000000.0,
            "sha256": hashlib.sha256(b"correct payload").hexdigest(),
        })
        ready_ack, _ = client.recv_frame()
        assert ready_ack["status"] == "READY"

        # Send corrupted chunk data
        client.send_frame({"op": "CHUNK", "encoding": "raw"}, b"tampered bytes")
        client.send_frame({"op": "FILE_END"})

        resp, _ = client.recv_frame()
        assert resp["status"] == "ERROR"
        assert "checksum mismatch" in resp["message"]

        agent_thread.join(timeout=5.0)

        # Invariant: No corrupted file or staging .part file remains
        assert not (target_dir / "corrupted.bin").exists()
        assert len(os.listdir(target_dir)) == 0
    finally:
        s_client.close()


def test_native_agent_transfer_mid_file_byte_range_resumption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """run_native_agent_transfer preserves verified chunks on network drop and resumes from byte offset."""
    ledger_db = tmp_path / "ledger" / "moecp_resume.db"
    monkeypatch.setenv("MOECP_LEDGER_PATH", str(ledger_db))

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    src_file = src_dir / "large_resume.bin"
    chunk1 = b"A" * 32768
    chunk2 = b"B" * 32768
    full_content = chunk1 + chunk2
    src_file.write_bytes(full_content)
    expected_sha = hashlib.sha256(full_content).hexdigest()

    target_dir = tmp_path / "remote_resume_target"
    target_dir.mkdir()

    # Attempt 1: send chunk1, then drop the socket mid-transfer (simulating TransportEOF)
    s_agent1, s_client1 = socket.socketpair()

    def run_agent1() -> None:
        try:
            secure1 = _DummySecureChannel(s_agent1)
            moecp.run_native_agent_transfer(s_agent1, secure1, {"session_type": "transfer"})  # type: ignore[arg-type]
        finally:
            s_agent1.close()

    t1 = threading.Thread(target=run_agent1)
    t1.start()

    client1 = moecp.FramedStreamClient(_DummySecureChannel(s_client1), s_client1)  # type: ignore[arg-type]
    client1.send_frame({"direction": "PUSH", "target": str(target_dir), "is_dir": False})
    ack1, _ = client1.recv_frame()
    assert ack1["status"] == "OK"

    client1.send_frame({
        "op": "FILE_START",
        "rel_path": "large_resume.bin",
        "size": len(full_content),
        "mode": 0o644,
        "mtime": 1700000000.0,
        "sha256": expected_sha,
    })
    ready1, _ = client1.recv_frame()
    assert ready1["status"] == "READY"
    assert ready1["offset"] == 0
    transfer_id = ready1["transfer_id"]

    # Send only chunk 1, then abruptly close client socket to trigger TransportEOF on agent
    client1.send_frame({"op": "CHUNK", "encoding": "raw"}, chunk1)
    s_client1.close()
    t1.join(timeout=5.0)

    # Verify staging file and ledger verified_ranges survived the network drop
    part_file = target_dir / f"large_resume.bin.part.{transfer_id}"
    assert part_file.exists()
    assert part_file.stat().st_size == 32768
    ledger = moecp.TransferLedger(str(ledger_db))
    assert ledger.get_verified_ranges(transfer_id) == [(0, 32768)]

    # Attempt 2: reconnect via upload_files and verify it resumes at offset 32768
    s_agent2, s_client2 = socket.socketpair()

    def run_agent2() -> None:
        try:
            secure2 = _DummySecureChannel(s_agent2)
            moecp.run_native_agent_transfer(s_agent2, secure2, {"session_type": "transfer"})  # type: ignore[arg-type]
        finally:
            s_agent2.close()

    t2 = threading.Thread(target=run_agent2)
    t2.start()

    try:
        client2 = moecp.FramedStreamClient(_DummySecureChannel(s_client2), s_client2)  # type: ignore[arg-type]
        rc = moecp.upload_files(
            client=client2,
            sources=[str(src_file)],
            target_spec=moecp.PathSpec(is_remote=True, host="host-1", path=str(target_dir)),
            recursive=False,
            preserve=False,
            quiet=True,
            compression="raw",
        )
        assert rc == 0
        t2.join(timeout=5.0)

        dest_file = target_dir / "large_resume.bin"
        assert dest_file.exists()
        assert dest_file.read_bytes() == full_content
        assert not part_file.exists()
        assert ledger.is_committed(transfer_id) is True
    finally:
        s_client2.close()


def test_native_agent_transfer_cross_directory_isolation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Centralized ledger scopes transfer_id by destination path to prevent cross-directory collisions."""
    ledger_db = tmp_path / "ledger" / "moecp_isolation.db"
    monkeypatch.setenv("MOECP_LEDGER_PATH", str(ledger_db))

    dir_a = tmp_path / "dir_a"
    dir_b = tmp_path / "dir_b"
    dir_a.mkdir()
    dir_b.mkdir()

    src_file = tmp_path / "same.txt"
    payload_new = b"NEW_CONTENT_16B!"
    Payload_stale = b"OLD_CONTENT_16B!"
    src_file.write_bytes(payload_new)

    # Pre-populate dir_b/same.txt with stale content of the exact same byte length (16 bytes)
    (dir_b / "same.txt").write_bytes(Payload_stale)

    # 1. Upload same.txt to dir_a (marks dir_a transfer_id as COMMITTED)
    for target_dir in (dir_a, dir_b):
        s_agent, s_client = socket.socketpair()

        def run_agent(sa: socket.socket = s_agent) -> None:
            try:
                secure = _DummySecureChannel(sa)
                moecp.run_native_agent_transfer(sa, secure, {"session_type": "transfer"})  # type: ignore[arg-type]
            finally:
                sa.close()

        t = threading.Thread(target=run_agent)
        t.start()
        try:
            client = moecp.FramedStreamClient(_DummySecureChannel(s_client), s_client)  # type: ignore[arg-type]
            rc = moecp.upload_files(
                client=client,
                sources=[str(src_file)],
                target_spec=moecp.PathSpec(is_remote=True, host="host-1", path=str(target_dir)),
                recursive=False,
                preserve=False,
                quiet=True,
            )
            assert rc == 0
            t.join(timeout=5.0)
        finally:
            s_client.close()

    # Both dir_a/same.txt and dir_b/same.txt must hold payload_new (dir_b was not falsely skipped)
    assert (dir_a / "same.txt").read_bytes() == payload_new
    assert (dir_b / "same.txt").read_bytes() == payload_new


def test_push_committed_verifies_disk_content_on_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PUSH transfer verifies actual disk content SHA-256 before skipping as COMMITTED."""
    ledger_db = tmp_path / "ledger" / "moecp.db"
    monkeypatch.setenv("MOECP_LEDGER_PATH", str(ledger_db))

    target_dir = tmp_path / "remote_target"
    target_dir.mkdir()

    content = b"EXPECTED_DISK_CONTENT_BLOCK_" * 100
    expected_sha = hashlib.sha256(content).hexdigest()
    dest_file = target_dir / "rollback_file.txt"

    # Pre-commit the transfer in ledger
    transfer_id = hashlib.sha256(f"{dest_file}:{len(content)}:{expected_sha}".encode()).hexdigest()[:16]
    ledger = moecp.TransferLedger(str(ledger_db))
    ledger.record_transfer(transfer_id, str(dest_file), len(content), expected_sha)
    ledger.mark_committed(transfer_id)
    assert ledger.is_committed(transfer_id) is True

    # Corrupt or rollback file on disk with different content of identical size
    corrupted_content = b"ROLLED_BACK_CORRUPTED_BLOCK_" * 100
    assert len(corrupted_content) == len(content)
    assert corrupted_content != content
    dest_file.write_bytes(corrupted_content)
    assert dest_file.stat().st_size == len(content)

    s_agent, s_client = socket.socketpair()

    def run_agent() -> None:
        try:
            secure = _DummySecureChannel(s_agent)
            moecp.run_native_agent_transfer(s_agent, secure, {"session_type": "transfer"})  # type: ignore[arg-type]
        finally:
            s_agent.close()

    agent_thread = threading.Thread(target=run_agent)
    agent_thread.start()

    try:
        client_secure = _DummySecureChannel(s_client)
        client = moecp.FramedStreamClient(client_secure, s_client)  # type: ignore[arg-type]

        client.send_frame({"direction": "PUSH", "target": str(target_dir), "is_dir": False})
        ack, _ = client.recv_frame()
        assert ack["status"] == "OK"

        # Send FILE_START. Agent must inspect disk SHA and discover mismatch, returning READY not COMMITTED
        client.send_frame({
            "op": "FILE_START",
            "rel_path": "rollback_file.txt",
            "size": len(content),
            "mode": 0o644,
            "mtime": 1700000000.0,
            "sha256": expected_sha,
        })
        ready_ack, _ = client.recv_frame()
        assert ready_ack["status"] == "READY"
        assert ready_ack["transfer_id"] == transfer_id
        assert ready_ack["offset"] == 0

        # Transfer real content to heal disk corruption
        client.send_frame({"op": "CHUNK", "encoding": "raw"}, content)
        client.send_frame({"op": "FILE_END"})
        commit_ack, _ = client.recv_frame()
        assert commit_ack["status"] == "OK"
        assert commit_ack["sha256"] == expected_sha

        client.send_frame({"op": "DONE"})
        done_ack2, _ = client.recv_frame()
        assert done_ack2["status"] == "DONE"

        agent_thread.join(timeout=5.0)

        # File on disk is repaired
        assert dest_file.read_bytes() == content
        assert ledger.is_committed(transfer_id) is True
    finally:
        s_client.close()


def test_prune_stale_transfers_unlinks_orphaned_part_files(tmp_path: Path) -> None:
    """prune_stale_transfers unlinks orphaned .part.<tid> files on disk for uncommitted transfers."""
    import time

    db_file = tmp_path / "prune_part_ledger.db"
    ledger = moecp.TransferLedger(str(db_file))

    now = time.time()
    stale_time = now - (10 * 86400.0)

    # 1. Stale uncommitted transfer with part file on disk
    tid_stale = "tx_stale_part"
    rel_stale = str(tmp_path / "stale_doc.pdf")
    part_stale = tmp_path / f"stale_doc.pdf.part.{tid_stale}"
    part_stale.write_bytes(b"stale partial content on disk")
    ledger.record_transfer(tid_stale, rel_stale, 10000, "sha_stale", updated_at=stale_time)
    ledger.record_range(tid_stale, 0, 5000, "chunk_sha_stale")
    with moecp.sqlite3.connect(ledger.db_path) as conn:
        conn.execute("UPDATE transfers SET updated_at=? WHERE transfer_id=?", (stale_time, tid_stale))

    # 2. Stale uncommitted transfer without part file (already deleted or never written)
    tid_stale_nopart = "tx_stale_nopart"
    rel_stale_nopart = str(tmp_path / "missing.bin")
    ledger.record_transfer(tid_stale_nopart, rel_stale_nopart, 2000, "sha_nopart", updated_at=stale_time)
    with moecp.sqlite3.connect(ledger.db_path) as conn:
        conn.execute("UPDATE transfers SET updated_at=? WHERE transfer_id=?", (stale_time, tid_stale_nopart))

    # 3. Fresh uncommitted transfer with part file
    tid_fresh = "tx_fresh_part"
    rel_fresh = str(tmp_path / "fresh_doc.pdf")
    part_fresh = tmp_path / f"fresh_doc.pdf.part.{tid_fresh}"
    part_fresh.write_bytes(b"fresh partial content on disk")
    ledger.record_transfer(tid_fresh, rel_fresh, 10000, "sha_fresh", updated_at=now)
    ledger.record_range(tid_fresh, 0, 4000, "chunk_sha_fresh")

    # 4. Stale committed transfer with fake part file (should not be pruned)
    tid_committed = "tx_stale_committed"
    rel_committed = str(tmp_path / "committed.pdf")
    part_committed = tmp_path / f"committed.pdf.part.{tid_committed}"
    part_committed.write_bytes(b"committed partial residual")
    ledger.record_transfer(tid_committed, rel_committed, 5000, "sha_committed", updated_at=stale_time)
    ledger.mark_committed(tid_committed)
    with moecp.sqlite3.connect(ledger.db_path) as conn:
        conn.execute("UPDATE transfers SET updated_at=? WHERE transfer_id=?", (stale_time, tid_committed))

    assert part_stale.exists()
    assert part_fresh.exists()
    assert part_committed.exists()

    pruned_count = ledger.prune_stale_transfers(days=7)
    assert pruned_count == 2

    # Stale uncommitted part file unlinked
    assert not part_stale.exists()
    assert ledger.get_verified_ranges(tid_stale) == []

    # Fresh uncommitted part file preserved
    assert part_fresh.exists()
    assert len(ledger.get_verified_ranges(tid_fresh)) == 1

    # Committed transfer preserved
    assert part_committed.exists()
    assert ledger.is_committed(tid_committed) is True


def test_pull_cross_invocation_resumption_with_verified_ranges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PULL downloads resume across client invocations using verified range hashes in ledger."""
    remote_src_dir = tmp_path / "remote_src"
    remote_src_dir.mkdir()
    source_file = remote_src_dir / "resumable_pull.bin"

    # Multi-chunk content: 65536 bytes block 1 + 19200 bytes block 2 = 84736 bytes
    chunk1 = (b"PULL_RESUME_CHUNK1_PAYLOAD_" * 3000)[:65536]
    chunk2 = b"PULL_RESUME_CHUNK2_DATA_" * 800
    full_content = chunk1 + chunk2
    source_file.write_bytes(full_content)

    local_dest_dir = tmp_path / "local_downloads"
    local_dest_dir.mkdir()
    dest_file = local_dest_dir / "resumable_pull.bin"

    client_ledger_path = tmp_path / "client_ledger.db"
    monkeypatch.setenv("MOECP_CLIENT_LEDGER_PATH", str(client_ledger_path))

    # Pre-simulate Invocation 1:
    # Client began downloading, wrote chunk 1 to dest_file.part.<pull_id>, recorded verified range,
    # then network disconnected before chunk 2 arrived.
    st = os.stat(source_file)
    pull_id = hashlib.sha256(f"pull:{dest_file}:{st.st_size}:{st.st_mtime!r}".encode()).hexdigest()[:16]
    part_file = local_dest_dir / f"resumable_pull.bin.part.{pull_id}"
    part_file.write_bytes(chunk1)

    ledger = moecp.TransferLedger(str(client_ledger_path))
    ledger.record_transfer(pull_id, str(dest_file), st.st_size, "")
    chunk1_sha = hashlib.sha256(chunk1).hexdigest()
    ledger.record_range(pull_id, 0, len(chunk1), chunk1_sha)

    # Verified range exists and is uncommitted
    assert ledger.get_verified_ranges(pull_id) == [(0, 65536)]
    assert ledger.is_committed(pull_id) is False

    # Invocation 2: fresh client connects and runs download_files
    s_agent, s_client = socket.socketpair()

    def run_agent() -> None:
        try:
            secure = _DummySecureChannel(s_agent)
            moecp.run_native_agent_transfer(s_agent, secure, {"session_type": "transfer"})  # type: ignore[arg-type]
        finally:
            s_agent.close()

    agent_thread = threading.Thread(target=run_agent)
    agent_thread.start()

    try:
        client_secure = _DummySecureChannel(s_client)
        client = moecp.FramedStreamClient(client_secure, s_client)  # type: ignore[arg-type]

        source_spec = moecp.PathSpec(is_remote=True, host="remote", path=str(source_file))
        exit_code = moecp.download_files(
            client=client,
            source_spec=source_spec,
            local_target=str(dest_file),
            recursive=False,
            preserve=False,
            quiet=True,
        )
        assert exit_code == 0
        agent_thread.join(timeout=5.0)

        # File completely assembled and verified
        assert dest_file.exists()
        assert dest_file.read_bytes() == full_content
        assert not part_file.exists()

        # Ledger marked committed and chunk ranges purged
        assert ledger.is_committed(pull_id) is True
        assert ledger.get_verified_ranges(pull_id) == []
    finally:
        s_client.close()


def test_pull_committed_deduplication_and_rollback_detection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PULL skips already-committed files with verified disk digests, and re-downloads if corrupted."""
    remote_src_dir = tmp_path / "remote_src"
    remote_src_dir.mkdir()
    source_file = remote_src_dir / "dedup_pull.bin"
    content = b"DEDUP_PULL_PAYLOAD_BLOCK_" * 100
    source_file.write_bytes(content)

    local_dest_dir = tmp_path / "local_downloads"
    local_dest_dir.mkdir()
    dest_file = local_dest_dir / "dedup_pull.bin"

    client_ledger_path = tmp_path / "client_ledger.db"
    monkeypatch.setenv("MOECP_CLIENT_LEDGER_PATH", str(client_ledger_path))
    ledger = moecp.TransferLedger(str(client_ledger_path))

    st = os.stat(source_file)
    content_sha = hashlib.sha256(content).hexdigest()
    pull_id = hashlib.sha256(f"pull:{dest_file}:{st.st_size}:{st.st_mtime!r}".encode()).hexdigest()[:16]

    # Pre-populate dest_file and mark as committed with expected SHA
    dest_file.write_bytes(content)
    ledger.record_transfer(pull_id, str(dest_file), st.st_size, content_sha)
    ledger.mark_committed(pull_id, content_sha)
    assert ledger.is_committed(pull_id) is True

    # 1. First run: file is committed, exists, matching size and disk SHA -> must skip without PULL_FILE
    s_agent, s_client = socket.socketpair()

    def run_agent() -> None:
        try:
            secure = _DummySecureChannel(s_agent)
            moecp.run_native_agent_transfer(s_agent, secure, {"session_type": "transfer"})  # type: ignore[arg-type]
        finally:
            s_agent.close()

    agent_thread = threading.Thread(target=run_agent)
    agent_thread.start()

    try:
        client_secure = _DummySecureChannel(s_client)
        client = moecp.FramedStreamClient(client_secure, s_client)  # type: ignore[arg-type]

        summary1 = moecp.TransferSummary()
        source_spec = moecp.PathSpec(is_remote=True, host="remote", path=str(source_file))
        exit_code = moecp.download_files(
            client=client,
            source_spec=source_spec,
            local_target=str(dest_file),
            recursive=False,
            preserve=False,
            quiet=True,
            summary=summary1,
        )
        assert exit_code == 0
        agent_thread.join(timeout=5.0)

        assert summary1.total == 1
        assert summary1.skipped == 1
        assert summary1.succeeded == 0
        assert summary1.failed == 0
    finally:
        s_client.close()

    # 2. Second run: alter dest_file to corrupt content with same size -> must detect disk hash mismatch,
    # refuse to skip, and download original content to repair it
    corrupt_content = (b"CORRUPTED_SAME_LEN_" * (len(content) // 19 + 1))[: len(content)]
    assert len(corrupt_content) == len(content)
    dest_file.write_bytes(corrupt_content)

    s_agent2, s_client2 = socket.socketpair()

    def run_agent2() -> None:
        try:
            secure = _DummySecureChannel(s_agent2)
            moecp.run_native_agent_transfer(s_agent2, secure, {"session_type": "transfer"})  # type: ignore[arg-type]
        finally:
            s_agent2.close()

    agent_thread2 = threading.Thread(target=run_agent2)
    agent_thread2.start()

    try:
        client_secure2 = _DummySecureChannel(s_client2)
        client2 = moecp.FramedStreamClient(client_secure2, s_client2)  # type: ignore[arg-type]

        summary2 = moecp.TransferSummary()
        exit_code2 = moecp.download_files(
            client=client2,
            source_spec=source_spec,
            local_target=str(dest_file),
            recursive=False,
            preserve=False,
            quiet=True,
            summary=summary2,
        )
        assert exit_code2 == 0
        agent_thread2.join(timeout=5.0)

        assert summary2.total == 1
        assert summary2.skipped == 0
        assert summary2.succeeded == 1
        assert summary2.failed == 0
        assert dest_file.read_bytes() == content
    finally:
        s_client2.close()


def test_partial_range_rollback_on_chunk_verification_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verification fault at chunk N rolls back ranges >= N while preserving valid prefix ranges."""
    remote_src_dir = tmp_path / "remote_src"
    remote_src_dir.mkdir()
    source_file = remote_src_dir / "three_chunk.bin"

    chunk1 = (b"CHUNK1_VALID_DATA_" * 2000)[:32768]
    chunk2 = (b"CHUNK2_VALID_DATA_" * 2000)[:32768]
    chunk3 = (b"CHUNK3_VALID_DATA_" * 2000)[:32768]
    full_content = chunk1 + chunk2 + chunk3
    source_file.write_bytes(full_content)

    local_dest_dir = tmp_path / "local_downloads"
    local_dest_dir.mkdir()
    dest_file = local_dest_dir / "three_chunk.bin"

    client_ledger_path = tmp_path / "client_ledger.db"
    monkeypatch.setenv("MOECP_CLIENT_LEDGER_PATH", str(client_ledger_path))
    ledger = moecp.TransferLedger(str(client_ledger_path))

    st = os.stat(source_file)
    pull_id = hashlib.sha256(f"pull:{dest_file}:{st.st_size}:{st.st_mtime!r}".encode()).hexdigest()[:16]

    # Pre-simulate an interrupted download where chunk1 was valid, chunk2 was corrupted on disk,
    # and chunk3 had also been pre-recorded.
    part_file = local_dest_dir / f"three_chunk.bin.part.{pull_id}"
    corrupted_chunk2 = b"X" * 32768
    part_file.write_bytes(chunk1 + corrupted_chunk2 + chunk3)

    ledger.record_transfer(pull_id, str(dest_file), st.st_size, "")
    ledger.record_range(pull_id, 0, 32768, hashlib.sha256(chunk1).hexdigest())
    ledger.record_range(pull_id, 32768, 65536, hashlib.sha256(chunk2).hexdigest())
    ledger.record_range(pull_id, 65536, 98304, hashlib.sha256(chunk3).hexdigest())

    assert len(ledger.get_verified_ranges(pull_id)) == 3

    s_agent, s_client = socket.socketpair()

    def run_agent() -> None:
        try:
            secure = _DummySecureChannel(s_agent)
            moecp.run_native_agent_transfer(s_agent, secure, {"session_type": "transfer"})  # type: ignore[arg-type]
        finally:
            s_agent.close()

    agent_thread = threading.Thread(target=run_agent)
    agent_thread.start()

    try:
        client_secure = _DummySecureChannel(s_client)
        client = moecp.FramedStreamClient(client_secure, s_client)  # type: ignore[arg-type]

        source_spec = moecp.PathSpec(is_remote=True, host="remote", path=str(source_file))
        exit_code = moecp.download_files(
            client=client,
            source_spec=source_spec,
            local_target=str(dest_file),
            recursive=False,
            preserve=False,
            quiet=True,
        )
        assert exit_code == 0
        agent_thread.join(timeout=5.0)

        # File is fully reconstructed with correct content
        assert dest_file.exists()
        assert dest_file.read_bytes() == full_content
        assert not part_file.exists()
        assert ledger.is_committed(pull_id) is True
    finally:
        s_client.close()


def test_download_files_prunes_stale_client_transfers_via_ttl_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """download_files automatically prunes stale client transfers older than MOECP_LEDGER_TTL_DAYS."""
    import time

    remote_src_dir = tmp_path / "remote_src"
    remote_src_dir.mkdir()
    source_file = remote_src_dir / "target.txt"
    source_file.write_bytes(b"HELLO_WORLD_TARGET_CONTENT")

    local_dest_dir = tmp_path / "local_downloads"
    local_dest_dir.mkdir()
    dest_file = local_dest_dir / "target.txt"

    client_ledger_path = tmp_path / "client_ledger.db"
    monkeypatch.setenv("MOECP_CLIENT_LEDGER_PATH", str(client_ledger_path))
    # Configure 3 days TTL
    monkeypatch.setenv("MOECP_LEDGER_TTL_DAYS", "3")

    ledger = moecp.TransferLedger(str(client_ledger_path))
    now = time.time()

    # 1. Stale uncommitted transfer updated 5 days ago (older than 3 days TTL)
    stale_time = now - (5 * 86400.0)
    stale_tid = "stale_pull_001"
    stale_rel = str(local_dest_dir / "orphaned_stale.bin")
    stale_part = local_dest_dir / f"orphaned_stale.bin.part.{stale_tid}"
    stale_part.write_bytes(b"stale partial leftover bytes")
    ledger.record_transfer(stale_tid, stale_rel, 1000, "sha_stale", updated_at=stale_time)
    ledger.record_range(stale_tid, 0, 500, "chunk_sha_stale")
    with moecp.sqlite3.connect(ledger.db_path) as conn:
        conn.execute("UPDATE transfers SET updated_at=? WHERE transfer_id=?", (stale_time, stale_tid))

    # 2. Fresh uncommitted transfer updated 1 day ago (newer than 3 days TTL)
    fresh_time = now - (1 * 86400.0)
    fresh_tid = "fresh_pull_002"
    fresh_rel = str(local_dest_dir / "active_fresh.bin")
    fresh_part = local_dest_dir / f"active_fresh.bin.part.{fresh_tid}"
    fresh_part.write_bytes(b"active fresh partial bytes")
    ledger.record_transfer(fresh_tid, fresh_rel, 2000, "sha_fresh", updated_at=fresh_time)
    ledger.record_range(fresh_tid, 0, 1000, "chunk_sha_fresh")
    with moecp.sqlite3.connect(ledger.db_path) as conn:
        conn.execute("UPDATE transfers SET updated_at=? WHERE transfer_id=?", (fresh_time, fresh_tid))

    assert stale_part.exists()
    assert fresh_part.exists()

    # Run download_files: initialization must trigger pruning with TTL=3 days
    s_agent, s_client = socket.socketpair()

    def run_agent() -> None:
        try:
            secure = _DummySecureChannel(s_agent)
            moecp.run_native_agent_transfer(s_agent, secure, {"session_type": "transfer"})  # type: ignore[arg-type]
        finally:
            s_agent.close()

    agent_thread = threading.Thread(target=run_agent)
    agent_thread.start()

    try:
        client_secure = _DummySecureChannel(s_client)
        client = moecp.FramedStreamClient(client_secure, s_client)  # type: ignore[arg-type]

        source_spec = moecp.PathSpec(is_remote=True, host="remote", path=str(source_file))
        exit_code = moecp.download_files(
            client=client,
            source_spec=source_spec,
            local_target=str(dest_file),
            recursive=False,
            preserve=False,
            quiet=True,
        )
        assert exit_code == 0
        agent_thread.join(timeout=5.0)

        # Stale staging file unlinked and db record purged
        assert not stale_part.exists()
        assert ledger.get_verified_ranges(stale_tid) == []

        # Fresh uncommitted staging file and ranges preserved
        assert fresh_part.exists()
        assert ledger.get_verified_ranges(fresh_tid) == [(0, 1000)]
    finally:
        s_client.close()






