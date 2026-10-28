#!/usr/bin/env python3
"""Integrity regressions for the native transfer engine (MOESH-001/006/007/008/009).

Each test states the invariant it measures in the docstring and drives the
public entry points (``run_native_agent_transfer`` / ``download_files``) over a
real socket pair, so a failure is a behaviour failure rather than a
source-shape assertion.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import socket
import threading
import time
import tracemalloc
import zlib
from typing import TYPE_CHECKING, Any

import pytest

import moecp
import moesh_proto as proto

if TYPE_CHECKING:
    from pathlib import Path

LEDGER_ENV = "MOECP_LEDGER_PATH"
CLIENT_LEDGER_ENV = "MOECP_CLIENT_LEDGER_PATH"


class _DummySecureChannel:
    """SecureChannel stand-in that copies bytes over a socket pair."""

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


class Pair:
    """An agent thread on one end of a socket pair and a client on the other."""

    def __init__(self) -> None:
        self.agent_sock, self.client_sock = socket.socketpair()
        self.thread = threading.Thread(target=self._run_agent, daemon=True)

    def _run_agent(self) -> None:
        try:
            moecp.run_native_agent_transfer(
                self.agent_sock,
                _DummySecureChannel(self.agent_sock),  # type: ignore[arg-type]
                {"session_type": "transfer"},
            )
        except Exception:  # noqa: S110 - the agent may fail closed on purpose
            pass
        finally:
            self.agent_sock.close()

    def start(self) -> Pair:
        self.thread.start()
        return self

    def client(self) -> moecp.FramedStreamClient:
        return moecp.FramedStreamClient(
            _DummySecureChannel(self.client_sock),  # type: ignore[arg-type]
            self.client_sock,
        )

    def join(self, timeout: float = 10.0) -> None:
        self.thread.join(timeout)

    def close(self) -> None:
        # Half-close first so the agent observes a transport EOF (the resume
        # path) instead of an EBADF from a socket closed under its recv().
        with contextlib.suppress(OSError):
            self.client_sock.shutdown(socket.SHUT_RDWR)
        time.sleep(0.05)
        for sock in (self.client_sock, self.agent_sock):
            with contextlib.suppress(OSError):
                sock.close()


def _agent_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(LEDGER_ENV, str(tmp_path / "agent-ledger.db"))
    monkeypatch.setenv(CLIENT_LEDGER_ENV, str(tmp_path / "client-ledger.db"))
    monkeypatch.setenv("MOECP_LOCK_DIR", str(tmp_path / "locks"))


def _pull(
    source: Path,
    target: str,
    *,
    recursive: bool,
) -> moecp.TransferSummary:
    pair = Pair().start()
    summary = moecp.TransferSummary()
    try:
        code = moecp.download_files(
            client=pair.client(),
            source_spec=moecp.PathSpec(is_remote=True, host="remote", path=str(source)),
            local_target=target,
            recursive=recursive,
            preserve=False,
            quiet=True,
            summary=summary,
        )
    finally:
        pair.close()
        pair.join()
    assert code == 0
    return summary


# ---------------------------------------------------------------------------
# MOESH-001 — deduplication must use current remote content identity
# ---------------------------------------------------------------------------


def test_pull_refreshes_destination_when_remote_content_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A same-size, same-mtime source replacement must not be silently skipped."""
    _agent_env(monkeypatch, tmp_path)
    source = tmp_path / "source.txt"
    original = b"A" * 2048
    replacement = b"B" * 2048
    source.write_bytes(original)
    stat_before = os.stat(source)

    dest = tmp_path / "dest.txt"
    _pull(source, str(dest), recursive=False)
    assert dest.read_bytes() == original

    # Same length, same mtime: every historical dedup key stays identical.
    source.write_bytes(replacement)
    os.utime(source, (stat_before.st_atime, stat_before.st_mtime))
    assert os.stat(source).st_size == stat_before.st_size
    assert os.stat(source).st_mtime == stat_before.st_mtime

    _pull(source, str(dest), recursive=False)
    assert dest.read_bytes() == replacement


# ---------------------------------------------------------------------------
# MOESH-006 — transfer writes cannot escape the destination root
# ---------------------------------------------------------------------------


def _push_file(
    pair: Pair,
    *,
    target: Path,
    rel_path: str,
    content: bytes,
) -> dict[str, Any]:
    client = pair.client()
    client.send_frame(
        {"direction": "PUSH", "target": str(target), "is_dir": True, "preserve": False}
    )
    init_ack, _ = client.recv_frame()
    assert init_ack["status"] == "OK"
    client.send_frame(
        {
            "op": "FILE_START",
            "rel_path": rel_path,
            "size": len(content),
            "mode": 0o644,
            "mtime": time.time(),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
    )
    ack, _ = client.recv_frame()
    if ack.get("status") == "READY":
        client.send_frame({"op": "CHUNK", "encoding": "raw"}, content)
        client.send_frame({"op": "FILE_END"})
        ack, _ = client.recv_frame()
    with contextlib.suppress(OSError):
        client.send_frame({"op": "DONE"})
    return ack


def test_push_refuses_intermediate_symlink_out_of_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A symlinked intermediate directory must not carry a write outside root."""
    _agent_env(monkeypatch, tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    os.symlink(outside, target / "link")

    pair = Pair().start()
    try:
        ack = _push_file(
            pair, target=target, rel_path="link/escaped.txt", content=b"ESCAPED"
        )
    finally:
        pair.close()
        pair.join()

    assert ack.get("status") == "ERROR"
    assert not (outside / "escaped.txt").exists()


def test_pull_refuses_intermediate_symlink_out_of_local_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A remote manifest entry must not write through a local symlinked directory."""
    _agent_env(monkeypatch, tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    local_root = tmp_path / "downloads"
    local_root.mkdir()
    os.symlink(outside, local_root / "sub")

    content = b"REMOTE PAYLOAD"
    files = [
        {
            "rel": "sub/escaped.txt",
            "size": len(content),
            "mode": 0o644,
            "mtime": 1.0,
            "sha256": hashlib.sha256(content).hexdigest(),
        }
    ]

    a_sock, c_sock = socket.socketpair()

    def scripted_agent() -> None:
        server = moecp.FramedStreamClient(
            _DummySecureChannel(a_sock), a_sock  # type: ignore[arg-type]
        )
        try:
            server.recv_frame()
            server.send_frame({"status": "OK", "is_dir": True, "files": files})
            while True:
                req, _ = server.recv_frame()
                op = req.get("op")
                if op == "PULL_FILE":
                    server.send_frame({"op": "CHUNK", "encoding": "raw"}, content)
                    server.send_frame(
                        {"op": "FILE_END", "sha256": hashlib.sha256(content).hexdigest()}
                    )
                    server.recv_frame()
                elif op == "DONE":
                    server.send_frame({"status": "DONE"})
                    return
                else:
                    return
        finally:
            a_sock.close()

    thread = threading.Thread(target=scripted_agent, daemon=True)
    thread.start()
    summary = moecp.TransferSummary()
    try:
        code = moecp.download_files(
            client=moecp.FramedStreamClient(
                _DummySecureChannel(c_sock), c_sock  # type: ignore[arg-type]
            ),
            source_spec=moecp.PathSpec(is_remote=True, host="remote", path="/src"),
            local_target=str(local_root),
            recursive=True,
            preserve=False,
            quiet=True,
            summary=summary,
        )
    finally:
        c_sock.close()
        thread.join(5)

    assert code != 0
    assert summary.failed == 1
    assert not (outside / "escaped.txt").exists()


# ---------------------------------------------------------------------------
# MOESH-007 — decompression output is bounded
# ---------------------------------------------------------------------------


def test_decompress_rejects_output_beyond_chunk_limit() -> None:
    """One compressed frame may not expand past the uncompressed chunk bound."""
    bomb = zlib.compress(b"A" * (moecp.CHUNK_SIZE + 1), 9)
    with pytest.raises(proto.ProtocolError):
        moecp.decompress_chunk(bomb)


def test_decompress_rejects_truncated_stream() -> None:
    """A partial zlib stream fails closed instead of yielding partial output."""
    with pytest.raises(proto.ProtocolError):
        moecp.decompress_chunk(zlib.compress(b"x" * 1024)[:-4])


def test_pull_bomb_does_not_allocate_the_decoded_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A 64 MiB decompression bomb is rejected without that allocation."""
    _agent_env(monkeypatch, tmp_path)
    declared = 64 * 1024 * 1024
    zero_sha = hashlib.sha256(b"\0" * declared).hexdigest()
    bomb = zlib.compress(b"\0" * declared, 9)
    dest = tmp_path / "bomb.bin"

    a_sock, c_sock = socket.socketpair()

    def scripted_agent() -> None:
        server = moecp.FramedStreamClient(
            _DummySecureChannel(a_sock), a_sock  # type: ignore[arg-type]
        )
        try:
            server.recv_frame()
            server.send_frame(
                {
                    "status": "OK",
                    "is_dir": False,
                    "files": [
                        {
                            "rel": "bomb.bin",
                            "size": declared,
                            "mode": 0o644,
                            "mtime": 1.0,
                            "sha256": zero_sha,
                        }
                    ],
                }
            )
            req, _ = server.recv_frame()
            assert req.get("op") == "PULL_FILE"
            server.send_frame({"op": "CHUNK", "encoding": "zlib"}, bomb)
            time.sleep(0.2)
        except Exception:  # noqa: S110 - the scripted peer may be closed by the client
            pass
        finally:
            a_sock.close()

    thread = threading.Thread(target=scripted_agent, daemon=True)
    thread.start()
    summary = moecp.TransferSummary()
    tracemalloc.start()
    try:
        code = moecp.download_files(
            client=moecp.FramedStreamClient(
                _DummySecureChannel(c_sock), c_sock  # type: ignore[arg-type]
            ),
            source_spec=moecp.PathSpec(is_remote=True, host="remote", path="/bomb"),
            local_target=str(dest),
            recursive=False,
            preserve=False,
            quiet=True,
            summary=summary,
        )
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
        c_sock.close()
        thread.join(5)

    assert code != 0
    assert peak < 8 * 1024 * 1024, f"decoded payload was materialised: peak={peak}"
    assert not dest.exists()


def test_push_rejects_cumulative_bytes_beyond_declared_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Chunks whose sum exceeds the declared file size fail closed."""
    _agent_env(monkeypatch, tmp_path)
    target = tmp_path / "target"
    target.mkdir()

    pair = Pair().start()
    try:
        client = pair.client()
        client.send_frame(
            {"direction": "PUSH", "target": str(target), "is_dir": True}
        )
        assert client.recv_frame()[0]["status"] == "OK"
        client.send_frame(
            {
                "op": "FILE_START",
                "rel_path": "small.bin",
                "size": 4,
                "mode": 0o644,
                "mtime": 1.0,
                "sha256": hashlib.sha256(b"12345678").hexdigest(),
            }
        )
        assert client.recv_frame()[0]["status"] == "READY"
        client.send_frame({"op": "CHUNK", "encoding": "raw"}, b"1234")
        client.send_frame({"op": "CHUNK", "encoding": "raw"}, b"5678")
        client.send_frame({"op": "FILE_END"})
        ack, _ = client.recv_frame()
    finally:
        pair.close()
        pair.join()

    assert ack["status"] == "ERROR"
    assert not (target / "small.bin").exists()


# ---------------------------------------------------------------------------
# MOESH-008 — a tree larger than one 64 KiB manifest frame still transfers
# ---------------------------------------------------------------------------


def test_pull_transfers_a_tree_larger_than_one_manifest_frame(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """1200 files must transfer with every manifest frame inside the bound."""
    _agent_env(monkeypatch, tmp_path)
    source = tmp_path / "tree"
    source.mkdir()
    expected: dict[str, bytes] = {}
    for index in range(1200):
        name = f"file-{index:04d}-{'x' * 20}.txt"
        payload = f"payload-{index}".encode()
        (source / name).write_bytes(payload)
        expected[name] = payload

    dest = tmp_path / "dest"
    summary = _pull(source, str(dest), recursive=True)

    assert summary.total == 1200
    assert summary.succeeded == 1200
    assert summary.failed == 0
    for name, payload in expected.items():
        assert (dest / name).read_bytes() == payload


# ---------------------------------------------------------------------------
# MOESH-009 — recovery validates durable contents instead of trusting the ledger
# ---------------------------------------------------------------------------


def test_committed_ledger_without_digest_never_skips_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A committed row with no expected digest must not authorise a skip."""
    _agent_env(monkeypatch, tmp_path)
    source = tmp_path / "source.bin"
    content = b"GOOD CONTENT BLOCK " * 64
    source.write_bytes(content)
    stat = os.stat(source)

    dest = tmp_path / "dest.bin"
    dest.write_bytes(b"X" * len(content))

    ledger = moecp.TransferLedger(str(tmp_path / "client-ledger.db"))
    legacy_id = hashlib.sha256(
        f"pull:{dest}:{stat.st_size}:{stat.st_mtime!r}".encode()
    ).hexdigest()[:16]
    ledger.record_transfer(legacy_id, str(dest), stat.st_size, "")
    ledger.mark_committed(legacy_id)

    summary = _pull(source, str(dest), recursive=False)

    assert summary.skipped == 0
    assert dest.read_bytes() == content


def test_concurrent_writer_to_the_same_destination_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A second writer holding no lease on the destination must not interleave."""
    _agent_env(monkeypatch, tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    dest = target / "shared.bin"

    with moecp.destination_lock(os.path.join(os.path.realpath(target), dest.name)):
        pair = Pair().start()
        try:
            ack = _push_file(pair, target=target, rel_path="shared.bin", content=b"NEW")
        finally:
            pair.close()
            pair.join()

    assert ack.get("status") == "ERROR"
    assert "busy" in str(ack.get("message", "")).lower()
    assert not dest.exists()


def test_interrupted_push_resumes_without_exposing_partial_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A drop mid-file leaves staging only; the retry commits verified bytes."""
    _agent_env(monkeypatch, tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    content = b"RESUMABLE-BLOCK-" * 4096
    sha = hashlib.sha256(content).hexdigest()

    first = Pair().start()
    try:
        client = first.client()
        client.send_frame({"direction": "PUSH", "target": str(target), "is_dir": True})
        assert client.recv_frame()[0]["status"] == "OK"
        client.send_frame(
            {
                "op": "FILE_START",
                "rel_path": "resume.bin",
                "size": len(content),
                "mode": 0o644,
                "mtime": 1.0,
                "sha256": sha,
            }
        )
        assert client.recv_frame()[0]["status"] == "READY"
        client.send_frame({"op": "CHUNK", "encoding": "raw"}, content[: moecp.CHUNK_SIZE])
        # Drop the connection mid-file.
    finally:
        first.close()
        first.join()

    assert not (target / "resume.bin").exists()
    staged = [p for p in target.iterdir() if ".part." in p.name]
    assert len(staged) == 1

    second = Pair().start()
    try:
        client = second.client()
        client.send_frame({"direction": "PUSH", "target": str(target), "is_dir": True})
        assert client.recv_frame()[0]["status"] == "OK"
        client.send_frame(
            {
                "op": "FILE_START",
                "rel_path": "resume.bin",
                "size": len(content),
                "mode": 0o644,
                "mtime": 1.0,
                "sha256": sha,
            }
        )
        ready, _ = client.recv_frame()
        assert ready["status"] == "READY"
        offset = int(ready.get("offset", 0))
        assert offset == moecp.CHUNK_SIZE
        for start in range(offset, len(content), moecp.CHUNK_SIZE):
            client.send_frame(
                {"op": "CHUNK", "encoding": "raw"}, content[start : start + moecp.CHUNK_SIZE]
            )
        client.send_frame({"op": "FILE_END"})
        ack, _ = client.recv_frame()
    finally:
        second.close()
        second.join()

    assert ack["status"] == "OK"
    assert (target / "resume.bin").read_bytes() == content
