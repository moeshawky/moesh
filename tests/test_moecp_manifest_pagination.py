#!/usr/bin/env python3
"""Byte-aware PULL manifest pagination regressions.

Covers manifest page assembly for the PULL builders (the embedded
``_WORKER_CODE`` worker and ``run_native_agent_transfer``, plus the shared page
planner used by the native path), asserting pages are bounded by serialized
bytes rather than entry count, and that the two implementations stay in lockstep.

The byte-budget failure (receiver ``ValueError``/``ProtocolError`` mid-transfer
when a 256-entry page of long paths exceeds the 64 KiB frame bound) is
reproduced by tests ``test_256_long_paths_split_at_byte_boundary`` and
``test_fewer_than_256_byte_busting_splits_early`` against the pre-fix build.
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
import threading
import time
from typing import TYPE_CHECKING, Any

import pytest

import moecp
import moesh_proto as proto

if TYPE_CHECKING:
    from pathlib import Path


def _frame(meta: dict[str, Any], payload: bytes = b"") -> bytes:
    hdr = json.dumps(meta).encode("utf-8")
    return struct.pack(">II", len(hdr), len(payload)) + hdr + payload


def _send(sock: socket.socket, meta: dict[str, Any], payload: bytes = b"") -> None:
    sock.sendall(_frame(meta, payload))


def _recv_frame(sock: socket.socket) -> tuple[dict[str, Any], bytes]:
    head = bytearray()
    while len(head) < 8:
        chunk = sock.recv(8 - len(head))
        if not chunk:
            raise EOFError("socket closed before frame header")
        head.extend(chunk)
    hlen, dlen = struct.unpack(">II", bytes(head))
    # Mirror the real client (moecp.FramedStreamClient.recv_frame): a frame whose
    # JSON header exceeds MAX_FRAME_HDR is rejected before any payload is read.
    if hlen > moecp.MAX_FRAME_HDR:
        raise proto.ProtocolError(
            f"received frame exceeding safety bounds: hdr={hlen}, data={dlen}"
        )
    if dlen > moecp.MAX_FRAME_PAYLOAD:
        raise proto.ProtocolError(
            f"received frame exceeding safety bounds: hdr={hlen}, data={dlen}"
        )
    hdr = bytearray()
    while len(hdr) < hlen:
        chunk = sock.recv(hlen - len(hdr))
        if not chunk:
            raise EOFError("socket closed before frame header body")
        hdr.extend(chunk)
    meta = json.loads(bytes(hdr).decode("utf-8"))
    payload = b""
    if dlen:
        data = bytearray()
        while len(data) < dlen:
            chunk = sock.recv(dlen - len(data))
            if not chunk:
                raise EOFError("socket closed before frame payload")
            data.extend(chunk)
        payload = bytes(data)
    return meta, payload


def _manifest_body_bytes(page: list[dict[str, Any]]) -> int:
    """Serialized bytes of one MANIFEST frame body for ``page`` (page 0, more=True)."""
    return len(
        json.dumps({"op": "MANIFEST", "page": 0, "files": page, "more": True}).encode("utf-8")
    )


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


class NativePull:
    """Runs ``run_native_agent_transfer`` on a socket pair; the test drives the client end."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        self.agent_sock, self.client_sock = socket.socketpair()
        monkeypatch.setenv("MOECP_LEDGER_PATH", str(tmp_path / "agent-ledger.db"))
        monkeypatch.setenv("MOECP_CLIENT_LEDGER_PATH", str(tmp_path / "client-ledger.db"))
        monkeypatch.setenv("MOECP_LOCK_DIR", str(tmp_path / "locks"))
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
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

    def pull_pages(self, source: str) -> list[list[dict[str, Any]]]:
        """Return the sequence of MANIFEST pages for a recursive PULL of ``source``."""
        _send(self.client_sock, {"direction": "PULL", "source": source, "recursive": True})
        manifest, _ = _recv_frame(self.client_sock)
        assert manifest.get("status") == "OK", manifest
        if manifest.get("paginated"):
            pages: list[list[dict[str, Any]]] = []
            page = 0
            while True:
                _send(self.client_sock, {"op": "LIST", "page": page})
                reply, _ = _recv_frame(self.client_sock)
                assert reply.get("op") == "MANIFEST", reply
                pages.append(reply.get("files", []))
                if not reply.get("more"):
                    break
                page += 1
            return pages
        return [manifest.get("files", [])]

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.client_sock.shutdown(socket.SHUT_RDWR)
        self.client_sock.close()


def _worker_pull_pages(source: str) -> list[list[dict[str, Any]]]:
    """Run the embedded ``_WORKER_CODE`` worker and return its MANIFEST pages."""
    s1, s2 = socket.socketpair()
    proc = subprocess.Popen(
        [sys.executable, "-u", "-c", moecp._WORKER_CODE],
        stdin=s2.fileno(),
        stdout=s2.fileno(),
    )
    s2.close()
    try:
        banner = s1.recv(len(moecp.MAGIC_READY))
        assert banner == moecp.MAGIC_READY, banner
        _send(s1, {"direction": "PULL", "source": source, "recursive": True})
        manifest, _ = _recv_frame(s1)
        assert manifest.get("status") == "OK", manifest
        if manifest.get("paginated"):
            pages: list[list[dict[str, Any]]] = []
            page = 0
            while True:
                _send(s1, {"op": "LIST", "page": page})
                reply, _ = _recv_frame(s1)
                assert reply.get("op") == "MANIFEST", reply
                pages.append(reply.get("files", []))
                if not reply.get("more"):
                    break
                page += 1
            return pages
        return [manifest.get("files", [])]
    finally:
        with contextlib.suppress(OSError):
            s1.close()
        if proc.poll() is None:
            proc.kill()


def _write_tree(tmp_path: Path, names: list[str], content: bytes = b"payload") -> Path:
    root = tmp_path / "tree"
    root.mkdir()
    for name in names:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    return root


# ---------------------------------------------------------------------------
# MOESH-008 follow-up: byte-aware pagination
# ---------------------------------------------------------------------------


def test_256_short_paths_all_received_digests_verify(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """256 short-named files: every entry received and its digest verifies."""
    root = _write_tree(tmp_path, [f"s{i:03d}.txt" for i in range(256)], b"short-content")
    expected = {
        f"s{i:03d}.txt": hashlib.sha256(b"short-content").hexdigest() for i in range(256)
    }
    pair = NativePull(monkeypatch, tmp_path)
    try:
        pages = pair.pull_pages(str(root))
    finally:
        pair.close()
    received = [entry for page in pages for entry in page]
    assert len(received) == 256
    by_rel = {entry["rel"]: entry for entry in received}
    assert set(by_rel) == {f"s{i:03d}.txt" for i in range(256)}
    for name in by_rel:
        assert by_rel[name]["sha256"] == expected[name]


def test_256_long_paths_split_at_byte_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """256 entries with ~200-byte paths: a single 256-entry page busts the 64 KiB
    frame bound pre-fix (receiver ProtocolError mid-transfer); post-fix pages at
    byte boundaries and all entries are received."""
    root = _write_tree(tmp_path, [("p" * 200) + f"_{i:03d}.bin" for i in range(256)], b"x")
    names = sorted(os.listdir(root))
    probe = [
        {**{"rel": name}, "sha256": "0" * 64, "size": 1, "mode": 0o644, "mtime": 1.0}
        for name in names
    ]
    total = len(
        json.dumps({"status": "OK", "is_dir": True, "files": probe}).encode("utf-8")
    )
    # Pre-fix, one 256-entry page of these exceeds the frame bound and fails.
    assert total > moecp.MAX_FRAME_HDR, total
    pair = NativePull(monkeypatch, tmp_path)
    try:
        pages = pair.pull_pages(str(root))
    finally:
        pair.close()
    received = [entry for page in pages for entry in page]
    assert len(received) == 256
    assert len(pages) >= 2  # byte budget binds before the 256-entry count cap
    for page in pages:
        assert _manifest_body_bytes(page) <= moecp.MANIFEST_PAGE_BYTES


def test_fewer_than_256_byte_busting_splits_early(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """255 entries (< 256 count cap) with ~247-byte flat paths: still splits
    because the byte budget binds even though the count cap would not.  The
    fixture serializes to ~96 KB (> MANIFEST_PAGE_BYTES 61,439 and > MAX_FRAME_HDR
    65,536), so the old count-only build put all entries in one oversized page
    and the receiver raised ProtocolError mid-transfer."""
    root = _write_tree(tmp_path, [("z" * 239) + f"_{i:03d}.bin" for i in range(255)], b"x")
    names = sorted(os.listdir(root))
    probe = [
        {**{"rel": name}, "sha256": "0" * 64, "size": 1, "mode": 0o644, "mtime": 1.0}
        for name in names
    ]
    total = len(
        json.dumps({"op": "MANIFEST", "page": 0, "files": probe, "more": True}).encode("utf-8")
    )
    # Self-validating fixture: 255 entries (< 256 count cap) must still bust the
    # byte budget, otherwise this test measures nothing.  Measured 2026-11-03:
    # OSError [Errno 36] File name too long (NAME_MAX=255) killed the z*250
    # fixture during creation, before any pagination code ran.
    assert total > moecp.MANIFEST_PAGE_BYTES, total
    pair = NativePull(monkeypatch, tmp_path)
    try:
        pages = pair.pull_pages(str(root))
    finally:
        pair.close()
    received = [entry for page in pages for entry in page]
    assert len(received) == 255
    assert len(pages) >= 2  # count cap (256) would not split; byte budget does
    for page in pages:
        assert _manifest_body_bytes(page) <= moecp.MANIFEST_PAGE_BYTES


def test_single_oversized_entry_fails_fast_naming_path_and_sizes() -> None:
    """A single entry that alone exceeds the page budget raises a clear
    ValueError naming the path and the sizes, before any bytes go on the wire."""
    oversized = "x" * 70000
    entry = {"rel": oversized, "size": 1, "mode": 0o644, "mtime": 1.0}
    with pytest.raises(ValueError) as excinfo:
        moecp.manifest_page_plan(
            [entry],
            False,
            inline_limit=moecp.MANIFEST_INLINE_LIMIT,
            page_bytes=moecp.MANIFEST_PAGE_BYTES,
            entry_count_cap=moecp.MANIFEST_PAGE_SIZE,
        )
    message = str(excinfo.value)
    assert oversized in message
    assert str(moecp.MANIFEST_PAGE_BYTES) in message


def test_empty_manifest_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Empty directory: empty file list, no pages, behavior unchanged."""
    root = tmp_path / "empty"
    root.mkdir()
    pair = NativePull(monkeypatch, tmp_path)
    try:
        pages = pair.pull_pages(str(root))
    finally:
        pair.close()
    assert sum(len(page) for page in pages) == 0


def test_mixed_short_long_deterministic_byte_boundaries() -> None:
    """Mixed short/long entries: page boundaries are deterministic and bounded by
    the byte budget (the split occurs before the 256-entry count cap)."""
    entries = [
        {"rel": ("p" * 200) + f"_{i}.bin", "size": 1, "mode": 0o644, "mtime": 1.0}
        for i in range(400)
    ]
    first = moecp.manifest_page_plan(
        entries,
        False,
        inline_limit=moecp.MANIFEST_INLINE_LIMIT,
        page_bytes=moecp.MANIFEST_PAGE_BYTES,
        entry_count_cap=moecp.MANIFEST_PAGE_SIZE,
    )
    second = moecp.manifest_page_plan(
        entries,
        False,
        inline_limit=moecp.MANIFEST_INLINE_LIMIT,
        page_bytes=moecp.MANIFEST_PAGE_BYTES,
        entry_count_cap=moecp.MANIFEST_PAGE_SIZE,
    )
    assert first == second  # deterministic
    is_inline, spans = first
    assert not is_inline
    assert spans[0][1] < moecp.MANIFEST_PAGE_SIZE  # byte budget binds before count cap
    for start, end in spans:
        assert _manifest_body_bytes(entries[start:end]) <= moecp.MANIFEST_PAGE_BYTES
    flat = [i for start, end in spans for i in range(start, end)]
    assert flat == list(range(len(entries)))  # every entry exactly once, in order


def _boundary_entry(rel: str, mtime: float) -> dict[str, Any]:
    """Manifest entry with a placeholder digest (same 64-char width as the wire
    entry after digest fill-in), so planner sizing matches serialization."""
    return {"rel": rel, "size": 1, "mode": 0o644, "mtime": mtime, "sha256": "0" * 64}


def _plan_pages(entries: list[dict[str, Any]]) -> list[tuple[int, int]]:
    _is_inline, spans = moecp.manifest_page_plan(
        entries,
        False,
        inline_limit=moecp.MANIFEST_INLINE_LIMIT,
        page_bytes=moecp.MANIFEST_PAGE_BYTES,
        entry_count_cap=moecp.MANIFEST_PAGE_SIZE,
    )
    return spans


def _assert_pages_bounded(entries: list[dict[str, Any]]) -> list[tuple[int, int]]:
    """Run the planner and assert every page's REAL serialized body is within
    the byte budget.  The body is serialized exactly as the wire emits it
    (json.dumps default separators -> \", \" list gaps), so this is the
    invariant the planner must guarantee."""
    spans = _plan_pages(entries)
    for start, end in spans:
        body = _manifest_body_bytes(entries[start:end])
        assert body <= moecp.MANIFEST_PAGE_BYTES, (start, end, body)
    return spans


# Float mtimes whose repr length varies run-to-run on real filesystems; this is
# the intermittency source (entry cost shifts +/-1-3 bytes, which the 1-byte
# per-gap undercount sometimes pushed over the budget).
_MTIME_VARIANTS: list[float] = [
    1.0,
    1793733909.683923,
    1793733909.6839234,
    1793733909.6839,
    1793733909.683923456789,
    0.0000001,
    9999999999.999999,
]


@pytest.mark.parametrize("mtime", _MTIME_VARIANTS)
def test_planner_pages_bounded_across_mtime_repr_lengths(mtime: float) -> None:
    """Same 256 ~200-byte paths, mtimes swept across float repr lengths: every
    planned page's real serialized body stays within MANIFEST_PAGE_BYTES no
    matter how long the mtime repr is.  Kills the wall-clock mtime
    intermittency deterministically (no dependence on file creation time)."""
    names = [("p" * 200) + f"_{i:03d}.bin" for i in range(256)]
    entries = [_boundary_entry(name, mtime) for name in names]
    spans = _assert_pages_bounded(entries)
    assert len(spans) >= 2  # 256 long-path entries cannot fit one page


@pytest.mark.parametrize("rel_len", [120, 180, 200, 247, 300])
def test_planner_page_fills_to_byte_boundary_without_busting(
    rel_len: int,
) -> None:
    """Entries of a controlled serialized size: the planner fills each page to
    the effective budget but never past it, so a page that fits exactly at the
    budget edge and a page one entry over both serialize within budget.

    Sweeps entry sizes so page remainders land at many different offsets from
    the bound (covers the 'exactly at budget' and 'one byte over' boundary
    families without wall-clock data)."""
    # len("_{i:05d}.bin") is a fixed 10 chars for i < 100000, so every entry in
    # this family has an identical serialized size.
    def make(index: int) -> dict[str, Any]:
        return _boundary_entry("x" * rel_len + f"_{index:05d}.bin", 1793733909.683923)

    entry_size = moecp._manifest_entry_bytes(make(0))
    overhead = moecp._MANIFEST_PAGE_OVERHEAD
    effective = moecp.MANIFEST_PAGE_BYTES - moecp._MANIFEST_PAGE_SLOP
    # Max entries that fit: overhead + n*size + 2*(n-1) <= effective
    n = max(1, (effective - overhead + 2) // (entry_size + 2))
    assert n < 100000  # keeps the fixed-width suffix assumption valid

    # Exact-fill page: n entries, real body equals the planner's estimate and
    # stays within the budget; n is maximal (n+1 cannot fit).
    exact = [make(i) for i in range(n)]
    spans = _assert_pages_bounded(exact)
    assert spans == [(0, n)], spans
    assert _manifest_body_bytes(exact) == overhead + n * entry_size + 2 * (n - 1)
    assert overhead + (n + 1) * entry_size + 2 * n > effective  # n is maximal

    # One-byte-over family: n+1 entries split into 2 pages, both bounded.
    over = [*exact, make(n)]
    spans = _assert_pages_bounded(over)
    assert len(spans) >= 2


def test_scaled_native_pull_thousands_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Thousands of entries incl. long paths through the native PULL path against
    the real framing: completes in seconds, every entry received, digests verify,
    no page exceeds the byte budget."""
    root = tmp_path / "scaled"
    root.mkdir()
    expected: dict[str, str] = {}
    for i in range(3000):
        name = (("q" * 200) + "_" if i % 7 == 0 else "") + f"file_{i:05d}.bin"
        content = f"payload-{i}".encode()
        (root / name).write_bytes(content)
        expected[name] = hashlib.sha256(content).hexdigest()
    start = time.monotonic()
    pair = NativePull(monkeypatch, tmp_path)
    try:
        pages = pair.pull_pages(str(root))
    finally:
        pair.close()
    elapsed = time.monotonic() - start
    received = [entry for page in pages for entry in page]
    assert len(received) == 3000, len(received)
    by_rel = {entry["rel"]: entry for entry in received}
    assert set(by_rel) == set(expected)
    for name, digest in expected.items():
        assert by_rel[name]["sha256"] == digest
    for page in pages:
        assert _manifest_body_bytes(page) <= moecp.MANIFEST_PAGE_BYTES
    assert elapsed < 30.0, elapsed


def test_native_and_worker_produce_identical_page_sequence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same input tree -> same page sequence (counts per page) from the native
    handler and the embedded worker: lockstep pagination."""
    root = _write_tree(tmp_path, [("m" * 120) + f"_{i:04d}.dat" for i in range(400)], b"z")
    pair = NativePull(monkeypatch, tmp_path)
    try:
        native_pages = pair.pull_pages(str(root))
    finally:
        pair.close()
    worker_pages = _worker_pull_pages(str(root))
    native_shape = [len(page) for page in native_pages]
    worker_shape = [len(page) for page in worker_pages]
    assert worker_shape == native_shape, (worker_shape, native_shape)
    assert sum(worker_shape) == 400


def test_worker_manifest_constants_match_moecp() -> None:
    """Drift guard: the worker's embedded manifest constants equal the named
    moecp constants (single source of truth for the byte budget)."""
    inline = re.search(r"^MANIFEST_INLINE_LIMIT = (\d+)$", moecp._WORKER_CODE, re.MULTILINE)
    page_size = re.search(r"^MANIFEST_PAGE_SIZE = (\d+)$", moecp._WORKER_CODE, re.MULTILINE)
    page_bytes = re.search(r"^MANIFEST_PAGE_BYTES = (\d+)$", moecp._WORKER_CODE, re.MULTILINE)
    assert inline is not None and page_size is not None and page_bytes is not None
    assert int(inline.group(1)) == moecp.MANIFEST_INLINE_LIMIT
    assert int(page_size.group(1)) == moecp.MANIFEST_PAGE_SIZE
    assert int(page_bytes.group(1)) == moecp.MANIFEST_PAGE_BYTES
