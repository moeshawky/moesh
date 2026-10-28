#!/usr/bin/env python3
"""Reproducible performance characterization for moesh (audit issue MOESH-015).

Each stage is measured on its own, because they are not interchangeable: a raw
socket pump is not an encrypted stream, an encrypted stream is not a
compression codec, and a compression codec is not an end-to-end file transfer.
The last section measures the whole in-process pipeline (framing, cipher,
staging, digest, ledger) against the real receiver, so the composition can be
compared with the parts instead of being inferred from them.

Everything runs on loopback in one process.  That is deliberate: the number
reported is the cost of *this process* doing the work, with the network taken
out, which is the only part a change to moesh can move.

Usage:
    python3 bench/moesh_bench.py [--size-mib 256] [--chunk-mib 32] [--ledger-ops 200]

The table printed here is what ``docs/performance.md`` records.  Re-run it on
the machine you care about before quoting any figure.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import os
import platform
import socket
import sys
import tempfile
import threading
import time
import zlib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import moesh_proto as proto  # noqa: E402  (path set up above)
from moecp import (  # noqa: E402
    CHUNK_SIZE,
    FramedStreamClient,
    TransferLedger,
    run_native_agent_transfer,
)

MIB = 1024 * 1024


def load_bridge_module() -> Any:
    """Load ``moesh-bridge.py`` so its pump can be measured directly."""
    spec = importlib.util.spec_from_file_location("moesh_bench_bridge", ROOT / "moesh-bridge.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def gibps(mib_per_second: float) -> float:
    """Convert MiB/s to Gbit/s (1 MiB = 2**20 bytes)."""
    return mib_per_second * MIB * 8 / 1e9


def make_payload(kind: str, size: int) -> bytes:
    """Return ``size`` bytes of compressible text or incompressible noise.

    The noise is derived from SHA-256 so the workload is identical on every
    run; ``os.urandom`` would make the compressed sizes wobble.
    """
    if kind == "text":
        line = b"def copy(src, dst):  # transfer chunk, zlib level 1\n"
        return (line * (size // len(line) + 1))[:size]
    out = bytearray()
    block = b"\x00" * 32
    counter = 0
    while len(out) < size:
        block = hashlib.sha256(block + counter.to_bytes(8, "big")).digest()
        out += block
        counter += 1
    return bytes(out[:size])


def handshake_pair() -> tuple[proto.SecureChannel, proto.SecureChannel, socket.socket, socket.socket]:
    """Establish two real Noise_XX sessions over a loopback socketpair."""
    private_a, public_a = proto.generate_static_keypair()
    private_b, public_b = proto.generate_static_keypair()
    sock_a, sock_b = socket.socketpair()
    sock_a.settimeout(30)
    sock_b.settimeout(30)
    session_a = proto.NoiseSession("initiator", private_a, public_b)
    session_b = proto.NoiseSession("responder", private_b, public_a)
    errors: list[BaseException] = []

    def initiator() -> None:
        try:
            channel = proto.Channel(sock_a)
            channel.send_frame(session_a.write_handshake())
            session_a.read_handshake(channel.recv_frame())
            channel.send_frame(session_a.write_handshake())
        except BaseException as exc:  # reported below
            errors.append(exc)

    def responder() -> None:
        try:
            channel = proto.Channel(sock_b)
            session_b.read_handshake(channel.recv_frame())
            channel.send_frame(session_b.write_handshake())
            session_b.read_handshake(channel.recv_frame())
        except BaseException as exc:  # reported below
            errors.append(exc)

    threads = [threading.Thread(target=initiator), threading.Thread(target=responder)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    if errors:
        raise RuntimeError(f"handshake failed: {errors!r}")
    return (
        proto.SecureChannel(proto.Channel(sock_a), session_a),
        proto.SecureChannel(proto.Channel(sock_b), session_b),
        sock_a,
        sock_b,
    )


# ---------------------------------------------------------------------------
# Component measurements
# ---------------------------------------------------------------------------


def bench_pump(bridge: Any, size: int) -> tuple[float, float]:
    """Raw transport: bytes through the bridge's own two-way pump, no crypto."""
    sender_end, pump_end = socket.socketpair()
    pump_other, sink_end = socket.socketpair()
    done = threading.Event()

    def run_pump() -> None:
        try:
            bridge.pump(pump_end, pump_other, linger=5.0)
        finally:
            done.set()

    def drain() -> None:
        remaining = size
        while remaining > 0:
            data = sink_end.recv(1 << 20)
            if not data:
                break
            remaining -= len(data)

    threading.Thread(target=run_pump, daemon=True).start()
    sink = threading.Thread(target=drain)
    sink.start()
    chunk = b"\x5a" * (1 << 16)
    started = time.perf_counter()
    sent = 0
    while sent < size:
        sender_end.sendall(chunk)
        sent += len(chunk)
    sink.join(120)
    sender_end.close()
    started = time.perf_counter() - started
    for sock in (sink_end, pump_end, pump_other):
        with contextlib.suppress(OSError):
            sock.close()
    done.wait(5)
    return size / MIB / started, started


def bench_encrypted(size: int) -> float:
    """Encryption + framing: records through two real Noise_XX sessions."""
    sender, receiver, sock_a, sock_b = handshake_pair()
    payload = b"\xa5" * proto.MAX_DATA_PAYLOAD

    def drain() -> None:
        remaining = size
        while remaining > 0:
            _msg_type, data = receiver.recv()
            remaining -= len(data)

    sink = threading.Thread(target=drain)
    started = time.perf_counter()
    sink.start()
    sent = 0
    while sent < size:
        take = min(proto.MAX_DATA_PAYLOAD, size - sent)
        sender.send(proto.Msg.DATA, payload[:take])
        sent += take
    sink.join(120)
    elapsed = time.perf_counter() - started
    for sock in (sock_a, sock_b):
        with contextlib.suppress(OSError):
            sock.close()
    return size / MIB / elapsed


def bench_compression(kind: str, size: int) -> tuple[float, float]:
    """Compression only: ``zlib`` level 1 over transfer-sized chunks.

    The call mirrors the transfer path (``zlib.compress(buf, 1)`` with
    ``CHUNK_SIZE`` buffers); the result is the rate of *input* bytes, which is
    what a transfer cares about.
    """
    payload = make_payload(kind, size)
    started = time.perf_counter()
    compressed = 0
    for offset in range(0, len(payload), CHUNK_SIZE):
        compressed += len(zlib.compress(payload[offset : offset + CHUNK_SIZE], 1))
    elapsed = time.perf_counter() - started
    return len(payload) / MIB / elapsed, compressed / len(payload)


def bench_ledger(ops: int, db_path: str) -> float:
    """Ledger overhead: WAL-backed range records per second."""
    ledger = TransferLedger(db_path)
    ledger.record_transfer("bench-transfer", "file.bin", ops * 1024, "0" * 64)
    started = time.perf_counter()
    for index in range(ops):
        ledger.record_range("bench-transfer", index * 1024, (index + 1) * 1024, "a" * 64)
    elapsed = time.perf_counter() - started
    return ops / elapsed


# ---------------------------------------------------------------------------
# End-to-end: a real PUSH into the real receiver
# ---------------------------------------------------------------------------


def bench_end_to_end(size: int, compression: str) -> tuple[float, float, int]:
    """Push a file through the real receiver and measure effective throughput.

    The sender side frames the transfer exactly as ``moecp`` does
    (``INIT`` → ``FILE_START`` → ``CHUNK`` → ``FILE_END`` → ``DONE``) over a
    real encrypted channel; the receiving side is the agent's own
    ``run_native_agent_transfer``, with the ledger, staging and digest
    verification that ships in the product.

    ``TransferLedger.record_range`` is instrumented with a stopwatch (the same
    method the receiver calls, unmodified) so the ledger's share of the wall
    clock is measured rather than inferred from the write rate.

    Returns:
        ``(MiB/s, ledger seconds, ledger calls)``.
    """
    ledger_seconds = [0.0]
    ledger_calls = [0]
    original_record_range = TransferLedger.record_range

    def timed_record_range(self: TransferLedger, *args: Any, **kwargs: Any) -> Any:
        started_at = time.perf_counter()
        try:
            return original_record_range(self, *args, **kwargs)
        finally:
            ledger_seconds[0] += time.perf_counter() - started_at
            ledger_calls[0] += 1

    TransferLedger.record_range = timed_record_range
    payload = make_payload("text", size)
    digest = hashlib.sha256(payload).hexdigest()
    with tempfile.TemporaryDirectory() as work:
        source = Path(work) / "source.bin"
        source.write_bytes(payload)
        target = Path(work) / "target"
        target.mkdir()
        os.environ["MOECP_LEDGER_PATH"] = str(Path(work) / "ledger.db")

        sender, receiver, sock_a, sock_b = handshake_pair()
        server_error: list[BaseException] = []
        started = threading.Event()

        def serve() -> None:
            try:
                started.wait(30)
                run_native_agent_transfer(sock_b, receiver, {"session_type": "transfer"})
            except BaseException as exc:  # surfaced by the caller
                server_error.append(exc)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        client = FramedStreamClient(sender, sock_a)
        client.send_frame(
            {
                "op": "INIT",
                "direction": "PUSH",
                "target": str(target),
                "is_dir": False,
                "preserve": False,
            }
        )
        ack, _ = client.recv_frame()
        assert ack.get("status") == "OK", ack
        client.send_frame(
            {
                "op": "FILE_START",
                "rel_path": "source.bin",
                "size": len(payload),
                "mode": 0o644,
                "mtime": time.time(),
                "sha256": digest,
            }
        )
        ready, _ = client.recv_frame()
        assert ready.get("status") == "READY", ready

        started.set()
        timer = time.perf_counter()
        with open(source, "rb") as handle:
            while buf := handle.read(CHUNK_SIZE):
                if compression == "raw":
                    client.send_frame({"op": "CHUNK", "encoding": "raw"}, buf)
                else:
                    client.send_frame({"op": "CHUNK", "encoding": "zlib"}, zlib.compress(buf, 1))
        client.send_frame({"op": "FILE_END"})
        end_ack, _ = client.recv_frame()
        assert end_ack.get("status") == "OK", end_ack
        client.send_frame({"op": "DONE"})
        done_ack, _ = client.recv_frame()
        assert done_ack.get("status") == "DONE", done_ack
        elapsed = time.perf_counter() - timer

        thread.join(30)
        if server_error:
            raise RuntimeError(f"receiver failed: {server_error!r}")
        written = target / "source.bin"
        assert written.is_file(), "receiver did not commit the file"
        assert hashlib.sha256(written.read_bytes()).hexdigest() == digest, "commit mismatch"
        for sock in (sock_a, sock_b):
            with contextlib.suppress(OSError):
                sock.close()
    TransferLedger.record_range = original_record_range  # type: ignore[method-assign]
    return size / MIB / elapsed, ledger_seconds[0], ledger_calls[0]


def main(argv: list[str] | None = None) -> int:
    """Run every stage and print one table."""
    parser = argparse.ArgumentParser(description="moesh performance characterization")
    parser.add_argument("--size-mib", type=int, default=256, help="payload size for streaming stages")
    parser.add_argument("--ledger-ops", type=int, default=200, help="ledger records to time")
    args = parser.parse_args(argv)

    size = args.size_mib * MIB
    bridge = load_bridge_module()

    print("moesh performance characterization")
    print(f"  host      : {platform.platform()}")
    print(f"  cpu       : {platform.processor() or platform.machine()}")
    print(f"  python    : {sys.version.split()[0]}")
    print(f"  payload   : {args.size_mib} MiB per streaming stage; loopback, one process")
    print()
    print(f"{'stage':<34}{'MiB/s':>10}{'Gbit/s':>10}   note")
    print("-" * 88)

    pump_rate, _ = bench_pump(bridge, size)
    print(f"{'raw socket pump (bridge.pump)':<34}{pump_rate:>10.1f}{gibps(pump_rate):>10.2f}   no crypto, no disk")

    enc_rate = bench_encrypted(size)
    print(f"{'Noise_XX records (end to end)':<34}{enc_rate:>10.1f}{gibps(enc_rate):>10.2f}   crypto + framing, no disk")

    for kind in ("text", "incompressible"):
        rate, ratio = bench_compression(kind, size)
        print(
            f"{'zlib level 1 (' + kind + ')':<34}{rate:>10.1f}{gibps(rate):>10.2f}"
            f"   input rate, ratio {ratio:.3f}"
        )

    ledger_rate = bench_ledger(args.ledger_ops, str(Path(tempfile.mkdtemp()) / "ledger.db"))
    print(f"{'transfer ledger records':<34}{ledger_rate:>10.1f}{'':>10}   records/s (SQLite WAL)")

    for compression in ("raw", "zlib"):
        e2e, ledger_seconds, ledger_calls = bench_end_to_end(size, compression)
        print(
            f"{'end-to-end PUSH (' + compression + ')':<34}{e2e:>10.1f}{gibps(e2e):>10.2f}"
            "   client+receiver, staging, digest"
        )
        if ledger_calls:
            chunk_count = max(1, size // CHUNK_SIZE)
            print(
                f"{'  of which ledger writes':<34}{'':>10}{'':>10}"
                f"   {ledger_calls} calls ({ledger_calls / chunk_count:.2f}/chunk), "
                f"{ledger_seconds:.3f}s of the run"
            )

    print("-" * 88)
    print(
        "All figures are loopback and in-process: they measure the work moesh does,\n"
        "not the network.  Effective throughput over a real link is bounded by the\n"
        "slowest stage above plus the link itself.  Re-run on the target machine\n"
        "before quoting any of these numbers."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
