# Performance

Measured, per stage, on one machine. Nothing here is a spec — it is what the
current tree does when you run the benchmark yourself.

```sh
python3 bench/moesh_bench.py                 # 256 MiB per streaming stage
python3 bench/moesh_bench.py --size-mib 64   # quicker pass
```

The script measures each stage separately because they are **not
interchangeable**:

| stage | what it measures | what it does not |
|---|---|---|
| `raw socket pump` | the bridge copying bytes between two sockets, in this process | anything cryptographic, anything on disk, any network |
| `Noise_XX records` | encryption + framing between two real sessions over loopback | compression, file I/O, the receiver's bookkeeping |
| `zlib level 1` | the compression codec alone, on transfer-sized buffers | framing, crypto, disk, the network |
| `transfer ledger` | one SQLite WAL range record per call | the transfer around it |
| `end-to-end PUSH` | the real receiver: framing, crypto, staging, digest verification and the ledger, with the file committed and re-hashed | the network — this is loopback, in one process |

Effective throughput over a real link is bounded by the slowest of these plus
the link itself. Quoting one row as "the speed of `moecp`" is the error this
split exists to prevent.

## Reference run

Recorded 2026-10-27, on the audit host — an `aarch64` Oracle VM, Linux
7.0.0-1013, CPython 3.14.5, loopback, one process, no network. This was a
development VM, not a tuned benchmark machine; the ratios between stages are
the portable part, not the absolute numbers.

| stage | MiB/s | Gbit/s | note |
|---|---:|---:|---|
| raw socket pump (`bridge.pump`) | 1107.2 | 9.29 | no crypto, no disk |
| Noise_XX records (end to end) | 146.2 | 1.23 | crypto + framing, no disk |
| zlib level 1 (text) | 618.8 | 5.19 | input rate; ratio 0.009 |
| zlib level 1 (incompressible) | 44.2 | 0.37 | input rate; ratio 1.000 |
| transfer ledger records | 2939.0 | — | records/s (SQLite WAL) |
| end-to-end PUSH (raw) | 49.2 | 0.41 | 256 MiB committed and verified |
| end-to-end PUSH (zlib) | 46.8 | 0.39 | same, compressed |

### What the end-to-end number is made of

The same run instruments `TransferLedger.record_range` with a stopwatch (the
method the receiver calls, unmodified), because a per-chunk write is the one
part of the pipeline whose cost is easy to attribute wrongly:

| run | wall clock | ledger calls | time in the ledger | share |
|---|---:|---:|---:|---:|
| PUSH, raw, 256 MiB | 5.21 s | 8192 (1.00 per 32 KiB chunk) | 2.216 s | 43 % |
| PUSH, zlib, 256 MiB | 5.47 s | 8192 | 3.484 s | 64 % |

So the transfer is **not** limited by the cipher or by the compression codec on
this host: it is limited by one WAL record per chunk. That is a measured
bottleneck, deliberately left as one: batching those records trades durability
granularity for throughput, which is a design decision with a crash-consistency
consequence (see `docs/architecture.md` on resume) and belongs to a change that
analyses that trade-off, not to this characterization.

### Scaling notes

- **Incompressible payloads are the slow path for compression** (44 MiB/s of
  input at level 1, ratio 1.000). `moecp --compression auto` scans for
  precompressed extensions and streams those raw, which is what makes the
  "raw" row — not "zlib" — the right mental model for `.gguf`,
  `.safetensors` and archives.
- **Many small files** cost one ledger record and one frame round trip per
  chunk regardless of file size, so throughput falls with file count; the
  per-chunk cost above is the number to multiply by.
- **Resumed transfers** re-hash the staged prefix before skipping anything
  (progress is never trusted on its own), so resume costs a read of what is
  already on disk rather than a free skip.

## Reporting a number here

If you add a figure to the documentation, add the row it came from together
with the host line the benchmark printed. A number without the command that
produced it, on a stated machine, is not a measurement.
