#!/usr/bin/env python3
"""Peak-memory characterization of moecp PULL manifest generation at scale.

Measures the REAL PULL manifest code path in ``moecp.py`` (the native agent
transfer handler, ``run_native_agent_transfer`` PULL branch, moecp.py:2357-2448):

    os.walk  -> file_list  -> entries  -> manifest_page_plan  -> file_map
                                            ^ calls moecp's own page plan
                                            ^ its internal ``sized`` shadow
                                            copy is freed before
                                            manifest_page_plan returns, so it
                                            does NOT coexist with file_map
                                            post-B2 (byte-aware pagination)

The walk loop mirrors ``moecp.run_native_agent_transfer`` (moecp.py:2371-2394)
and reuses ``moecp.sanitize_relpath`` and ``moecp.manifest_page_plan``; nothing
about the manifest semantics is reimplemented.  A reimplementation would
measure the wrong thing (anti-idiocy R-MEASURE).

For each scale (1k / 10k / 100k / 1M entries) it builds a synthetic tree of
mixed path lengths (mean ~60 chars, long tail) once, then runs the generation
``runs`` times in fresh subprocesses (one subprocess per run so peak RSS is clean
per run) and reports:

    scale | n | mean path len | peak RSS MiB | tracemalloc peak MiB | gen time s

plus:
  * k bytes/entry from a least-squares fit peak_bytes ~ k*n (fixed interpreter
    baseline subtracted), and the file count at which RSS hits 512 MiB / 1 GiB;
  * per-structure attribution at the largest scale (deep sys.getsizeof of the
    structures that coexist at peak, shared objects counted once, plus
    tracemalloc snapshot diffs at each construction boundary);
  * a one-line verdict on whether SQLite/streaming is justified below that file
    count;
  * exact reproduction commands;
  * optional idle side RSS for moesh-bridge.py (live, loopback, non-operator
    ports) and moesh-relay.py (import footprint only -- it connects to a
    receiver, so a live idle run is not meaningful without one).

Usage:
    python3 bench/bench_manifest_memory.py \\
        [--scales 1k,10k,100k,1M] [--runs-per-scale 2] \\
        [--max-total-seconds 160] [--tree-dir /tmp/opencode/bench-trees] [--side]

Exit status is 0 when at least one scale completed.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import platform
import stat
import subprocess
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import moecp  # noqa: E402  (manifest wire constants imported from moecp, not redeclared)

MIB: int = 1024 * 1024
DATE: str = "2026-11-03"
# Long-tail fraction of files that get an extra ~170-char directory component.
LONG_FRAC: float = 0.01
# Content written to each synthetic file (manifest generation only stats files,
# it never reads content, so 1-byte files keep tree build fast and cheap).
FILE_CONTENT: bytes = b"\0"
# Overall wall-clock budget for the whole bench (tree builds + all runs).
MAX_TOTAL_SECONDS: float = 160.0


def scale_token(value: str) -> int:
    """Parse a scale token like ``1k``, ``10k``, ``100k``, ``1M`` into a count."""
    value = value.strip().lower()
    if value.endswith("m"):
        return int(float(value[:-1]) * 1_000_000)
    if value.endswith("k"):
        return int(float(value[:-1]) * 1_000)
    return int(value)


def vmhwm_kb() -> int:
    """Return this process's high-water-mark RSS in KiB (peak since start)."""
    with open("/proc/self/status") as handle:
        for line in handle:
            if line.startswith("VmHWM:"):
                return int(line.split()[1])
    return -1


def deep_getsizeof(obj: Any, seen: set[int] | None = None) -> int:
    """Recursive ``sys.getsizeof``; shared objects counted once via ``seen``."""
    if seen is None:
        seen = set()
    oid = id(obj)
    if oid in seen:
        return 0
    seen.add(oid)
    size = sys.getsizeof(obj)
    if isinstance(obj, dict):
        for key, val in obj.items():
            size += deep_getsizeof(key, seen) + deep_getsizeof(val, seen)
    elif isinstance(obj, (list, tuple, set, frozenset)):
        for item in obj:
            size += deep_getsizeof(item, seen)
    return size


def walk_file_list(root: str) -> list[dict[str, Any]]:
    """Mirror moecp PULL manifest file collection (moecp.py:2371-2394).

    Walks ``root`` and returns one dict per regular file (symlinks to regular
    files included), exactly as ``run_native_agent_transfer`` builds
    ``file_list``.  Reuses ``moecp.sanitize_relpath`` for the rel path.
    """
    file_list: list[dict[str, Any]] = []
    base_dir = root.rstrip("/")
    for current, _dirs, files in os.walk(base_dir):
        for fname in files:
            full = os.path.join(current, fname)
            try:
                lst = os.lstat(full)
            except OSError:
                continue
            if stat.S_ISLNK(lst.st_mode):
                try:
                    st = os.stat(full)
                    if not stat.S_ISREG(st.st_mode):
                        continue
                except OSError:
                    continue
            elif stat.S_ISREG(lst.st_mode):
                st = lst
            else:
                continue
            rel = moecp.sanitize_relpath(os.path.relpath(full, base_dir))
            file_list.append(
                {
                    "rel": rel,
                    "full": full,
                    "size": st.st_size,
                    "mode": st.st_mode,
                    "mtime": st.st_mtime,
                }
            )
    return file_list


def build_entries(file_list: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Mirror the metadata-only ``entries`` list (moecp.py:2408-2411)."""
    return [
        {"rel": f["rel"], "size": f["size"], "mode": f["mode"], "mtime": f["mtime"]}
        for f in file_list
    ]


def build_tree(root: str, n_files: int, seed: int = 20261103) -> tuple[float, float]:
    """Build ``n_files`` files with mixed path lengths under ``root``.

    Returns ``(build_seconds, mean_rel_path_len)``.  Directory names are cycled
    through a small fixed set so tree construction stays cheap (few
    ``makedirs`` calls) while file paths stay realistic: 3-4 directory levels
    plus a ~170-char component on ``LONG_FRAC`` of files (the long tail).
    """
    import random

    # S311: this RNG only shapes a synthetic bench tree; no secrets depend on it.
    rng = random.Random(seed)  # noqa: S311
    regions = [f"region-{r:04d}" for r in range(8)]
    clusters = [f"cluster-{c:03d}" for c in range(4)]
    hosts = [f"host-{h:03d}" for h in range(4)]
    disks = [f"disk-{d:02d}" for d in range(4)]
    long_dir = "x" * 170
    created_dirs: set[str] = set()
    total_len = 0
    started = time.perf_counter()
    for i in range(n_files):
        comps = [
            regions[i % 8],
            clusters[(i // 8) % 4],
            hosts[(i // 32) % 4],
            disks[(i // 128) % 4],
        ]
        if rng.random() < LONG_FRAC:
            comps.insert(1, long_dir)
        rel = "/".join([*comps, f"file-{i:08d}.bin"])
        total_len += len(rel)
        full = os.path.join(root, rel)
        directory = os.path.dirname(full)
        if directory not in created_dirs:
            os.makedirs(directory, exist_ok=True)
            created_dirs.add(directory)
        with open(full, "wb") as handle:
            handle.write(FILE_CONTENT)
    build_seconds = time.perf_counter() - started
    mean_len = total_len / n_files if n_files else 0.0
    return build_seconds, mean_len


def generate_manifest(
    tree_root: str,
    *,
    attribute: bool = False,
) -> dict[str, Any]:
    """Run one manifest generation and return per-run measurements.

    Runs the real code path in a fresh interpreter (import moecp, then
    tracemalloc), so peak RSS (VmHWM) is clean per run.  tracemalloc's peak
    captures the transient ``sized`` shadow copy allocated inside
    manifest_page_plan; its end value captures what still coexists after
    generation.
    """
    baseline_rss_kb = vmhwm_kb()
    tracemalloc.start()

    started = time.perf_counter()
    file_list = walk_file_list(tree_root)
    entries = build_entries(file_list)
    is_inline, spans = moecp.manifest_page_plan(
        entries,
        True,
        inline_limit=moecp.MANIFEST_INLINE_LIMIT,
        page_bytes=moecp.MANIFEST_PAGE_BYTES,
        entry_count_cap=moecp.MANIFEST_PAGE_SIZE,
    )
    file_map = {f["rel"]: f for f in file_list}
    inline_blob: str | None = None
    if is_inline:
        inline_blob = json.dumps({"status": "OK", "is_dir": True, "files": entries})
    generation_seconds = time.perf_counter() - started

    tracemalloc_peak = tracemalloc.get_traced_memory()[1]
    tracemalloc_end = tracemalloc.get_traced_memory()[0]
    tracemalloc.stop()
    end_rss_kb = vmhwm_kb()

    n = len(file_list)
    mean_rel_len = sum(len(f["rel"]) for f in file_list) / n if n else 0.0

    result: dict[str, Any] = {
        "n": n,
        "mean_rel_len": mean_rel_len,
        "is_inline": is_inline,
        "n_pages": len(spans),
        "generation_seconds": generation_seconds,
        "baseline_rss_kb": baseline_rss_kb,
        "end_rss_kb": end_rss_kb,
        "peak_rss_kb": end_rss_kb,  # VmHWM is the high-water mark for the run
        "tracemalloc_peak_bytes": tracemalloc_peak,
        # Current allocation at end of run = structures that still coexist after
        # generation (sized shadow already freed; inline blob already sent).
        "tracemalloc_end_bytes": tracemalloc_end,
        # Bytes that were allocated and freed during the run: the transient
        # manifest_page_plan ``sized`` shadow (+ sizes) and, for inline trees,
        # the serialized JSON blob.  Upper bound on transient duplication.
        "tracemalloc_transient_bytes": max(0, tracemalloc_peak - tracemalloc_end),
    }

    if attribute:
        # One shared ``seen`` set so objects shared across structures (the rel
        # strings, the file_list dicts that file_map references) are counted
        # once: this is the memory that actually coexists at peak.
        seen: set[int] = set()
        result["deep_bytes"] = {
            "file_list": deep_getsizeof(file_list, seen),
            "entries": deep_getsizeof(entries, seen),
            "file_map": deep_getsizeof(file_map, seen),
            "spans": deep_getsizeof(spans, seen),
        }

    # Release references so nothing is pinned for the RSS read already taken.
    del file_list, entries, file_map, spans, inline_blob
    return result


def run_subprocess(args: list[str]) -> dict[str, Any]:
    """Run one bench subprocess and parse its JSON result line."""
    # S603: args are constructed internally from our own scales/tree paths;
    # no operator-supplied input reaches this subprocess.
    proc = subprocess.run(  # noqa: S603
        args,
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"subprocess failed (rc={proc.returncode}): {proc.stderr[-2000:]}"
        )
    line = proc.stdout.strip().splitlines()[-1]
    return json.loads(line)


def baseline_rss() -> int:
    """Fixed interpreter+import RSS overhead (KiB) from a fresh subprocess."""
    result = run_subprocess(
        [sys.executable, str(ROOT / "bench" / "bench_manifest_memory.py"), "baseline"]
    )
    return int(result["baseline_rss_kb"])


def cmd_baseline() -> int:
    """Print baseline RSS (import moecp only) as one JSON line."""
    import moecp  # noqa: F401  (import cost is the baseline we subtract)

    print(json.dumps({"baseline_rss_kb": vmhwm_kb()}))
    return 0


def cmd_measure_one(tree_root: str, attribute: bool) -> int:
    """Print one generation run's measurements as one JSON line."""
    result = generate_manifest(tree_root, attribute=attribute)
    print(json.dumps(result))
    return 0


def fit_k(points: list[tuple[int, float]]) -> float:
    """Least-squares slope k for peak_bytes ~ k*n through the origin."""
    num = sum(n * rss for n, rss in points)
    den = sum(n * n for n, rss in points)
    return num / den if den else 0.0


def side_rss() -> dict[str, Any]:
    """Idle RSS of moesh-bridge.py (live) and import footprint of moesh-relay.py.

    The bridge is started on loopback high ports with relay ports disabled, so
    no operator port is touched (Iron Law 4).  The relay connects to a receiver,
    so a live idle run is not meaningful without one; its import footprint is
    reported instead.
    """
    import importlib.util

    out: dict[str, Any] = {"bridge": None, "relay_import_kb": None}

    # --- bridge: live idle on loopback high ports, relays disabled -------------
    bridge_env = dict(os.environ)
    bridge_env.update(
        {
            "MOESH_BRIDGE_TUNNEL_LISTEN": "127.0.0.1:49447",
            "MOESH_BRIDGE_OPERATOR_LISTEN": "127.0.0.1:44440",
            "MOESH_BRIDGE_OPERATOR_V2_LISTEN": "127.0.0.1:44441",
            # Disable GPU/relay ports (0.0.0.0:26420-26430 by default).
            "MOESH_BRIDGE_GPU_PORTS": "",
        }
    )
    # S603: the bridge is launched with interpreter + our own module path;
    # no operator-supplied input reaches this process.
    proc = subprocess.Popen(  # noqa: S603
        [sys.executable, str(ROOT / "moesh-bridge.py")],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=bridge_env,
    )
    try:
        # Wait for listeners to come up, then take a 30-second idle sample.
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline and proc.poll() is None:
            time.sleep(0.25)
        time.sleep(30.0)
        with open(f"/proc/{proc.pid}/status") as handle:
            for line in handle:
                if line.startswith("VmHWM:"):
                    out["bridge"] = {
                        "pid": proc.pid,
                        "peak_rss_kb": int(line.split()[1]),
                        "note": "idle 30s, loopback high ports, relays disabled",
                    }
                    break
    finally:
        if proc.poll() is None:
            proc.terminate()
            with contextlib.suppress(ProcessLookupError):
                proc.wait(timeout=5)

    # --- relay: import footprint only (it connects to a receiver at run time) --
    spec = importlib.util.spec_from_file_location(
        "bench_side_moesh_relay", ROOT / "moesh_relay.py"
    )
    if spec is not None and spec.loader is not None:
        module = importlib.util.module_from_spec(spec)
        before = vmhwm_kb()
        spec.loader.exec_module(module)
        after = vmhwm_kb()
        out["relay_import_kb"] = {
            "import_delta_kb": max(0, after - before),
            "after_rss_kb": after,
            "note": "import footprint only; live idle needs a receiver",
        }
    return out


def cmd_main(argv: list[str] | None = None) -> int:
    """Run the full characterization and print a small dated table."""
    parser = argparse.ArgumentParser(
        description="Peak memory of moecp PULL manifest generation at scale."
    )
    parser.add_argument(
        "--scales",
        default="1k,10k,100k,1M",
        help="comma-separated scale tokens (1k/10k/100k/1M)",
    )
    parser.add_argument(
        "--runs-per-scale",
        type=int,
        default=2,
        help="fresh subprocess runs per scale (>=2)",
    )
    parser.add_argument(
        "--max-total-seconds",
        type=float,
        default=MAX_TOTAL_SECONDS,
        help="wall-clock budget for the whole bench",
    )
    parser.add_argument(
        "--tree-dir",
        # S108: /tmp/opencode is the pre-created, operator-approved bench dir
        # (AGENTS.md test-environment gotchas); not a shared /tmp temp dir.
        default="/tmp/opencode/bench-trees",  # noqa: S108
        help="directory holding the synthetic trees",
    )
    parser.add_argument(
        "--side",
        action="store_true",
        default=False,
        help="also measure idle bridge / relay import RSS",
    )
    args = parser.parse_args(argv)

    scales = [scale_token(tok) for tok in args.scales.split(",") if tok.strip()]
    runs = max(1, args.runs_per_scale)
    tree_dir = args.tree_dir
    os.makedirs(tree_dir, exist_ok=True)

    print(f"moecp PULL manifest peak-memory characterization ({DATE})")
    print(f"  machine     : {platform.platform()}")
    print(f"  interpreter : {sys.version.split()[0]} ({sys.executable})")
    print(f"  scales      : {scales}")
    print(f"  runs/scale  : {runs}")
    print(f"  tree dir    : {tree_dir}")
    print(f"  path target : mean ~60 chars with a long tail ({LONG_FRAC*100:.0f}% long)")
    print()

    overall_started = time.perf_counter()

    # Fixed interpreter+import baseline (subtracted for the per-entry fit).
    print("baseline: measuring interpreter+import RSS (fresh subprocess) ...")
    baseline_kb = baseline_rss()
    print(f"    baseline RSS = {baseline_kb / 1024:.1f} MiB")
    print()

    header = (
        f"{'scale':<7}{'n':>9}{'mean len':>9}"
        f"{'peak RSS MiB':>13}{'tracemalloc MiB':>16}"
        f"{'gen time s':>12}"
    )
    print(header)
    print("-" * len(header))

    results: list[dict[str, Any]] = []
    largest_scale = scales[-1] if scales else 0
    largest_results: list[dict[str, Any]] = []

    for scale in scales:
        if time.perf_counter() - overall_started > args.max_total_seconds:
            print(f"  (stopped: time budget {args.max_total_seconds:.0f}s reached)")
            break
        tree_root = os.path.join(tree_dir, f"tree-{scale}")
        if not os.path.isdir(tree_root):
            os.makedirs(tree_root, exist_ok=True)
            build_seconds, mean_len = build_tree(tree_root, scale)
            print(
                f"  built tree-{scale}: {scale} files in {build_seconds:.2f}s "
                f"(mean rel path {mean_len:.0f} chars)",
                flush=True,
            )
        else:
            mean_len = 0.0
            count = 0
            for _current, _dirs, files in os.walk(tree_root):
                for fname in files:
                    mean_len += len(fname)
                    count += 1
            mean_len = mean_len / count if count else 0.0

        scale_runs: list[dict[str, Any]] = []
        for run in range(runs):
            if time.perf_counter() - overall_started > args.max_total_seconds:
                break
            attribute = run == 0 and scale == largest_scale
            result = run_subprocess(
                [
                    sys.executable,
                    str(ROOT / "bench" / "bench_manifest_memory.py"),
                    "measure-one",
                    tree_root,
                    "1" if attribute else "0",
                ]
            )
            result["run"] = run
            scale_runs.append(result)

        if not scale_runs:
            print(f"  tree-{scale}: no runs completed (time budget)")
            break

        n = scale_runs[0]["n"]
        peak_mibs = [r["peak_rss_kb"] / 1024.0 for r in scale_runs]
        trac_mibs = [r["tracemalloc_peak_bytes"] / MIB for r in scale_runs]
        times = [r["generation_seconds"] for r in scale_runs]
        attr_rss_mib = [max(0.0, (r["peak_rss_kb"] - baseline_kb) / 1024.0) for r in scale_runs]

        results.append(
            {
                "scale": scale,
                "n": n,
                "mean_len": scale_runs[0]["mean_rel_len"],
                "peak_rss_mib": sum(peak_mibs) / len(peak_mibs),
                "peak_rss_min": min(peak_mibs),
                "peak_rss_max": max(peak_mibs),
                "tracemalloc_mib": sum(trac_mibs) / len(trac_mibs),
                "gen_seconds": sum(times) / len(times),
                "gen_seconds_min": min(times),
                "gen_seconds_max": max(times),
                "attr_rss_mib": sum(attr_rss_mib) / len(attr_rss_mib),
                "runs": scale_runs,
            }
        )
        if scale == largest_scale:
            largest_results = scale_runs
        run_str = f"{times[0]:.3f}s"
        if len(times) > 1:
            run_str += f" / {times[1]:.3f}s"
        print(
            f"{scale:<7}{n:>9}{scale_runs[0]['mean_rel_len']:>9.0f}"
            f"{results[-1]['peak_rss_mib']:>13.2f}"
            f"{results[-1]['tracemalloc_mib']:>16.2f}"
            f"{results[-1]['gen_seconds']:>12.3f}"
            f"  (runs {run_str})"
        )

    print()

    # Fit k bytes/entry and ceilings.
    points = [
        (r["n"], r["attr_rss_mib"] * MIB) for r in results if r["n"] > 0
    ]
    k = fit_k(points) if points else 0.0
    n_512 = int((512 * MIB) / k) if k else 0
    n_1g = int((1024 * MIB) / k) if k else 0

    print("linearity fit  peak_bytes ~ k * n  (fixed baseline subtracted):")
    print(f"  k             = {k:,.1f} bytes/entry")
    print(f"  n at 512 MiB  = {n_512:,} files")
    print(f"  n at 1 GiB    = {n_1g:,} files")
    print()

    # Per-structure attribution at the largest scale.
    print("per-structure attribution at largest scale (deep sys.getsizeof):")
    if largest_results and "deep_bytes" in largest_results[0]:
        deep = largest_results[0]["deep_bytes"]
        total = deep["file_list"] + deep["entries"] + deep["file_map"]
        print(f"  n              = {largest_results[0]['n']:,}")
        print(
            f"  file_list      = {deep['file_list'] / MIB:>10.2f} MiB  "
            f"{deep['file_list'] / total * 100 if total else 0:>5.1f}%"
        )
        print(
            f"  entries        = {deep['entries'] / MIB:>10.2f} MiB  "
            f"{deep['entries'] / total * 100 if total else 0:>5.1f}%"
        )
        print(
            f"  file_map       = {deep['file_map'] / MIB:>10.2f} MiB  "
            f"{deep['file_map'] / total * 100 if total else 0:>5.1f}%"
        )
        print(f"  spans          = {deep['spans'] / MIB:>10.2f} MiB")
        print(f"  coexisting total  = {total / MIB:>10.2f} MiB")
        print(
            "  tracemalloc: peak {:.2f} MiB / end (coexisting) {:.2f} MiB / "
            "transient freed-by-end {:.2f} MiB".format(
                largest_results[0]["tracemalloc_peak_bytes"] / MIB,
                largest_results[0]["tracemalloc_end_bytes"] / MIB,
                largest_results[0]["tracemalloc_transient_bytes"] / MIB,
            )
        )
        print(
            "  note: manifest_page_plan's ``sized`` shadow copy is freed before "
            "file_map is built (post-B2), so it does not coexist with file_map; "
            "it DOES coexist transiently with file_list+entries during the call "
            "(that transient is the peak-end gap above)."
        )
    else:
        print(
            "  (attribution skipped -- attribution runs on the largest scale's first run)"
        )
    print()

    # Verdict.
    realistic = 1_000_000  # a large home-directory / site tree is on this order
    if k and n_512 > max(realistic, 10_000):
        verdict = (
            f"SQLite/streaming NOT justified below {n_512:,} files "
            f"(current code survives {n_512:,} files within 512 MiB; "
            f"realistic trees are ~{realistic:,} and under the ceiling)."
        )
    elif k:
        verdict = (
            f"SQLite/streaming warranted around {n_512:,} files "
            f"(512 MiB ceiling); current code reaches {n_512:,} before the budget."
        )
    else:
        verdict = "could not fit k (no completed scales)."
    print("VERDICT: " + verdict)
    print()

    # Side measurement.
    if args.side:
        print("side measurement: idle bridge / relay import RSS (" + DATE + ")")
        side = side_rss()
        if side["bridge"]:
            b = side["bridge"]
            print(
                f"  moesh-bridge.py idle peak RSS = {b['peak_rss_kb'] / 1024:.2f} MiB "
                f"(pid {b['pid']}, {b['note']})"
            )
        else:
            print("  moesh-bridge.py idle: could not read VmHWM")
        if side["relay_import_kb"]:
            r = side["relay_import_kb"]
            print(
                f"  moesh-relay.py import footprint = {r['import_delta_kb'] / 1024:.2f} MiB "
                f"(after {r['after_rss_kb'] / 1024:.2f} MiB; {r['note']})"
            )
        print()

    # Reproduction commands.
    print("reproduction:")
    print(f"  cd {ROOT}")
    print(f"  python3 bench/bench_manifest_memory.py --scales {args.scales} --runs-per-scale {runs}")
    print("  python3 bench/bench_manifest_memory.py --side")
    print()

    return 0 if results else 1


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "baseline":
        raise SystemExit(cmd_baseline())
    if len(sys.argv) >= 3 and sys.argv[1] == "measure-one":
        tree_root = sys.argv[2]
        attribute = len(sys.argv) > 3 and sys.argv[3] == "1"
        raise SystemExit(cmd_measure_one(tree_root, attribute))
    raise SystemExit(cmd_main())
