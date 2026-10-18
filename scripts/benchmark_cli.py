#!/usr/bin/env python3
"""Black-box CLI timing harness. No performance threshold, no execution of input binaries."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SIZES = (2048, 1024 * 1024, 4 * 1024 * 1024)


def measure(binary: Path, fixture: bytes, target: Path, count: int, warmup: int) -> dict:
    target.write_bytes(fixture)
    with target.open("r+b") as output:
        output.truncate(target.stat().st_size)
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    observations: list[float] = []
    for iteration in range(warmup + count):
        start = time.perf_counter_ns()
        result = subprocess.run(
            [str(binary), "analyze", str(target)],
            capture_output=True, text=True, timeout=30, check=False,
        )
        elapsed = (time.perf_counter_ns() - start) / 1_000_000
        if result.returncode != 0:
            raise RuntimeError(f"REL failed for {target.name}: {result.stderr[:200]}")
        report = json.loads(result.stdout)
        if report["binary_sha256"] != digest or report["size_bytes"] != target.stat().st_size:
            raise RuntimeError("Manifest verification failed")
        if iteration >= warmup:
            observations.append(elapsed)

    ordered = sorted(observations)
    return {
        "size_bytes": target.stat().st_size,
        "sha256": digest,
        "iterations": len(observations),
        "median_ms": round(statistics.median(ordered), 4),
        "p95_ms": round(ordered[max(0, math.ceil(len(ordered) * 0.95) - 1)], 4),
        "min_ms": round(ordered[0], 4),
        "max_ms": round(ordered[-1], 4),
        "all_ms": [round(x, 4) for x in observations],
    }


def run(binary: Path, count: int, warmup: int) -> dict:
    fixture = (ROOT / "fixtures/pe64-basic.exe").read_bytes()
    if len(fixture) != 2048:
        raise ValueError("Reference fixture size changed")
    metadata = {
        "kind": "rel-cli-benchmark-v1",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "os": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "commit": os.environ.get("GITHUB_SHA"),
        "binary": binary.name,
        "method": "CLI process startup + PE parsing + SHA-256 + JSON stdout",
        "warmup": warmup,
        "samples": count,
    }
    results = []
    with tempfile.TemporaryDirectory(prefix="rel-bench-") as directory:
        for size in SIZES:
            target = Path(directory) / f"fixture-overlay-{size}.exe"
            with target.open("wb") as output:
                output.write(fixture)
                output.truncate(size)
            results.append(measure(binary, fixture, target, count, warmup))
            # measure() reopens file and preserves its requested size.
    return {"environment": metadata, "results": results}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--samples", type=int, default=9)
    parser.add_argument("--warmup", type=int, default=2)
    args = parser.parse_args()
    if not 3 <= args.samples <= 200:
        parser.error("--samples must be between 3 and 200")
    if not 0 <= args.warmup <= 50:
        parser.error("--warmup must be between 0 and 50")
    report = run(args.binary.resolve(strict=True), args.samples, args.warmup)
    document = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as output:
            output.write(document)
    else:
        sys.stdout.write(document)


if __name__ == "__main__":
    main()
