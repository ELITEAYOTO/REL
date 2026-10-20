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

from _internal.corpus_cases import ROOT, prepare_cases
from _internal.measurement_environment import capture_context


def measure(binary: Path, target: Path, count: int, warmup: int) -> dict:
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


def run(
    binary: Path, count: int, warmup: int, *,
    windows_msvc_probe: Path | None = None,
    windows_clang_probe: Path | None = None,
    windows_msvc_structured: Path | None = None,
    windows_clang_structured: Path | None = None,
    linux_mingw_probe: Path | None = None,
) -> dict:
    context, context_id = capture_context(binary)
    metadata = {
        "kind": "rel-cli-benchmark-v1",
        "measurement_context": context,
        "measurement_context_sha256": context_id,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "os": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "commit": os.environ.get("GITHUB_SHA"),
        "binary": binary.name,
        "method": "CLI process startup + PE parsing + SHA-256 + JSON stdout",
        "warmup": warmup,
        "samples": count,
        "corpus_policy": "docs/security/P15A_CORPUS_PROVENANCE.md",
    }
    results = []
    with tempfile.TemporaryDirectory(prefix="rel-bench-") as directory:
        cases = prepare_cases(
            ROOT / "fixtures", Path(directory), binary,
            include_windows_executable=os.name == "nt",
            windows_msvc_probe=windows_msvc_probe,
            windows_clang_probe=windows_clang_probe,
            windows_msvc_structured=windows_msvc_structured,
            windows_clang_structured=windows_clang_structured,
            linux_mingw_probe=linux_mingw_probe,
        )
        for case in cases:
            results.append({
                **case.report_fields(),
                **measure(binary, case.path, count, warmup),
            })
    return {"environment": metadata, "results": results}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--samples", type=int, default=9)
    parser.add_argument("--warmup", type=int, default=2)
    parser.add_argument("--windows-msvc-probe", type=Path)
    parser.add_argument("--windows-clang-probe", type=Path)
    parser.add_argument("--windows-msvc-structured", type=Path)
    parser.add_argument("--windows-clang-structured", type=Path)
    parser.add_argument("--linux-mingw-probe", type=Path)
    args = parser.parse_args()
    if os.name != "nt":
        if args.windows_msvc_probe is not None:
            parser.error("--windows-msvc-probe is Windows only")
        if args.windows_clang_probe is not None:
            parser.error("--windows-clang-probe is Windows only")
        if args.windows_msvc_structured is not None or args.windows_clang_structured is not None:
            parser.error("structured compiler probes are Windows only")
    if not 3 <= args.samples <= 200:
        parser.error("--samples must be between 3 and 200")
    if os.name == "nt" and args.linux_mingw_probe is not None:
        parser.error("--linux-mingw-probe is Linux only")
    if not 0 <= args.warmup <= 50:
        parser.error("--warmup must be between 0 and 50")
    report = run(
        args.binary.resolve(strict=True), args.samples, args.warmup,
        windows_msvc_probe=(
            args.windows_msvc_probe.resolve(strict=True)
            if args.windows_msvc_probe is not None else None
        ),
        windows_clang_probe=(
            args.windows_clang_probe.resolve(strict=True)
            if args.windows_clang_probe is not None else None
        ),
        windows_msvc_structured=(
            args.windows_msvc_structured.resolve(strict=True)
            if args.windows_msvc_structured is not None else None
        ),
        windows_clang_structured=(
            args.windows_clang_structured.resolve(strict=True)
            if args.windows_clang_structured is not None else None
        ),
        linux_mingw_probe=(
            args.linux_mingw_probe.resolve(strict=True)
            if args.linux_mingw_probe is not None else None
        ),
    )
    document = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as output:
            output.write(document)
    else:
        sys.stdout.write(document)


if __name__ == "__main__":
    main()
