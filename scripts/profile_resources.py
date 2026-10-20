#!/usr/bin/env python3
"""Measure observed resources of REL CLI. This never launches the inspected PE."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil
from _internal.corpus_cases import ROOT, prepare_cases
from _internal.measurement_environment import capture_context
TIMEOUT_SECONDS = 30
POLL_SECONDS = 0.002


def poll_child_with_usage(process: psutil.Popen) -> tuple[int | None, int | None, float | None]:
    """Reap Linux direct child with final kernel usage; retain Windows polling."""
    if sys.platform != "linux":
        return process.poll(), None, None
    pid, status, usage = os.wait4(process.pid, os.WNOHANG)
    if pid == 0:
        return None, None, None
    # No earlier poll()/wait(): either would consume wait4's rusage.
    process.returncode = os.waitstatus_to_exitcode(status)
    return (
        process.returncode,
        int(usage.ru_maxrss) * 1024,  # Linux ru_maxrss is in KiB.
        round((usage.ru_utime + usage.ru_stime) * 1000, 4),
    )


def profile_once(binary: Path, fixture: Path) -> dict:
    """Use file redirection to avoid child stdout/stderr pipe deadlocks."""
    expected_hash = hashlib.sha256(fixture.read_bytes()).hexdigest()
    started = time.perf_counter()
    peak_sampled_rss: int | None = None
    cpu_ms: float | None = None
    kernel_peak_rss: int | None = None
    kernel_cpu_ms: float | None = None
    samples = 0

    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as stdout:
        with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as stderr:
            process = psutil.Popen(
                [str(binary), "analyze", str(fixture)],
                stdout=stdout,
                stderr=stderr,
            )
            try:
                while True:
                    if time.perf_counter() - started > TIMEOUT_SECONDS:
                        raise TimeoutError(f"REL CLI exceeded {TIMEOUT_SECONDS}s")
                    try:
                        info = process.memory_info()
                        times = process.cpu_times()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                    else:
                        peak_sampled_rss = max(peak_sampled_rss or 0, info.rss)
                        cpu_ms = (times.user + times.system) * 1000
                        samples += 1
                    status, kernel_peak_rss, kernel_cpu_ms = poll_child_with_usage(process)
                    if status is not None:
                        break
                    time.sleep(POLL_SECONDS)
            except BaseException:
                if process.poll() is None:
                    process.kill()
                process.wait()
                raise
            wall_ms = (time.perf_counter() - started) * 1000
            stdout.seek(0)
            stderr.seek(0)
            if status:
                raise RuntimeError(f"REL CLI failed: {stderr.read(400)}")
            manifest = json.load(stdout)
            if manifest["binary_sha256"] != expected_hash:
                raise AssertionError("CLI hash differs from profiled fixture")
            if manifest["size_bytes"] != fixture.stat().st_size:
                raise AssertionError("CLI file size differs from profiled fixture")

    return {
        "wall_ms": round(wall_ms, 4),
        "sampled_peak_rss_bytes": peak_sampled_rss,
        "last_sampled_cpu_ms": round(cpu_ms, 4) if cpu_ms is not None else None,
        "resource_samples": samples,
        "kernel_peak_rss_bytes": kernel_peak_rss,
        "kernel_cpu_ms": kernel_cpu_ms,
    }


def summarize(values: list[dict]) -> dict:
    wall = [sample["wall_ms"] for sample in values]
    rss = [sample["sampled_peak_rss_bytes"] for sample in values]
    cpu = [sample["last_sampled_cpu_ms"] for sample in values]
    observed_rss = [value for value in rss if value is not None]
    observed_cpu = [value for value in cpu if value is not None]
    kernel_rss = [v["kernel_peak_rss_bytes"] for v in values
                  if v["kernel_peak_rss_bytes"] is not None]
    kernel_cpu = [v["kernel_cpu_ms"] for v in values
                  if v["kernel_cpu_ms"] is not None]
    return {
        "wall_median_ms": round(statistics.median(wall), 4),
        "max_sampled_rss_bytes": max(observed_rss) if observed_rss else None,
        "max_last_sampled_cpu_ms": max(observed_cpu) if observed_cpu else None,
        "max_kernel_peak_rss_bytes": max(kernel_rss) if kernel_rss else None,
        "max_kernel_cpu_ms": max(kernel_cpu) if kernel_cpu else None,
        "observations": values,
    }


def run(
    binary: Path, samples: int, warmup: int, *,
    windows_msvc_probe: Path | None = None,
    windows_clang_probe: Path | None = None,
    windows_msvc_structured: Path | None = None,
    windows_clang_structured: Path | None = None,
    linux_mingw_probe: Path | None = None,
) -> dict:
    context, context_id = capture_context(binary)
    meta = {
        "schema": "rel-resource-observations-v1",
        "measurement_context": context,
        "measurement_context_sha256": context_id,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "os": platform.platform(),
        "machine": platform.machine(),
        "python_version": platform.python_version(),
        "psutil_version": psutil.__version__,
        "git_sha": os.environ.get("GITHUB_SHA"),
        "analyzer": binary.name,
        "method": "observed child-process RSS/CPU sampling, CLI wall-time",
        "kernel_usage_method": (
            "linux-wait4-ru_maxrss-and-ru_utime-ru_stime"
            if sys.platform == "linux" else None
        ),
        "poll_interval_ms_nominal": POLL_SECONDS * 1000,
        "timeout_seconds": TIMEOUT_SECONDS,
        "warmup": warmup,
        "samples": samples,
        "corpus_policy": "docs/security/P15A_CORPUS_PROVENANCE.md",
    }
    scenarios = []
    with tempfile.TemporaryDirectory(prefix="rel-resource-") as folder:
        cases = prepare_cases(
            ROOT / "fixtures", Path(folder), binary,
            include_windows_executable=os.name == "nt",
            windows_msvc_probe=windows_msvc_probe,
            windows_clang_probe=windows_clang_probe,
            windows_msvc_structured=windows_msvc_structured,
            windows_clang_structured=windows_clang_structured,
            linux_mingw_probe=linux_mingw_probe,
        )
        for case in cases:
            for _ in range(warmup):
                profile_once(binary, case.path)
            readings = [profile_once(binary, case.path) for _ in range(samples)]
            scenarios.append({
                **case.report_fields(),
                "size_bytes": case.path.stat().st_size,
                "sha256": hashlib.sha256(case.path.read_bytes()).hexdigest(),
                **summarize(readings),
            })
    return {"environment": meta, "scenarios": scenarios}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--warmup", type=int, default=1)
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
    if not 2 <= args.samples <= 100:
        parser.error("--samples must be between 2 and 100")
    if os.name == "nt" and args.linux_mingw_probe is not None:
        parser.error("--linux-mingw-probe is Linux only")
    if not 0 <= args.warmup <= 20:
        parser.error("--warmup must be between 0 and 20")
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
    document = json.dumps(report, indent=2) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as output:
            output.write(document)
    else:
        sys.stdout.write(document)


if __name__ == "__main__":
    main()
