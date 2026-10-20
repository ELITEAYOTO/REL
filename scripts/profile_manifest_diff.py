#!/usr/bin/env python3
"""Observe rel-diff time/RSS on synthetic metadata, not real PE corpus behavior.

Sampling misses short-lived peaks; runner values are observations, not limits.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import statistics
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil
from _internal.measurement_environment import capture_context

TIMEOUT_SECONDS = 30
POLL_SECONDS = 0.002
MAX_REPORT_BYTES = 16 * 1024 * 1024
MIN_NEAR_REPORT_BYTES = 15 * 1024 * 1024


def manifest(
    digest: str, imports: list[str], *,
    exports: list[str] | None = None, sections: list[dict] | None = None,
) -> dict:
    return {
        "schema_version": "1.0.0",
        "binary_sha256": digest * 64,
        "size_bytes": 1024,
        "format": "PE",
        "arch": "x86_64",
        "sections": sections if sections is not None else [
            {"name": ".text", "offset": 512, "size": 64, "virtual_address": 4096}
        ],
        "imports": imports,
        "exports": exports if exports is not None else [],
        "warnings": [],
    }


def mixed_pair(count: int) -> tuple[dict, dict]:
    """Controlled mixed-cardinality stress case, not a real PE layout."""
    def make_side(digest: str) -> dict:
        sections = []
        for index in range(count):
            shared = index < count // 2
            name = f".shared{index:05}" if shared else f".{digest}{index:05}"
            sections.append({
                "name": name, "offset": 512 + 64 * index,
                "size": (64 if digest == "a" else 80) if shared else 64,
                "virtual_address": 4096 + 64 * index,
            })
        return manifest(
            digest,
            [f"KERNEL32.dll!{digest}Import{index:05}" for index in range(count)],
            exports=[f"{digest}Export{index:05}" for index in range(count)],
            sections=sections,
        )

    return make_side("a"), make_side("b")


def profile_once(
    binary: Path, left: Path, right: Path, expected: tuple[str, str],
    expected_counts: tuple[int, int, int, int, int],
) -> dict:
    started = time.perf_counter()
    sampled_rss = None
    sampled_cpu = None
    observations = 0
    with tempfile.TemporaryFile(mode="w+b") as stdout:
        with tempfile.TemporaryFile(mode="w+b") as stderr:
            child = psutil.Popen([str(binary), str(left), str(right)], stdout=stdout, stderr=stderr)
            try:
                while True:
                    if time.perf_counter() - started > TIMEOUT_SECONDS:
                        raise TimeoutError(f"rel-diff exceeded {TIMEOUT_SECONDS}s")
                    try:
                        sample = child.memory_info()
                        cpu = child.cpu_times()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                    else:
                        sampled_rss = max(sampled_rss or 0, sample.rss)
                        sampled_cpu = (cpu.user + cpu.system) * 1000
                        observations += 1
                    if child.poll() is not None:
                        break
                    time.sleep(POLL_SECONDS)
                code = child.wait()
            except BaseException:
                if child.poll() is None:
                    child.kill()
                child.wait()
                raise
            elapsed = (time.perf_counter() - started) * 1000
            if code != 0:
                stderr.seek(0)
                raise RuntimeError(f"rel-diff failed: {stderr.read(300)!r}")
            stdout.seek(0)
            encoded_report = stdout.read()
            report_bytes = len(encoded_report)
            if report_bytes > MAX_REPORT_BYTES or not encoded_report.endswith(b"\n"):
                raise AssertionError("unexpected report size or missing final newline")
            report_digest = hashlib.sha256(encoded_report).hexdigest()
            report = json.loads(encoded_report)
            if (report["left_sha256"], report["right_sha256"]) != expected:
                raise AssertionError("diff report lost the source manifest identities")
            if report["schema_version"] != "0.1.0-experimental":
                raise AssertionError("unexpected report contract")
            actual_counts = (
                len(report["imports"]["added"]), len(report["exports"]["added"]),
                len(report["sections"]["added"]), len(report["sections"]["removed"]),
                len(report["sections"]["changed"]),
            )
            if actual_counts != expected_counts:
                raise AssertionError(
                    f"metadata delta counts {actual_counts} != {expected_counts}"
                )
            if len(report["imports"]["removed"]) != expected_counts[0]:
                raise AssertionError("unexpected removed import count")
            if len(report["exports"]["removed"]) != expected_counts[1]:
                raise AssertionError("unexpected removed export count")
    return {
        "wall_ms": round(elapsed, 4),
        "report_bytes": report_bytes,
        "report_sha256": report_digest,
        "sampled_peak_rss_bytes": sampled_rss,
        "last_sampled_cpu_ms": round(sampled_cpu, 4) if sampled_cpu is not None else None,
        "rss_observations": observations,
    }


def summarize(samples: list[dict]) -> dict:
    times = sorted(item["wall_ms"] for item in samples)
    rss = [item["sampled_peak_rss_bytes"] for item in samples]
    observed = [value for value in rss if value is not None]
    report_sizes = {item["report_bytes"] for item in samples}
    report_digests = {item["report_sha256"] for item in samples}
    if len(report_sizes) != 1 or len(report_digests) != 1:
        raise AssertionError("identical inputs produced different report bytes")
    return {
        "report_bytes": report_sizes.pop(),
        "report_sha256": report_digests.pop(),
        "median_wall_ms": round(statistics.median(times), 4),
        "p95_wall_ms": times[max(0, math.ceil(0.95 * len(times)) - 1)],
        "max_sampled_rss_bytes": max(observed) if observed else None,
        "observations": samples,
    }


def run(binary: Path, samples: int, warmup: int) -> dict:
    context, context_id = capture_context(binary)
    report = {
        "schema_version": "rel-diff-resource-observations-v1-experimental",
        "measurement_context": context,
        "measurement_context_sha256": context_id,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "samples": samples,
        "warmup": warmup,
        "method": "release CLI subprocess; 2ms nominal RSS/CPU sampling; stdout redirected; controlled manifests",
        "limitations": [
            "Synthetic imports, exports and sections are not a real PE layout or authorized compiler build corpus.",
            "Near-budget case increases profiling cost; run count is still small and not a performance guarantee.",
            "Polled RSS can miss transient process peaks; this is not a memory cap.",
            "Observed runner timings are not cross-platform or cross-run performance guarantees.",
        ],
        "scenarios": [],
    }
    with tempfile.TemporaryDirectory(prefix="rel-diff-profile-") as work:
        root = Path(work)
        cases = []
        for name, count in (("minimal", 1), ("imports-8000", 8000)):
            a = manifest("a", [f"KERNEL32.dll!A{index:05}" for index in range(count)])
            b = manifest("b", [f"KERNEL32.dll!B{index:05}" for index in range(count)])
            cases.append((name, count, 0, 1, a, b, (count, 0, 0, 0, 0)))
        mixed_count = 2048
        a, b = mixed_pair(mixed_count)
        cases.append((
            "mixed-metadata-2048", mixed_count, mixed_count, mixed_count,
            a, b, (mixed_count, mixed_count, mixed_count // 2,
                   mixed_count // 2, mixed_count // 2),
        ))
        # 8192 unique strings per side, chosen to yield >15 MiB and <=16 MiB
        # of serialized diff output. This is a RESOURCE measurement case,
        # not a realistic PE import table.
        near_count = 8192
        padding = "X" * 950
        near_a = manifest(
            "a",
            [f"KERNEL32.dll!A{index:05d}{padding}" for index in range(near_count)],
        )
        near_b = manifest(
            "b",
            [f"KERNEL32.dll!B{index:05d}{padding}" for index in range(near_count)],
        )
        cases.append((
            "near-report-budget-8192", near_count, 0, 1,
            near_a, near_b, (near_count, 0, 0, 0, 0),
        ))

        for name, imports, exports, sections, a, b, counts in cases:
            left = root / "left.json"
            right = root / "right.json"
            payload_left = json.dumps(a).encode("utf-8")
            payload_right = json.dumps(b).encode("utf-8")
            if max(len(payload_left), len(payload_right)) > 16 * 1024 * 1024:
                raise AssertionError("synthetic profile input exceeds the CLI's 16 MiB cap")
            left.write_bytes(payload_left)
            right.write_bytes(payload_right)
            expected = (a["binary_sha256"], b["binary_sha256"])
            values = []
            for i in range(warmup + samples):
                value = profile_once(binary, left, right, expected, counts)
                if i >= warmup:
                    values.append(value)
            summary = summarize(values)
            if name == "near-report-budget-8192" and not (
                MIN_NEAR_REPORT_BYTES < summary["report_bytes"] <= MAX_REPORT_BYTES
            ):
                raise AssertionError("near-budget case did not exercise 15–16 MiB output")
            report["scenarios"].append({
                "name": name,
                "import_count_each": imports,
                "export_count_each": exports,
                "section_count_each": sections,
                "expected_delta_counts": counts,
                "left_input_bytes": len(payload_left),
                "right_input_bytes": len(payload_right),
                "left_json_sha256": hashlib.sha256(payload_left).hexdigest(),
                "right_json_sha256": hashlib.sha256(payload_right).hexdigest(),
                **summary,
            })
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--warmup", type=int, default=1)
    args = parser.parse_args()
    if not 3 <= args.samples <= 100:
        parser.error("samples must be in [3, 100]")
    if not 0 <= args.warmup <= 20:
        parser.error("warmup must be in [0, 20]")
    result = run(args.binary.resolve(strict=True), args.samples, args.warmup)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"EX-02 profile: PASS ({args.samples} samples × {len(result['scenarios'])} cases)")


if __name__ == "__main__":
    main()
