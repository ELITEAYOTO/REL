#!/usr/bin/env python3
"""Profile CLI rejection of controlled malformed PE inputs, never execute PE."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import psutil
from _internal.corpus_cases import ROOT, load_verified_seeds

WALL_SECONDS = 20
POLL_SECONDS = 0.002
MAX_SPOOL_BYTES = 64 * 1024
F001_SHA = "f65f21c07542483584cf156f1171ef6d02af1ce7168c573da79f8b81b96cc59e"
REDUCED_SHA = "687718a1765dd0ef0322879c4e5f89bf3ae6920cbf6b7c464ff4571ef17fcbed"


@dataclass(frozen=True)
class NegativeCase:
    name: str
    path: Path
    source: str
    source_sha256: str
    change: str
    expected_error: str


def save(
    directory: Path, name: str, payload: bytes, source: str,
    source_sha: str, change: str, expected: str,
) -> NegativeCase:
    path = directory / f"{name}.exe"
    with path.open("xb") as file:
        file.write(payload)
    return NegativeCase(name, path, source, source_sha, change, expected)


def verified_export_header_offset(seed: bytes, coff: int, optional: int) -> int:
    """Map the export header RVA through a raw section of a checked fixture."""
    optional_size = int.from_bytes(seed[coff + 16:coff + 18], "little")
    table = optional + optional_size
    count = int.from_bytes(seed[coff + 2:coff + 4], "little")
    directory = optional + (96 if int.from_bytes(seed[optional:optional + 2], "little") == 0x10b else 112)
    rva = int.from_bytes(seed[directory:directory + 4], "little")
    for index in range(count):
        section = table + 40 * index
        va = int.from_bytes(seed[section + 12:section + 16], "little")
        size = int.from_bytes(seed[section + 16:section + 20], "little")
        start = int.from_bytes(seed[section + 20:section + 24], "little")
        if va <= rva and rva + 40 <= va + size:
            offset = start + rva - va
            if offset + 40 > len(seed):
                break
            return offset
    raise ValueError("verified source export header is not raw-section mapped")


def cases_from_verified_sources(fixtures: Path, directory: Path) -> list[NegativeCase]:
    """Never depend on unverified third-party binaries or execute PE samples."""
    cases: list[NegativeCase] = []
    for source, seed, source_sha in load_verified_seeds(fixtures):
        arch = source.split("-")[0]
        nt = int.from_bytes(seed[0x3c:0x40], "little")
        coff = nt + 4
        optional = coff + 20
        optional_size = int.from_bytes(seed[coff + 16:coff + 18], "little")
        section = optional + optional_size
        directory_start = optional + (96 if arch == "pe32" else 112)
        export_header = verified_export_header_offset(seed, coff, optional)
        variations = (
            ("nt-offset-limit", 0x3c, (1048577).to_bytes(4, "little"),
             "PE header offset exceeds alpha limit"),
            ("section-count-limit", coff + 2, (97).to_bytes(2, "little"),
             "section count outside alpha policy"),
            ("section-raw-oob", section + 20, (0xffffffff).to_bytes(4, "little"),
             "section raw data extends beyond input"),
            ("import-size-limit", directory_start + 12, (1048577).to_bytes(4, "little"),
             "import directory declaration exceeds alpha size limit"),
            ("export-size-limit", directory_start + 4, (1048577).to_bytes(4, "little"),
             "export directory declaration exceeds alpha size limit"),
            ("export-rva-unmapped", directory_start, (0xfffffff0).to_bytes(4, "little"),
             "export directory cannot be mapped to raw section data"),
            ("export-rva-zero", directory_start, (0).to_bytes(4, "little"),
             "invalid export directory RVA or size"),
            ("export-function-count-limit", export_header + 20, (65537).to_bytes(4, "little"),
             "export count exceeds alpha symbol limit"),
            ("export-name-count-limit", export_header + 24, (65537).to_bytes(4, "little"),
             "export count exceeds alpha symbol limit"),
        )
        for label, offset, replacement, diagnostic in variations:
            data = bytearray(seed)
            data[offset:offset + len(replacement)] = replacement
            cases.append(save(
                directory, f"{arch}-{label}", bytes(data), source, source_sha,
                f"offset={offset};hex={replacement.hex()}", diagnostic,
            ))
        if arch == "pe64":
            data = bytearray(seed)
            data[coff + 2:coff + 4] = (97).to_bytes(2, "little")
            data.extend(bytes(8 * 1024 * 1024 - len(data)))
            cases.append(save(
                directory, "pe64-8m-overlay-bad-count", bytes(data),
                source, source_sha, "8 MiB zero overlay; section count=97",
                "section count outside alpha policy",
            ))
    for name, expected in (
        ("goblin-0.9.3-tls-oob.bin", F001_SHA),
        ("goblin-0.9.3-tls-oob-minimized.bin", REDUCED_SHA),
    ):
        data = (fixtures / "regressions" / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f"{name}: historical F001 hash mismatch")
        cases.append(save(
            directory, name[:-4], data, f"regressions/{name}", expected,
            "unchanged regression source bytes", "invalid PE:",
        ))
    return cases


def observe_failure(binary: Path, case: NegativeCase) -> dict:
    """Sample direct-child resources, enforce wall/spool limits, verify no JSON."""
    start = time.perf_counter()
    peak_rss: int | None = None
    last_cpu_ms: float | None = None
    polls = 0
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        child = psutil.Popen(
            [str(binary), "analyze", str(case.path)],
            stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
        )
        try:
            while child.poll() is None:
                if time.perf_counter() - start > WALL_SECONDS:
                    raise TimeoutError(f"{case.name}: exceeded {WALL_SECONDS}s wall timeout")
                if any(os.fstat(f.fileno()).st_size > MAX_SPOOL_BYTES
                       for f in (stdout, stderr)):
                    raise RuntimeError(f"{case.name}: diagnostic spool exceeded limit")
                try:
                    rss = child.memory_info().rss
                    times = child.cpu_times()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                else:
                    peak_rss = max(peak_rss or 0, rss)
                    last_cpu_ms = (times.user + times.system) * 1000
                    polls += 1
                time.sleep(POLL_SECONDS)
            status = child.wait()
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
        if any(os.fstat(f.fileno()).st_size > MAX_SPOOL_BYTES
               for f in (stdout, stderr)):
            raise RuntimeError(f"{case.name}: diagnostic spool exceeded limit")
        stdout.seek(0)
        stderr.seek(0)
        out = stdout.read(MAX_SPOOL_BYTES + 1)
        diagnostic = stderr.read(MAX_SPOOL_BYTES + 1).decode("utf-8", "replace")
    if status == 0 or out or case.expected_error not in diagnostic:
        raise AssertionError(
            f"{case.name}: wanted rejection {case.expected_error!r}; "
            f"status={status}, stdout_bytes={len(out)}, stderr={diagnostic[:200]!r}"
        )
    return {
        "wall_ms": round((time.perf_counter() - start) * 1000, 4),
        "sampled_peak_rss_bytes": peak_rss,
        "last_sampled_cpu_ms": round(last_cpu_ms, 4) if last_cpu_ms is not None else None,
        "resource_samples": polls,
        "exit_status": status,
    }


def run(binary: Path, samples: int = 3) -> dict:
    if not 2 <= samples <= 10:
        raise ValueError("samples must be in [2, 10]")
    binary = binary.resolve(strict=True)
    observations = []
    with tempfile.TemporaryDirectory(prefix="rel-malformed-pe-") as folder:
        for case in cases_from_verified_sources(ROOT / "fixtures", Path(folder)):
            readings = [observe_failure(binary, case) for _ in range(samples)]
            rss = [v["sampled_peak_rss_bytes"] for v in readings
                   if v["sampled_peak_rss_bytes"] is not None]
            observations.append({
                "case_id": case.name,
                "source_fixture": case.source,
                "source_sha256": case.source_sha256,
                "mutation": case.change,
                "sha256": hashlib.sha256(case.path.read_bytes()).hexdigest(),
                "size_bytes": case.path.stat().st_size,
                "expected_error": case.expected_error,
                "median_wall_ms": round(statistics.median(
                    v["wall_ms"] for v in readings), 4),
                "max_sampled_rss_bytes": max(rss) if rss else None,
                "measurements": readings,
            })
    return {
        "schema": "rel-malformed-pe-resources-v1",
        "environment": {
            "os": platform.platform(),
            "machine": platform.machine(),
            "psutil_version": psutil.__version__,
            "git_sha": os.getenv("GITHUB_SHA"),
            "analyzer_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "samples": samples,
            "poll_interval_ms_nominal": POLL_SECONDS * 1000,
        },
        "bounds": {
            "per_run_wall_timeout_seconds": WALL_SECONDS,
            "max_spool_bytes": MAX_SPOOL_BYTES,
            "rss_and_cpu_are_sampled_not_hard_capped": True,
            "short_lived_processes_may_have_null_rss_or_cpu": True,
        },
        "cases": observations,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--samples", type=int, default=3)
    args = parser.parse_args()
    if not 2 <= args.samples <= 10:
        parser.error("--samples must be between 2 and 10")
    report = run(args.binary, args.samples)
    with args.output.open("x", encoding="utf-8") as file:
        json.dump(report, file, indent=2, allow_nan=False)
        file.write("\n")


if __name__ == "__main__":
    main()
