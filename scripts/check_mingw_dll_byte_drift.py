#!/usr/bin/env python3
"""Same-job GNU MinGW-w64 DLL byte-drift evidence; never executes a PE."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from scripts.check_windows_diff_repro import category, differing_ranges, record_regions


MAX_PROBE_BYTES = 4 * 1024 * 1024


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def describe_differences(left: bytes, right: bytes, regions: dict) -> dict:
    """Preserve raw-file identity and classify ALL differing bytes by first file."""
    spans = differing_ranges(left, right)
    categories: dict[str, int] = {}
    for start, end in spans:
        for offset in range(start, end):
            name = category(offset, regions)
            categories[name] = categories.get(name, 0) + 1
    only_timestamp_fields = bool(spans) and set(categories).issubset({
        "coff-timestamp", "debug-directory-timestamp",
    })
    return {
        "raw_byte_identical": not spans,
        "changed_byte_count": sum(end - start for start, end in spans),
        "changed_range_count": len(spans),
        "only_timestamp_field_bytes_changed": only_timestamp_fields,
        "changed_bytes_by_first_file_region": categories,
        "first_changed_ranges": [
            {"start": start, "end": end, "first_file_region": category(start, regions)}
            for start, end in spans[:32]
        ],
    }


def check(first: Path, second: Path, source: Path, versions: Path, packages: Path) -> dict:
    for path in (first, second, source, versions, packages):
        if not path.is_file() or path.is_symlink():
            raise ValueError("expected existing regular evidence file")
    a, b = first.read_bytes(), second.read_bytes()
    if not a or not b or max(len(a), len(b)) > MAX_PROBE_BYTES:
        raise ValueError("probe size outside controlled bounds")
    a_fields, b_fields = record_regions(a), record_regions(b)
    if a_fields["machine"] != 0x8664 or b_fields["machine"] != 0x8664:
        raise ValueError("expected AMD64 PE observations")
    banners = versions.read_text(encoding="utf-8").splitlines()
    if len(banners) != 2 or not all(banners):
        raise ValueError("expected compiler and linker version lines")
    package_lines = packages.read_text(encoding="utf-8").splitlines()
    if len(package_lines) != 2 or not all(package_lines):
        raise ValueError("expected two GNU MinGW-w64 package version lines")
    return {
        "format": "rel-ex02-mingw-dll-same-job-raw-byte-diagnostic-v1",
        "source_sha256": sha256(source.read_bytes()),
        "first_binary_sha256": sha256(a),
        "second_binary_sha256": sha256(b),
        "first_size_bytes": len(a),
        "second_size_bytes": len(b),
        "first_pe_regions": a_fields,
        "second_pe_regions": b_fields,
        "diff": describe_differences(a, b, a_fields),
        "compiler_version": banners[0][:256],
        "linker_version": banners[1][:256],
        "toolchain_packages": package_lines,
        "compiler_flags": ["-std=c11", "-O2", "-s", "-shared", "-Wall",
                           "-Wextra", "-Werror", "-Wno-unknown-pragmas", "-lkernel32"],
        "runner_image_os": os.environ.get("ImageOS"),
        "runner_image_version": os.environ.get("ImageVersion"),
        "runner_commit": os.environ.get("GITHUB_SHA"),
        "limits": [
            "Two rebuilds of one controlled DLL in the same Ubuntu job only.",
            "Neither executable code nor the DLL was executed or loaded.",
            "Classifications are byte locations from the first PE, not root causes.",
            "Raw hashes are never normalized and cannot establish behavior.",
            "Exact byte differences may reflect toolchain, time, environment or input state.",
            "Package banners alone do not enumerate every transitive linker input.",
            "No cross-run reproducibility or hostile-input safety conclusion follows.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("first", "second", "source", "versions", "packages", "output"):
        parser.add_argument(f"--{flag}", type=Path, required=True)
    args = parser.parse_args()
    report = check(args.first, args.second, args.source, args.versions, args.packages)
    if args.output.exists():
        parser.error("will not overwrite an existing report")
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("MinGW-w64 controlled DLL repeat build: "
          f"raw_identical={report['diff']['raw_byte_identical']} "
          f"changed_bytes={report['diff']['changed_byte_count']} "
          f"regions={report['diff']['changed_bytes_by_first_file_region']}")


if __name__ == "__main__":
    main()
