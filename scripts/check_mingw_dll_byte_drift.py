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


def validate_source_date_epoch(value: str | None) -> int:
    """Require an explicit, nonzero 32-bit epoch for this controlled PE test."""
    if value is None or not value.isascii() or not value.isdecimal():
        raise ValueError("SOURCE_DATE_EPOCH must be ASCII decimal seconds")
    number = int(value)
    if number < 1 or number > 0xFFFFFFFF:
        raise ValueError("SOURCE_DATE_EPOCH is outside nonzero PE u32 seconds")
    return number


def read_mapped_fields(data: bytes) -> dict[str, dict]:
    """Resolve PE field offsets directly from pinned pefile; never execute DLL."""
    import pefile

    pe = pefile.PE(data=data, fast_load=False)
    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        )
        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            raise ValueError("controlled DLL export directory missing")
        fields = {
            "optional-checksum": (
                pe.OPTIONAL_HEADER, "CheckSum"
            ),
            "export-directory-timestamp": (
                pe.DIRECTORY_ENTRY_EXPORT.struct, "TimeDateStamp"
            ),
        }
        observed = {}
        for name, (structure, field) in fields.items():
            offset = int(structure.get_field_absolute_offset(field))
            value = int(getattr(structure, field))
            if not 0 <= offset <= len(data) - 4:
                raise ValueError(f"{name} is outside PE source bytes")
            if int.from_bytes(data[offset:offset + 4], "little") != value:
                raise ValueError(f"{name} PE field is inconsistent with source bytes")
            observed[name] = {"offset": offset, "size": 4, "value": value}
        return observed
    finally:
        pe.close()


def classified_byte(offset: int, regions: dict, fields: dict | None = None) -> str:
    for label, field in (fields or {}).items():
        if field["offset"] <= offset < field["offset"] + field["size"]:
            return label
    return category(offset, regions)


def describe_differences(
    left: bytes, right: bytes, regions: dict, fields: dict | None = None
) -> dict:
    """Preserve raw identity and classify every changed byte by actual PE fields."""
    spans = differing_ranges(left, right)
    categories: dict[str, int] = {}
    for start, end in spans:
        for offset in range(start, end):
            name = classified_byte(offset, regions, fields)
            categories[name] = categories.get(name, 0) + 1
    only_timestamp_fields = bool(spans) and set(categories).issubset({
        "coff-timestamp", "debug-directory-timestamp", "export-directory-timestamp",
    })
    all_known_fields = bool(spans) and set(categories).issubset({
        "coff-timestamp", "debug-directory-timestamp", "export-directory-timestamp",
        "optional-checksum",
    })
    return {
        "raw_byte_identical": not spans,
        "changed_byte_count": sum(end - start for start, end in spans),
        "changed_range_count": len(spans),
        "only_timestamp_field_bytes_changed": only_timestamp_fields,
        "all_changed_bytes_in_observed_pe_fields": all_known_fields,
        "changed_bytes_by_first_file_region": categories,
        "first_changed_ranges": [
            {"start": start, "end": end, "first_file_region": classified_byte(start, regions, fields)}
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
    a_mapped, b_mapped = read_mapped_fields(a), read_mapped_fields(b)
    if any(a_mapped[k]["offset"] != b_mapped[k]["offset"] for k in a_mapped):
        raise ValueError("observed PE field offsets differ between builds")
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
        "first_mapped_pe_fields": a_mapped,
        "second_mapped_pe_fields": b_mapped,
        "diff": describe_differences(a, b, a_fields, a_mapped),
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
            "Mapped checksum/export timestamp offsets come from independent pefile structures.",
            "Classifications are verified byte locations, not proven build root causes.",
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
    parser.add_argument("--fixed-epoch-experiment", action="store_true")
    args = parser.parse_args()
    epoch = None
    if args.fixed_epoch_experiment:
        try:
            epoch = validate_source_date_epoch(os.environ.get("SOURCE_DATE_EPOCH"))
        except ValueError as exc:
            parser.error(str(exc))
    report = check(args.first, args.second, args.source, args.versions, args.packages)
    if epoch is not None:
        observed = {
            "first_coff": report["first_pe_regions"]["timestamp"],
            "second_coff": report["second_pe_regions"]["timestamp"],
            "first_export": report["first_mapped_pe_fields"]["export-directory-timestamp"]["value"],
            "second_export": report["second_mapped_pe_fields"]["export-directory-timestamp"]["value"],
        }
        report["controlled_timestamp_experiment"] = {
            "source_date_epoch": epoch,
            "linker_option": "--insert-timestamp",
            "observed_timestamp_fields": observed,
            "all_observed_timestamps_match_epoch": all(
                value == epoch for value in observed.values()
            ),
            "raw_files_equal": report["diff"]["raw_byte_identical"],
            "scope": (
                "Two builds in one job with fixed SOURCE_DATE_EPOCH. "
                "This does not establish portability, loader behavior, or general reproducibility."
            ),
        }
    if args.output.exists():
        parser.error("will not overwrite an existing report")
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("MinGW-w64 controlled DLL repeat build: "
          f"raw_identical={report['diff']['raw_byte_identical']} "
          f"changed_bytes={report['diff']['changed_byte_count']} "
          f"regions={report['diff']['changed_bytes_by_first_file_region']}")


if __name__ == "__main__":
    main()
