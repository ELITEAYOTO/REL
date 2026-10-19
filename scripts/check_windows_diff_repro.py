#!/usr/bin/env python3
"""Compare two independently built copies of the controlled EX-02 Windows corpus.

This is a byte-level diagnostic, not a semantic equivalence test. The eight
generated PE files are never executed. No arbitrary file paths are published.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
from datetime import datetime, timezone
from pathlib import Path

COMPILERS = ("msvc", "clang")
VERSIONS = (1, 2, 3, 4)
CASE_NAMES = tuple(f"{compiler}-v{version}.exe" for compiler in COMPILERS for version in VERSIONS)
METADATA_FILES = ("msvc-version.txt", "clang-cl-version.txt", "linker-version.txt")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def differing_ranges(left: bytes, right: bytes) -> list[tuple[int, int]]:
    """Return half-open byte ranges where two files differ, including tail."""
    spans = []
    start = None
    for pos in range(max(len(left), len(right))):
        different = pos >= min(len(left), len(right)) or left[pos] != right[pos]
        if different and start is None:
            start = pos
        if not different and start is not None:
            spans.append((start, pos))
            start = None
    if start is not None:
        spans.append((start, max(len(left), len(right))))
    return spans


def record_regions(data: bytes) -> dict:
    """Inspect direct PE fields, never evaluate any executable code."""
    import pefile

    parsed = pefile.PE(data=data, fast_load=False)
    try:
        coff = parsed.FILE_HEADER
        optional = parsed.OPTIONAL_HEADER
        section_entries = []
        for section in parsed.sections:
            start = int(section.PointerToRawData)
            size = int(section.SizeOfRawData)
            end = start + size
            assert 0 <= start <= end <= len(data), "invalid section byte span"
            section_entries.append({
                "name": section.Name.rstrip(b"\0").decode("ascii", errors="replace"),
                "offset": start,
                "size": size,
                "sha256": sha(data[start:end]),
            })
        debug_entries = []
        debug_directory_timestamps = []
        parsed.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]]
        )
        for item in getattr(parsed, "DIRECTORY_ENTRY_DEBUG", []):
            start = int(item.struct.PointerToRawData)
            size = int(item.struct.SizeOfData)
            if size and start and start + size <= len(data):
                debug_entries.append({
                    "offset": start,
                    "size": size,
                    "sha256": sha(data[start:start + size]),
                })
            debug_directory_timestamps.append({
                "offset": int(item.struct.get_field_absolute_offset("TimeDateStamp")),
                "value": int(item.struct.TimeDateStamp),
            })
        return {
            "machine": int(coff.Machine),
            "timestamp": int(coff.TimeDateStamp),
            "coff_timestamp_offset": int(coff.get_field_absolute_offset("TimeDateStamp")),
            "debug_directory_timestamps": debug_directory_timestamps,
            "optional_checksum": int(optional.CheckSum),
            "entry_point_rva": int(optional.AddressOfEntryPoint),
            "size_of_image": int(optional.SizeOfImage),
            "sections": section_entries,
            "debug_blobs": debug_entries,
        }
    finally:
        parsed.close()


def category(pos: int, regions: dict) -> str:
    coff_offset = regions.get("coff_timestamp_offset")
    if coff_offset is not None and coff_offset <= pos < coff_offset + 4:
        return "coff-timestamp"
    for field in regions.get("debug_directory_timestamps", []):
        if field["offset"] <= pos < field["offset"] + 4:
            return "debug-directory-timestamp"
    for section in regions["sections"]:
        if section["offset"] <= pos < section["offset"] + section["size"]:
            return f"section:{section['name']}"
    for item in regions["debug_blobs"]:
        if item["offset"] <= pos < item["offset"] + item["size"]:
            return "debug-data"
    return "header-or-overlay"


def snapshot(source: Path, target: Path) -> None:
    assert source.is_dir(), source
    target.mkdir(parents=True, exist_ok=False)
    for name in (*CASE_NAMES, *METADATA_FILES):
        path = source / name
        assert path.is_file() and not path.is_symlink(), path
        shutil.copyfile(path, target / name)
    print(f"EX-02 captured {len(CASE_NAMES)} controlled PE outputs for same-run rebuild")


def compare(first: Path, second: Path, output: Path) -> None:
    if not first.is_dir() or not second.is_dir():
        raise ValueError("both corpus roots must exist")
    cases = []
    for name in CASE_NAMES:
        before_file, after_file = first / name, second / name
        if not before_file.is_file() or not after_file.is_file():
            raise FileNotFoundError(name)
        before = before_file.read_bytes()
        after = after_file.read_bytes()
        a = record_regions(before)
        b = record_regions(after)
        assert a["machine"] == 0x8664 and b["machine"] == 0x8664
        spans = differing_ranges(before, after)
        categories = {}
        for start, end in spans:
            for pos in range(start, end):
                label = category(pos, a)
                categories[label] = categories.get(label, 0) + 1
        timestamp_only = bool(spans) and set(categories) <= {
            "coff-timestamp", "debug-directory-timestamp"
        }
        cases.append({
            "case": name,
            "first_sha256": sha(before),
            "second_sha256": sha(after),
            "first_size": len(before),
            "second_size": len(after),
            "same_bytes": before == after,
            "all_changed_bytes_in_timestamp_fields": timestamp_only,
            "first_pe_fields": a,
            "second_pe_fields": b,
            "changed_byte_count": sum(end - start for start, end in spans),
            "changed_range_count": len(spans),
            "first_changed_ranges": [
                {"start": start, "end": end, "category": category(start, a)}
                for start, end in spans[:32]
            ],
            "changed_bytes_by_initial_region": categories,
        })
    toolchain_banners = {}
    for name in METADATA_FILES:
        left = (first / name).read_bytes()
        right = (second / name).read_bytes()
        toolchain_banners[name] = {"same_sha256": sha(left) == sha(right)}
    report = {
        "schema_version": "rel-ex02-same-run-raw-byte-diagnostic-v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "runner_platform": platform.platform(),
        "github_sha": os.getenv("GITHUB_SHA"),
        "case_count": len(cases),
        "raw_byte_identical_count": sum(item["same_bytes"] for item in cases),
        "toolchain_banners": toolchain_banners,
        "cases": cases,
        "interpretation_limits": [
            "Only two builds per PE within one CI job; cross-run differences remain separate.",
            "PE raw SHA and section bytes are evidence, never proof of behavior.",
            "Byte categories prioritize exact COFF/debug-directory timestamp offsets over section ranges.",
            "Categories reflect first-build field offsets; they cannot prove a root cause.",
            "The first 32 byte ranges are a diagnostic excerpt; counts cover the entire file.",
            "No raw PE data, debug paths or absolute runner filesystem paths are published.",
            "Compiler/environment root causes require controlled experiments, not field correlation.",
        ],
    }
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        f"EX-02 same-run byte diagnostic: {report['raw_byte_identical_count']}"
        f"/{len(cases)} reproducible SHA identities; evidence saved"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--capture", action="store_true")
    action.add_argument("--compare", action="store_true")
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.capture:
        if args.output:
            parser.error("--output is only valid for --compare")
        snapshot(args.corpus, args.snapshot)
    else:
        if args.output is None:
            parser.error("--compare requires --output")
        compare(args.snapshot, args.corpus, args.output)


if __name__ == "__main__":
    main()
