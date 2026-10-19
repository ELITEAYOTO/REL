#!/usr/bin/env python3
"""Compare independent EX-02 compiler-corpus reports, preserving raw SHA evidence.

Designed for locally downloaded GitHub Actions artifact ZIPs or extracted JSON.
No PE is executed, reconstructed, overwritten, or normalized.
"""
from __future__ import annotations

import argparse
import json
import re
import zipfile
from pathlib import Path

EXPECTED_IDS = {f"{compiler}-v{variant}" for compiler in ("msvc", "clang") for variant in range(1, 5)}
REPORT_FILES = {
    "standard": "rel-ex02-compiler-pairs.json",
    "brepro": "rel-ex02-brepro-pairs.json",
}
HASH = re.compile(r"[0-9a-f]{64}\Z")


def load_report(path: Path, mode: str) -> dict:
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as archive:
            expected = REPORT_FILES[mode]
            matches = [name for name in archive.namelist() if Path(name).name == expected]
            if len(matches) != 1:
                raise ValueError(f"{path.name}: expected exactly one {expected}")
            report = json.loads(archive.read(matches[0]))
    else:
        report = json.loads(path.read_text(encoding="utf-8"))
    if report.get("schema_version") != "rel-ex02-compiler-pair-evidence-v1":
        raise ValueError("incompatible corpus evidence version")
    if report.get("link_mode") != mode:
        raise ValueError("wrong linker mode for comparison")
    cases = report.get("cases")
    if not isinstance(cases, list) or len(cases) != len(EXPECTED_IDS):
        raise ValueError("expected exactly eight corpus build cases")
    ids = [row.get("id") for row in cases]
    if set(ids) != EXPECTED_IDS or len(set(ids)) != len(ids):
        raise ValueError("missing or duplicate variant IDs")
    for row in cases:
        if not isinstance(row.get("sha256"), str) or HASH.fullmatch(row["sha256"]) is None:
            raise ValueError(f"{row.get('id')}: malformed SHA-256")
        if not isinstance(row.get("size_bytes"), int) or row["size_bytes"] <= 0:
            raise ValueError(f"{row['id']}: invalid source file size")
    return report


def compare_reports(first: dict, second: dict, *, require_identical: bool) -> dict:
    keys = ("source_sha256", "compilers", "build_script", "link_mode", "link_flags")
    for key in keys:
        if first.get(key) != second.get(key):
            raise ValueError(f"cannot compare different build provenance: {key}")
    a = {item["id"]: item for item in first["cases"]}
    b = {item["id"]: item for item in second["cases"]}
    same = sorted(key for key in EXPECTED_IDS if (a[key]["sha256"], a[key]["size_bytes"]) == (b[key]["sha256"], b[key]["size_bytes"]))
    changed = sorted(EXPECTED_IDS - set(same))
    summary = {
        "link_mode": first["link_mode"],
        "identical_raw_build_count": len(same),
        "case_count": len(EXPECTED_IDS),
        "identical_cases": same,
        "different_cases": changed,
        "first_run_sha": first.get("github_sha"),
        "second_run_sha": second.get("github_sha"),
        "limitations": "Same source/compiler banners do not guarantee identical SDK/linker/runner environment.",
    }
    if require_identical and changed:
        raise AssertionError(f"raw PE reproducibility regression in {changed}")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--first", type=Path, required=True)
    parser.add_argument("--second", type=Path, required=True)
    parser.add_argument("--mode", choices=tuple(REPORT_FILES), required=True)
    parser.add_argument("--require-identical", action="store_true")
    args = parser.parse_args()
    if args.require_identical and args.mode != "brepro":
        parser.error("only /Brepro has an explicit byte-identical acceptance gate")
    a = load_report(args.first, args.mode)
    b = load_report(args.second, args.mode)
    summary = compare_reports(a, b, require_identical=args.require_identical)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
