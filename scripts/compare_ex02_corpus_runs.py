#!/usr/bin/env python3
"""Compare independent EX-02 compiler-corpus reports, preserving raw SHA evidence.

Designed for locally downloaded GitHub Actions artifact ZIPs or extracted JSON.
No PE is executed, reconstructed, overwritten, or normalized.
"""
from __future__ import annotations

import argparse
import itertools
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
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
EXPECTED_PAIRS = {
    (f"{compiler}-v{left}", f"{compiler}-v{right}")
    for compiler in ("msvc", "clang")
    for left, right in itertools.combinations(range(1, 5), 2)
} | {(f"msvc-v{v}", f"clang-v{v}") for v in range(1, 5)}


def check_provenance(report: dict, mode: str) -> None:
    """Refuse absent or malformed provenance, not just conflicting values."""
    if mode not in REPORT_FILES or report.get("link_mode") != mode:
        raise ValueError("missing or incompatible provenance: linker mode")
    for key in ("source_sha256", "build_script_sha256"):
        value = report.get(key)
        if not isinstance(value, str) or HASH.fullmatch(value) is None:
            raise ValueError(f"missing or invalid provenance: {key}")
    for key in ("linker_banner", "build_script", "link_flags"):
        value = report.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"missing or invalid provenance: {key}")
    if report["build_script"] != "scripts/build_windows_diff_pairs.cmd":
        raise ValueError("unrecognized build script")
    expected_flags = (
        "/INCREMENTAL:NO /Brepro" if mode == "brepro" else "/INCREMENTAL:NO"
    )
    if report["link_flags"] != expected_flags:
        raise ValueError("linker mode and flags disagree")
    compilers = report.get("compilers")
    if not isinstance(compilers, dict) or set(compilers) != {"msvc", "clang"}:
        raise ValueError("missing or invalid provenance: compilers")
    if not all(isinstance(x, str) and x.strip() for x in compilers.values()):
        raise ValueError("missing compiler version")
    environment = report.get("build_environment")
    if not isinstance(environment, dict):
        raise ValueError("missing build environment provenance")
    for key in ("windows_sdk_version", "vc_tools_version", "image_os", "image_version"):
        value = environment.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"missing or invalid provenance: {key}")



def unique_json_keys(pairs: list[tuple[str, object]]) -> dict:
    """Reject ambiguous evidence documents with duplicate JSON member names."""
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def check_report_structure(report: dict) -> None:
    """Reject incomplete/mislabeled evidence before comparing build identities."""
    cases = report.get("cases")
    if type(report.get("case_count")) is not int or report["case_count"] != 8:
        raise ValueError("invalid case count")
    if not isinstance(cases, list) or len(cases) != 8:
        raise ValueError("expected exactly eight corpus build cases")
    ids = [row.get("id") for row in cases if isinstance(row, dict)]
    if (
        len(ids) != 8
        or any(not isinstance(key, str) for key in ids)
        or set(ids) != EXPECTED_IDS
        or len(set(ids)) != 8
    ):
        raise ValueError("missing or duplicate variant IDs")
    for row in cases:
        case_id = row["id"]
        compiler, variant_text = case_id.split("-v", 1)
        expected_version = int(variant_text)
        if row.get("compiler") != compiler or type(row.get("variant")) is not int or row["variant"] != expected_version:
            raise ValueError(f"{case_id}: inconsistent compiler/variant identity")
        if row.get("source_sha256") != report["source_sha256"]:
            raise ValueError(f"{case_id}: source provenance mismatch")
        if not isinstance(row.get("sha256"), str) or HASH.fullmatch(row["sha256"]) is None:
            raise ValueError(f"{case_id}: malformed SHA-256")
        for key in ("size_bytes", "import_count", "export_count"):
            value = row.get(key)
            minimum = 1 if key == "size_bytes" else 0
            if type(value) is not int or value < minimum:
                raise ValueError(f"{case_id}: invalid {key}")

    pairs = report.get("pairs")
    if type(report.get("pair_count")) is not int or report["pair_count"] != len(EXPECTED_PAIRS):
        raise ValueError("invalid pair count")
    if not isinstance(pairs, list) or len(pairs) != len(EXPECTED_PAIRS):
        raise ValueError("incomplete pair observations")
    seen = set()
    for pair in pairs:
        if not isinstance(pair, dict):
            raise ValueError("malformed pair observation")
        identity = (pair.get("left"), pair.get("right"))
        if any(not isinstance(key, str) for key in identity):
            raise ValueError("malformed A/B pair identity")
        if identity not in EXPECTED_PAIRS or identity in seen:
            raise ValueError("missing, duplicated or unexpected A/B pair")
        seen.add(identity)
        if pair.get("oracle") != "pefile-independent-PE-structures":
            raise ValueError(f"{identity}: invalid independent oracle identifier")
        if pair.get("section_status") not in ("changed", "unchanged", "ambiguous"):
            raise ValueError(f"{identity}: invalid section status")
        for key in ("import_added", "import_removed", "export_added", "export_removed"):
            items = pair.get(key)
            if not isinstance(items, list) or any(not isinstance(x, str) for x in items):
                raise ValueError(f"{identity}: malformed delta: {key}")
            if items != sorted(set(items)):
                raise ValueError(f"{identity}: noncanonical delta: {key}")
        if set(pair["import_added"]) & set(pair["import_removed"]):
            raise ValueError(f"{identity}: import both added and removed")
        if set(pair["export_added"]) & set(pair["export_removed"]):
            raise ValueError(f"{identity}: export both added and removed")
    if seen != EXPECTED_PAIRS:
        raise ValueError("incomplete pair coverage")


def load_report(path: Path, mode: str) -> dict:
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as archive:
            expected = REPORT_FILES[mode]
            matches = [
                entry for entry in archive.infolist()
                if not entry.is_dir() and Path(entry.filename).name == expected
            ]
            if len(matches) != 1:
                raise ValueError(f"{path.name}: expected exactly one {expected}")
            if matches[0].file_size > MAX_EVIDENCE_BYTES:
                raise ValueError("evidence report exceeds 2 MiB")
            with archive.open(matches[0]) as member:
                payload = member.read(MAX_EVIDENCE_BYTES + 1)
    else:
        if path.stat().st_size > MAX_EVIDENCE_BYTES:
            raise ValueError("evidence report exceeds 2 MiB")
        with path.open("rb") as member:
            payload = member.read(MAX_EVIDENCE_BYTES + 1)
    if len(payload) > MAX_EVIDENCE_BYTES:
        raise ValueError("evidence report exceeds 2 MiB")
    report = json.loads(payload, object_pairs_hook=unique_json_keys)
    if not isinstance(report, dict):
        raise ValueError("evidence report must be a JSON object")
    if report.get("schema_version") != "rel-ex02-compiler-pair-evidence-v1":
        raise ValueError("incompatible corpus evidence version")
    if report.get("link_mode") != mode:
        raise ValueError("wrong linker mode for comparison")
    check_provenance(report, mode)
    check_report_structure(report)
    return report


def compare_reports(first: dict, second: dict, *, require_identical: bool) -> dict:
    if require_identical and first.get("link_mode") != "brepro":
        raise ValueError("strict raw reproducibility requires /Brepro mode")
    check_provenance(first, first.get("link_mode"))
    check_provenance(second, second.get("link_mode"))
    check_report_structure(first)
    check_report_structure(second)
    keys = (
        "source_sha256",
        "compilers",
        "linker_banner",
        "build_environment",
        "build_script",
        "build_script_sha256",
        "link_mode",
        "link_flags",
    )
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
