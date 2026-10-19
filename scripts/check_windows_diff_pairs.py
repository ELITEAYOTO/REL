#!/usr/bin/env python3
"""Independent Windows A/B oracle for eight source-defined compiler-built PEs.

Only rel-inspect and rel-diff executables are launched. The corpus PEs are
*always read as static bytes*, never executed or loaded as programs.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import platform
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pefile
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "fixtures/probes/diff_version_probe.c"
COMPILERS = ("msvc", "clang")
VERSIONS = (1, 2, 3, 4)
EXPECTED_API = {
    1: ("GetTickCount", {"rel_diff_transform"}),
    2: ("GetTickCount64", {"rel_diff_transform", "rel_diff_new_api"}),
    3: ("GetComputerNameW", {"rel_diff_transform", "rel_diff_other_api"}),
    4: (
        "GetTickCount64",
        {"rel_diff_transform", "rel_diff_new_api", "rel_diff_other_api"},
    ),
}


def read_pe(path: Path, version: int) -> dict:
    raw = path.read_bytes()
    parsed = pefile.PE(data=raw, fast_load=False)
    try:
        parsed.parse_data_directories()
        assert parsed.FILE_HEADER.Machine == 0x8664, path
        assert parsed.OPTIONAL_HEADER.Magic == 0x20B, path
        imports = set()
        for entry in getattr(parsed, "DIRECTORY_ENTRY_IMPORT", []):
            dll = entry.dll.decode("ascii")
            for symbol in entry.imports:
                assert symbol.name is not None, "ordinal import not modeled by v1"
                imports.add(f"{dll}!{symbol.name.decode('ascii')}")
        exports = {
            symbol.name.decode("ascii")
            for symbol in getattr(
                getattr(parsed, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []
            )
            if symbol.name is not None
        }
        sections = [
            {
                "name": section.Name.rstrip(b"\x00").decode("ascii"),
                "offset": int(section.PointerToRawData),
                "size": int(section.SizeOfRawData),
                "virtual_address": int(section.VirtualAddress),
            }
            for section in parsed.sections
        ]
        required_api, expected_exports = EXPECTED_API[version]
        assert any(x.endswith(f"!{required_api}") for x in imports), (
            path, required_api, imports
        )
        tracked_apis = {"GetTickCount", "GetTickCount64", "GetComputerNameW"}
        for unexpected in tracked_apis - {required_api}:
            assert not any(x.endswith(f"!{unexpected}") for x in imports), (
                path, "unexpected tracked API", unexpected, imports
            )
        assert exports == expected_exports, (path, exports, expected_exports)
        assert sections, f"{path}: no PE sections"
        return {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
            "arch": "x86_64",
            "imports": sorted(imports),
            "exports": sorted(exports),
            "sections": sections,
        }
    finally:
        parsed.close()


def inspect(binary: Path, path: Path) -> dict:
    result = subprocess.run(
        [str(binary), "analyze", str(path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, (path, result.stderr[:800])
    return json.loads(result.stdout)


def sections_expected(left: list, right: list) -> dict:
    a_names = [s["name"] for s in left]
    b_names = [s["name"] for s in right]
    if len(set(a_names)) != len(a_names) or len(set(b_names)) != len(b_names):
        return {"status": "ambiguous", "added": [], "removed": [], "changed": []}
    a = {s["name"]: s for s in left}
    b = {s["name"]: s for s in right}
    added = sorted(b.keys() - a.keys())
    removed = sorted(a.keys() - b.keys())
    changed = sorted(k for k in a.keys() & b.keys() if a[k] != b[k])
    return {
        "status": "changed" if (added or removed or changed) else "unchanged",
        "added": added,
        "removed": removed,
        "changed": changed,
    }


def case_only(left: list[str], right: list[str]) -> bool:
    if set(left) == set(right):
        return False

    def normalized(items: list[str]) -> set[str]:
        answer = set()
        for item in items:
            dll, separator, symbol = item.partition("!")
            answer.add(f"{dll.lower()}!{symbol}" if separator and dll and symbol else item)
        return answer

    a, b = normalized(left), normalized(right)
    return len(a) == len(left) and len(b) == len(right) and a == b


def diff_expected(left: dict, right: dict) -> dict:
    result = {
        "left_sha256": left["sha256"],
        "right_sha256": right["sha256"],
        "size_changed": left["size_bytes"] != right["size_bytes"],
        "arch_changed": left["arch"] != right["arch"],
        "import_dll_case_only": case_only(left["imports"], right["imports"]),
        "sections": sections_expected(left["sections"], right["sections"]),
    }
    for kind in ("imports", "exports"):
        a, b = set(left[kind]), set(right[kind])
        result[kind] = {"added": sorted(b - a), "removed": sorted(a - b)}
    return result


def compare(binary: Path, a: Path, b: Path, validator) -> dict:
    result = subprocess.run(
        [str(binary), str(a), str(b)],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, (a, b, result.stderr[:800])
    payload = json.loads(result.stdout)
    validator.validate(payload)
    return payload


def check_diff(actual: dict, expected: dict, label: str) -> None:
    for key, truth in expected.items():
        if key == "sections":
            observed = {k: actual[key][k] for k in truth}
            assert observed == truth, (label, key, observed, truth)
        else:
            assert actual[key] == truth, (label, key, actual[key], truth)


def verify(inspector: Path, diff: Path, corpus: Path, output: Path, link_mode: str) -> None:
    v1 = json.loads((ROOT / "contracts/schemas/binary-manifest.schema.json").read_text())
    experimental = json.loads(
        (ROOT / "contracts/experimental/manifest-diff.schema.json").read_text()
    )
    Draft202012Validator.check_schema(v1)
    Draft202012Validator.check_schema(experimental)
    valid_manifest = Draft202012Validator(v1)
    valid_diff = Draft202012Validator(experimental)
    source_sha = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    provenance = {}
    cases = []
    pairs = []

    with tempfile.TemporaryDirectory(prefix="rel-diff-compiled-") as directory:
        temp = Path(directory)
        for compiler in COMPILERS:
            banner = (corpus / f"{'msvc' if compiler == 'msvc' else 'clang-cl'}-version.txt")
            assert banner.is_file(), f"missing compiler provenance: {banner}"
            provenance[compiler] = banner.read_text(encoding="utf-8", errors="replace").splitlines()[0][:240]
            assert provenance[compiler], f"empty version: {banner}"
            for version in VERSIONS:
                case_id = f"{compiler}-v{version}"
                pe_path = corpus / f"{case_id}.exe"
                assert pe_path.is_file(), pe_path
                reference = read_pe(pe_path, version)
                produced = inspect(inspector, pe_path)
                valid_manifest.validate(produced)
                for key in ("binary_sha256", "size_bytes", "arch", "imports", "exports", "sections"):
                    ground_key = "sha256" if key == "binary_sha256" else key
                    assert produced[key] == reference[ground_key], (
                        case_id, key, produced[key], reference[ground_key]
                    )
                assert produced["warnings"] == [], (case_id, produced["warnings"])
                manifest_path = temp / f"{case_id}.json"
                manifest_path.write_text(json.dumps(produced), encoding="utf-8")
                cases.append({
                    "id": case_id,
                    "compiler": compiler,
                    "variant": version,
                    "source_sha256": source_sha,
                    "sha256": reference["sha256"],
                    "size_bytes": reference["size_bytes"],
                    "import_count": len(reference["imports"]),
                    "export_count": len(reference["exports"]),
                })
                provenance[case_id] = reference

        pairs_to_check = []
        for compiler in COMPILERS:
            pairs_to_check += [
                (f"{compiler}-v{v1}", f"{compiler}-v{v2}")
                for v1, v2 in itertools.combinations(VERSIONS, 2)
            ]
        pairs_to_check += [(f"msvc-v{v}", f"clang-v{v}") for v in VERSIONS]
        assert len(pairs_to_check) == 16
        for left_id, right_id in pairs_to_check:
            left = provenance[left_id]
            right = provenance[right_id]
            expected = diff_expected(left, right)
            forward = compare(diff, temp / f"{left_id}.json", temp / f"{right_id}.json", valid_diff)
            check_diff(forward, expected, f"{left_id} -> {right_id}")
            backward = compare(diff, temp / f"{right_id}.json", temp / f"{left_id}.json", valid_diff)
            check_diff(backward, diff_expected(right, left), f"{right_id} -> {left_id}")
            pairs.append({
                "left": left_id,
                "right": right_id,
                "oracle": "pefile-independent-PE-structures",
                "import_added": expected["imports"]["added"],
                "import_removed": expected["imports"]["removed"],
                "export_added": expected["exports"]["added"],
                "export_removed": expected["exports"]["removed"],
                "section_status": expected["sections"]["status"],
            })
        for case in cases:
            case_id = case["id"]
            same = compare(diff, temp / f"{case_id}.json", temp / f"{case_id}.json", valid_diff)
            check_diff(same, diff_expected(provenance[case_id], provenance[case_id]), case_id)

    report = {
        "schema_version": "rel-ex02-compiler-pair-evidence-v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "runner_platform": platform.platform(),
        "github_sha": os.environ.get("GITHUB_SHA"),
        "source": "fixtures/probes/diff_version_probe.c",
        "source_sha256": source_sha,
        "compilers": {name: provenance[name] for name in COMPILERS},
        "build_script": "scripts/build_windows_diff_pairs.cmd",
        "link_mode": link_mode,
        "link_flags": "/INCREMENTAL:NO /Brepro" if link_mode == "brepro" else "/INCREMENTAL:NO",
        "case_count": len(cases),
        "pair_count": len(pairs),
        "cases": cases,
        "pairs": pairs,
        "limitations": [
            "Eight compiler-built executables arise from four variants of one small source file.",
            "Sixteen pairs are selected from those eight files; these are not sixteen independent projects.",
            "Compiled PEs were parsed statically with pefile and rel-inspect; never executed.",
            "The oracle checks observed PE metadata, not runtime behavior, function identity or security.",
            "Build output may vary with runner toolchain; artifact hashes preserve per-run identity.",
            "This controlled compiler corpus is NOT a representative 10-20 licensed real-world build-pair corpus.",
        ],
    }
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"EX-02 compiler-pair oracle: PASS ({len(cases)} builds, {len(pairs)} A/B pairs)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inspector", required=True, type=Path)
    parser.add_argument("--diff", required=True, type=Path)
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--link-mode", choices=("standard", "brepro"), default="standard")
    args = parser.parse_args()
    verify(
        args.inspector.resolve(strict=True),
        args.diff.resolve(strict=True),
        args.corpus.resolve(strict=True),
        args.output,
        args.link_mode,
    )
