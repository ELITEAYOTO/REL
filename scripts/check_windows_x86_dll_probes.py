#!/usr/bin/env python3
"""Independent static pefile oracle for two locally compiled Windows x86 DLLs.

The sample DLLs are NEVER executed or loaded; redistribution is NOT cleared.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

import pefile

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_EXPORT = "rel_dll_probe_transform"


def verify_manifest_evidence(
    manifest: dict, sections: list[dict], imports: list[str], exports: list[str],
) -> None:
    """Prove complete named v1 observations for a controlled PE32 DLL."""
    assert manifest["sections"] == sections, "PE32 DLL section table mismatch"
    assert manifest["imports"] == imports, "PE32 DLL named import mismatch"
    assert manifest["exports"] == exports, "PE32 DLL named export mismatch"
    assert manifest["warnings"] == [], "PE32 DLL extraction has warnings"


def check(analyzer: Path, path: Path, producer: str) -> dict:
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    pe = pefile.PE(data=data, fast_load=False)
    assert pe.FILE_HEADER.Machine == 0x014C, "expected IMAGE_FILE_MACHINE_I386"
    assert pe.OPTIONAL_HEADER.Magic == 0x10B, "expected PE32, not PE32+"
    assert pe.FILE_HEADER.Characteristics & 0x2000, "expected DLL flag"
    pe.parse_data_directories()

    sections = [
        {
            "name": entry.Name.rstrip(b"\x00").decode("ascii"),
            "offset": int(entry.PointerToRawData),
            "size": int(entry.SizeOfRawData),
            "virtual_address": int(entry.VirtualAddress),
        }
        for entry in pe.sections
    ]
    section_names = {entry["name"] for entry in sections}
    assert ".text" in section_names and len(section_names) >= 2, section_names
    assert hasattr(pe, "DIRECTORY_ENTRY_IMPORT"), "DLL has no imports"
    imports: set[str] = set()
    for directory in pe.DIRECTORY_ENTRY_IMPORT:
        dll = directory.dll.decode("ascii")
        for symbol in directory.imports:
            # Named symbols only are representable by this scoped oracle.
            # Refuse unmodelled ordinal-only imports rather than claiming completeness.
            assert symbol.name is not None, "ordinal-only DLL import not modelled"
            imports.add(f"{dll}!{symbol.name.decode('ascii')}")
    assert any(item.endswith("!GetTickCount64") for item in imports), imports
    assert hasattr(pe, "DIRECTORY_ENTRY_EXPORT"), "DLL has no exports"
    exports: set[str] = set()
    for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        assert symbol.name is not None, "ordinal-only DLL export not modelled"
        exports.add(symbol.name.decode("ascii"))
    assert any(name.lstrip("_") == EXPECTED_EXPORT for name in exports), exports

    result = subprocess.run(
        [str(analyzer), "analyze", str(path)],
        text=True, capture_output=True, check=False, timeout=30,
    )
    assert result.returncode == 0, result.stderr[:1000]
    manifest = json.loads(result.stdout)
    assert manifest["schema_version"] == "1.0.0"
    assert manifest["format"] == "PE" and manifest["arch"] == "x86"
    assert manifest["binary_sha256"] == digest
    assert manifest["size_bytes"] == len(data)
    verify_manifest_evidence(manifest, sections, sorted(imports), sorted(exports))

    return {
        "case_id": f"{producer}-x86-dll",
        "source_path": "fixtures/probes/x86_dll_probe.c",
        "source_sha256": hashlib.sha256(
            (ROOT / "fixtures/probes/x86_dll_probe.c").read_bytes()
        ).hexdigest(),
        "compiler_frontend": producer,
        "binary_sha256": digest,
        "size_bytes": len(data),
        "pe_magic": "PE32",
        "machine": "I386",
        "is_dll": True,
        "section_names": sorted(section_names),
        "independently_observed_import": "GetTickCount64",
        "independently_observed_export": EXPECTED_EXPORT,
        "redistribution_status": "not-established",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--msvc-dll", required=True, type=Path)
    parser.add_argument("--clang-dll", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    analyzer = args.binary.resolve(strict=True)
    cases = [
        check(analyzer, args.msvc_dll.resolve(strict=True), "msvc"),
        check(analyzer, args.clang_dll.resolve(strict=True), "clang-cl"),
    ]
    report = {
        "format": "rel-p15a-ci-built-x86-dll-oracle-v1",
        "reference_oracle": "pefile==2024.8.26",
        "scope": "locally-compiled-static-only-pe32-dlls",
        "cases": cases,
    }
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    for case in cases:
        print(f"PASS {case['case_id']}: static PE32 DLL, sha256={case['binary_sha256']}")


if __name__ == "__main__":
    main()
