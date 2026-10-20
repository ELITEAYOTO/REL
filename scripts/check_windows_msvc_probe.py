#!/usr/bin/env python3
"""Independent PE32+ x64 oracle for static compiler-built reference EXEs.

Only rel-inspect is executed. The referenced Windows PE is never launched.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

import pefile


def check(analyzer: Path, probe: Path, compiler_label: str = "MSVC") -> dict:
    assert probe.is_file(), f"{compiler_label} probe was not built"
    raw = probe.read_bytes()
    assert raw[:2] == b"MZ", "not a PE file"
    expected_sha = hashlib.sha256(raw).hexdigest()
    independent = pefile.PE(data=raw, fast_load=False)
    assert independent.FILE_HEADER.Machine == 0x8664, "expected x64 PE"
    assert independent.OPTIONAL_HEADER.Magic == 0x20B, "expected PE32+"
    independent.parse_data_directories()

    section_names = {
        s.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        for s in independent.sections
    }
    assert ".text" in section_names and ".rdata" in section_names, section_names
    assert len(section_names) >= 3, section_names
    reference_sections = [
        {
            "name": entry.Name.rstrip(b"\x00").decode("ascii", errors="replace"),
            "offset": int(entry.PointerToRawData),
            "size": int(entry.SizeOfRawData),
            "virtual_address": int(entry.VirtualAddress),
        }
        for entry in independent.sections
    ]
    assert hasattr(independent, "DIRECTORY_ENTRY_IMPORT"), "probe has no imports"
    imported_symbols = {
        symbol.name.decode("ascii", errors="replace")
        for directory in independent.DIRECTORY_ENTRY_IMPORT
        for symbol in directory.imports if symbol.name
    }
    assert "GetTickCount64" in imported_symbols, imported_symbols
    assert hasattr(independent, "DIRECTORY_ENTRY_EXPORT"), "probe has no exports"
    export_names = {
        symbol.name.decode("ascii", errors="replace")
        for symbol in independent.DIRECTORY_ENTRY_EXPORT.symbols if symbol.name
    }
    assert "rel_probe_transform" in export_names, export_names

    result = subprocess.run(
        [str(analyzer), "analyze", str(probe)],
        text=True, capture_output=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stderr[:1000]
    manifest = json.loads(result.stdout)
    assert manifest["schema_version"] == "1.0.0"
    assert manifest["format"] == "PE"
    assert manifest["arch"] == "x86_64"
    assert manifest["binary_sha256"] == expected_sha
    assert manifest["size_bytes"] == len(raw)
    assert manifest["sections"] == reference_sections, (
        "PE section table differs from independent pefile oracle",
        manifest["sections"], reference_sections,
    )
    assert "rel_probe_transform" in manifest["exports"]
    assert any("GetTickCount64" in item for item in manifest["imports"]), (
        "REL missing the independently verified GetTickCount64 import"
    )
    print(f"PASS {compiler_label} x64 probe analyzed without running; sha256={expected_sha}")
    return {
        "case_id": f"{compiler_label.lower()}-x64-exe",
        "producer": compiler_label,
        "binary_sha256": expected_sha,
        "size_bytes": len(raw),
        "pe_machine": "AMD64",
        "pe_magic": "PE32+",
        "section_table": reference_sections,
        "verified_import": "GetTickCount64",
        "verified_export": "rel_probe_transform",
        "source_path": "fixtures/probes/msvc_probe.c",
        "source_sha256": hashlib.sha256(
            (Path(__file__).resolve().parents[1] / "fixtures/probes/msvc_probe.c").read_bytes()
        ).hexdigest(),
        "reference_oracle": "pefile==2024.8.26",
        "redistribution_status": "not-established",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument(
        "--compiler-label", default="MSVC", choices=["MSVC", "Clang-cl", "MinGW-w64"]
    )
    parser.add_argument("--toolchain-version-file", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = check(
        args.binary.resolve(strict=True), args.probe.resolve(strict=True),
        args.compiler_label,
    )
    if args.output is not None:
        if args.toolchain_version_file is None:
            parser.error("--output requires --toolchain-version-file for provenance")
        lines = args.toolchain_version_file.read_text(encoding="utf-8").splitlines()
        if len(lines) != 2 or not all(lines):
            parser.error("expected compiler and linker version lines")
        result["observed_compiler_version"] = lines[0][:256]
        result["observed_linker_version"] = lines[1][:256]
        result["runner_commit"] = os.environ.get("GITHUB_SHA")
        args.output.write_text(
            json.dumps({"format": "rel-p15a-ci-built-x64-oracle-v1", "case": result},
                       indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
