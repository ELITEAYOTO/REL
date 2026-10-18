#!/usr/bin/env python3
"""Windows-only independent oracle for a never-executed compiler-built PE."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

import pefile


def check(analyzer: Path, probe: Path, compiler_label: str = "MSVC") -> None:
    assert probe.is_file(), "MSVC probe was not built"
    raw = probe.read_bytes()
    assert raw[:2] == b"MZ", "not a PE file"
    expected_sha = hashlib.sha256(raw).hexdigest()
    independent = pefile.PE(data=raw, fast_load=False)
    assert independent.FILE_HEADER.Machine == 0x8664, "expected MSVC x64 PE"
    assert independent.OPTIONAL_HEADER.Magic == 0x20B, "expected PE32+"
    independent.parse_data_directories()

    section_names = {
        s.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        for s in independent.sections
    }
    assert ".text" in section_names and ".rdata" in section_names, section_names
    assert len(section_names) >= 3, section_names
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
    assert ".text" in {x["name"] for x in manifest["sections"]}
    assert ".rdata" in {x["name"] for x in manifest["sections"]}
    assert "rel_probe_transform" in manifest["exports"]
    assert any("GetTickCount64" in item for item in manifest["imports"]), (
        "REL missing the independently verified GetTickCount64 import"
    )
    print(f"PASS {compiler_label} x64 probe analyzed without running; sha256={expected_sha}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--compiler-label", default="MSVC", choices=["MSVC", "Clang-cl"])
    args = parser.parse_args()
    check(args.binary.resolve(strict=True), args.probe.resolve(strict=True), args.compiler_label)
