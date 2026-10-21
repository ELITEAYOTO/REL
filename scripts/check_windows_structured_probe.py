#!/usr/bin/env python3
"""Cross-compiler static-only PE resource and base-relocation oracle (Windows)."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

import pefile


def verify_manifest_evidence(
    manifest: dict, *, sha256: str, size_bytes: int,
    sections: list[dict], imports: list[str], exports: list[str],
) -> None:
    """Check complete v1 observations against independent pefile evidence."""
    assert manifest["schema_version"] == "1.0.0"
    assert manifest["format"] == "PE" and manifest["arch"] == "x86_64"
    assert manifest["binary_sha256"] == sha256
    assert manifest["size_bytes"] == size_bytes
    assert manifest["sections"] == sections, "PE sections differ from independent oracle"
    assert manifest["imports"] == imports, "PE imports differ from independent oracle"
    assert manifest["exports"] == exports, "PE exports differ from independent oracle"
    assert manifest["warnings"] == [], "controlled PE extraction is incomplete"


def validate(binary: Path, probe: Path, compiler_label: str) -> None:
    data = probe.read_bytes()
    expected_hash = hashlib.sha256(data).hexdigest()
    independent = pefile.PE(data=data, fast_load=False)
    assert independent.FILE_HEADER.Machine == 0x8664, "expected x64 PE"
    assert independent.OPTIONAL_HEADER.Magic == 0x20B, "expected PE32+"
    assert independent.OPTIONAL_HEADER.DllCharacteristics & 0x40, "ASLR flag absent"
    independent.parse_data_directories()

    sections = [
        {
            "name": entry.Name.rstrip(b"\x00").decode("ascii"),
            "offset": int(entry.PointerToRawData),
            "size": int(entry.SizeOfRawData),
            "virtual_address": int(entry.VirtualAddress),
        }
        for entry in independent.sections
    ]
    names = {section["name"] for section in sections}
    assert {".text", ".rsrc", ".reloc"} <= names, names

    assert hasattr(independent, "DIRECTORY_ENTRY_RESOURCE"), "resource directory missing"
    matching_resource = False
    for kind in independent.DIRECTORY_ENTRY_RESOURCE.entries:
        if kind.id != 10:  # RT_RCDATA
            continue
        for resource_id in kind.directory.entries:
            if resource_id.id != 101:
                continue
            for language in resource_id.directory.entries:
                descriptor = language.data.struct
                raw = independent.get_data(descriptor.OffsetToData, descriptor.Size)
                if raw.startswith(b"REL-STRUCTURED-PE-RCDATA-V1"):
                    matching_resource = True
    assert matching_resource, "expected RCDATA #101 not found"

    assert hasattr(independent, "DIRECTORY_ENTRY_BASERELOC"), "relocations missing"
    relocations = [
        entry for block in independent.DIRECTORY_ENTRY_BASERELOC
        for entry in block.entries if entry.type == 10  # IMAGE_REL_BASED_DIR64
    ]
    assert relocations, "no DIR64 base relocation entries"

    assert hasattr(independent, "DIRECTORY_ENTRY_IMPORT"), "imports missing"
    imports = sorted({
        f"{library.dll.decode('ascii')}!{symbol.name.decode('ascii')}"
        for library in independent.DIRECTORY_ENTRY_IMPORT
        for symbol in library.imports
        if symbol.name is not None
    })
    assert any(name.endswith("!GetTickCount") for name in imports), (
        "expected GetTickCount import missing", imports
    )
    assert hasattr(independent, "DIRECTORY_ENTRY_EXPORT"), "exports missing"
    exports = sorted({
        item.name.decode("ascii")
        for item in independent.DIRECTORY_ENTRY_EXPORT.symbols if item.name
    })
    assert {"rel_structured_query", "rel_structured_pointer"} <= set(exports), exports

    result = subprocess.run(
        [str(binary), "analyze", str(probe)],
        text=True, capture_output=True, check=False, timeout=30,
    )
    assert result.returncode == 0, result.stderr[:1000]
    manifest = json.loads(result.stdout)
    verify_manifest_evidence(
        manifest, sha256=expected_hash, size_bytes=len(data),
        sections=sections, imports=imports, exports=exports,
    )
    print(
        f"PASS {compiler_label}: controlled .rsrc RCDATA and DIR64 relocations "
        f"verified independently; static REL manifest sha256={expected_hash}"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--probe", required=True, type=Path)
    parser.add_argument("--compiler-label", choices=["MSVC", "Clang-cl"], required=True)
    args = parser.parse_args()
    validate(args.binary.resolve(strict=True), args.probe.resolve(strict=True),
             args.compiler_label)
