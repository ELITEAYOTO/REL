#!/usr/bin/env python3
"""Check REL output against pefile on a native Windows binary built by this CI."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

import pefile


def report_from_rel(binary: Path) -> dict:
    result = subprocess.run(
        [str(binary), "analyze", str(binary)],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(f"rel-inspect failed: {result.stderr[:300]}")
    return json.loads(result.stdout)


def reference_sections(parsed: pefile.PE) -> list[tuple]:
    return [
        (
            section.Name.rstrip(b"\x00").decode("ascii", errors="replace"),
            int(section.PointerToRawData),
            int(section.SizeOfRawData),
            int(section.VirtualAddress),
        )
        for section in parsed.sections
    ]


def manifest_sections(manifest: dict) -> list[tuple]:
    return [
        (
            item["name"],
            item["offset"],
            item["size"],
            item["virtual_address"],
        )
        for item in manifest["sections"]
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    manifest = report_from_rel(binary)

    parsed = pefile.PE(str(binary), fast_load=False)
    try:
        expected_machine = 0x8664 if manifest["arch"] == "x86_64" else 0x14C
        assert int(parsed.FILE_HEADER.Machine) == expected_machine, "machine mismatch"
        assert manifest["format"] == "PE"
        assert manifest["size_bytes"] == binary.stat().st_size
        assert manifest["binary_sha256"] == hashlib.sha256(binary.read_bytes()).hexdigest()

        expected_sections = reference_sections(parsed)
        observed_sections = manifest_sections(manifest)
        assert expected_sections, "oracle has no sections"
        assert observed_sections == expected_sections, (
            "section mismatch", observed_sections, expected_sections
        )

        expected_dlls = {
            entry.dll.decode("ascii", errors="replace").casefold()
            for entry in getattr(parsed, "DIRECTORY_ENTRY_IMPORT", [])
        }
        observed_dlls = {
            imported.split("!", 1)[0].casefold() for imported in manifest["imports"]
        }
        assert expected_dlls, "oracle has no imported DLLs"
        assert observed_dlls == expected_dlls, (
            "imported DLL mismatch", observed_dlls, expected_dlls
        )
        print(
            f"PASS native Windows PE oracle: {len(expected_sections)} sections, "
            f"{len(expected_dlls)} imported DLLs; checksum matches"
        )
    finally:
        parsed.close()


if __name__ == "__main__":
    main()
