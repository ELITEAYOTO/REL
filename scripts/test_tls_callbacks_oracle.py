#!/usr/bin/env python3
"""Independent static TLS callback-table oracle for REL's owned PE fixtures.

Synthesized inputs exist only in a temporary directory. Neither the original
PEs nor the derived images are executed, imported, or committed.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

import pefile


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
RAW_TLS = 0x600  # .rdata RVA 0x2200, raw offset 0x400
RAW_DATA = 0x700  # .rdata RVA 0x2300
RAW_INDEX = 0x710
RAW_CALLBACKS = 0x720
TLS_RVA = 0x2200


def synthesize_tls(source: bytes, *, is_64: bool) -> tuple[bytes, int, int]:
    """Place a valid two-callback, zero-terminated TLS table in unused .rdata."""
    data = bytearray(source)
    assert len(data) == 2048 and data[RAW_TLS:0x740] == bytes(0x140)
    assert data[:2] == b"MZ"
    nt, = struct.unpack_from("<I", data, 0x3C)
    assert nt == 0x80 and data[nt:nt + 4] == b"PE\x00\x00"
    optional = nt + 24
    magic, = struct.unpack_from("<H", data, optional)
    assert magic == (0x20B if is_64 else 0x10B)

    width = 8 if is_64 else 4
    fmt = "<Q" if is_64 else "<I"
    base, = struct.unpack_from(fmt, data, optional + (24 if is_64 else 28))
    assert base == (0x140000000 if is_64 else 0x400000)
    directory_start = 112 if is_64 else 96
    count, = struct.unpack_from("<I", data, optional + directory_start - 4)
    assert count >= 10
    tls_slot = optional + directory_start + 9 * 8
    assert struct.unpack_from("<II", data, tls_slot) == (0, 0)

    struct.pack_into("<II", data, tls_slot, TLS_RVA, 40 if is_64 else 24)
    for index, rva in enumerate((0x2300, 0x2304, 0x2310, 0x2320)):
        struct.pack_into(fmt, data, RAW_TLS + index * width, base + rva)
    data[RAW_DATA:RAW_DATA + 4] = b"\x12\x34\x56\x78"
    for index, rva in enumerate((0x1000, 0x1010, 0)):
        struct.pack_into(fmt, data, RAW_CALLBACKS + index * width, base + rva if rva else 0)

    return bytes(data), base, width


def reference_check(data: bytes, base: int, width: int) -> None:
    """Use pinned pefile, independently of REL, to inspect the PE layout."""
    parsed = pefile.PE(data=data, fast_load=False)
    try:
        assert len(parsed.sections) == 2
        assert parsed.sections[1].Name.rstrip(b"\x00") == b".rdata"
        assert parsed.sections[1].VirtualAddress == 0x2000
        assert parsed.sections[1].PointerToRawData == 0x400
        assert parsed.sections[1].SizeOfRawData == 0x400
        directory = parsed.OPTIONAL_HEADER.DATA_DIRECTORY[9]
        assert (directory.VirtualAddress, directory.Size) == (
            TLS_RVA, 40 if width == 8 else 24
        )
        tls = parsed.DIRECTORY_ENTRY_TLS.struct
        assert tls.StartAddressOfRawData == base + 0x2300
        assert tls.EndAddressOfRawData == base + 0x2304
        assert tls.AddressOfIndex == base + 0x2310
        assert tls.AddressOfCallBacks == base + 0x2320
        assert parsed.get_data(0x2300, 4) == b"\x12\x34\x56\x78"
        pointer_format = "<" + ("Q" if width == 8 else "I") * 3
        callbacks = struct.unpack(
            pointer_format, parsed.get_data(0x2320, width * 3)
        )
        assert callbacks == (base + 0x1000, base + 0x1010, 0)
        assert all(0x1000 <= address - base < 0x1400 for address in callbacks[:2])
    finally:
        parsed.close()


def invoke_rel(binary: Path, data: bytes, output: Path) -> subprocess.CompletedProcess[str]:
    output.write_bytes(data)
    return subprocess.run(
        [str(binary), "analyze", str(output)],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )


def main() -> None:
    binary = ROOT / "target" / "release" / (
        "rel-inspect.exe" if os.name == "nt" else "rel-inspect"
    )
    binary = binary.resolve(strict=True)
    expected = json.loads((FIXTURES / "expected.json").read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="rel-tls-static-") as temp:
        tmp = Path(temp)
        for name, is_64, arch, imported in (
            ("pe32-basic.exe", False, "x86", "KERNEL32.dll!GetTickCount"),
            ("pe64-basic.exe", True, "x86_64", "KERNEL32.dll!GetTickCount64"),
        ):
            source = (FIXTURES / name).read_bytes()
            assert expected[name]["synthetic"] is True
            assert expected[name]["size_bytes"] == len(source)
            assert expected[name]["sha256"] == hashlib.sha256(source).hexdigest()

            valid, base, width = synthesize_tls(source, is_64=is_64)
            reference_check(valid, base, width)
            completed = invoke_rel(binary, valid, tmp / name)
            assert completed.returncode == 0, (
                name, completed.returncode, completed.stderr[:600]
            )
            observed = json.loads(completed.stdout)
            assert observed["format"] == "PE"
            assert observed["arch"] == arch
            assert observed["binary_sha256"] == hashlib.sha256(valid).hexdigest()
            assert observed["imports"] == [imported]
            assert observed["exports"] == ["SampleExport"]
            assert len(observed["sections"]) == 2

            # Unmapped callback-table VA: validity is deliberately unspecified,
            # but an escaped or caught dependency panic is never acceptable.
            mutated = bytearray(valid)
            struct.pack_into(
                "<Q" if is_64 else "<I",
                mutated,
                RAW_TLS + 3 * width,
                base + 0x2400,
            )
            rejected_or_parsed = invoke_rel(
                binary, bytes(mutated), tmp / ("mutated-" + name)
            )
            assert rejected_or_parsed.returncode in (0, 1), (
                name, rejected_or_parsed.returncode, rejected_or_parsed.stderr[:600]
            )
            assert "dependency panicked" not in rejected_or_parsed.stderr.lower()
            if rejected_or_parsed.returncode == 0:
                assert json.loads(rejected_or_parsed.stdout)["format"] == "PE"
            else:
                assert not rejected_or_parsed.stdout, "partial manifest on failure"

            print(
                f"PASS {name}: static TLS directory, 2 callback VAs + null, "
                f"pefile oracle, REL manifest, unmapped callback pointer; "
                f"source_sha256={hashlib.sha256(source).hexdigest()} "
                f"derived_sha256={hashlib.sha256(valid).hexdigest()}"
            )


if __name__ == "__main__":
    main()
