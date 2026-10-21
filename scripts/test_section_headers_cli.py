#!/usr/bin/env python3
"""Independent EX-01 section-header oracle for controlled PE fixtures."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

from validate_observation_envelope import validate
from verify_observation_evidence import verify as verify_source_evidence

ROOT = Path(__file__).resolve().parents[1]
CONFIG = b"rel-observe:section-headers:v1;limit=2097152;max=32;record=40"


def run(binary: Path, path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(binary), "section-headers", str(path)],
        text=True, capture_output=True, timeout=20, check=False,
    )


def fields(data: bytes) -> tuple[int, int, int]:
    nt = struct.unpack_from("<I", data, 0x3c)[0]
    assert data[nt:nt + 4] == b"PE\0\0"
    coff = nt + 4
    count = struct.unpack_from("<H", data, coff + 2)[0]
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    return count, coff, coff + 20 + optional_size


def verify(binary: Path, path: Path, expected_status: str) -> dict:
    data = path.read_bytes()
    first = run(binary, path)
    second = run(binary, path)
    assert first.returncode == second.returncode == 0, (first.stderr, second.stderr)
    assert first.stdout == second.stdout, "report must be byte-reproducible"
    report = json.loads(first.stdout)
    validate(report)
    assert report["schema_version"] == "0.1.0-experimental"
    assert report["subject"]["sha256"] == hashlib.sha256(data).hexdigest()
    assert report["subject"]["size_bytes"] == len(data)
    assert report["scope"]["domain"] == "pe.section_headers"
    assert report["scope"]["status"] == expected_status
    assert report["producer"]["config_sha256"] == hashlib.sha256(CONFIG).hexdigest()
    preimage = (
        b"REL-EX01-RUN-v1\0"
        + hashlib.sha256(data).digest()
        + hashlib.sha256(CONFIG).digest()
        + b"pe.section_headers\0"
        + report["producer"]["version"].encode("ascii")
    )
    assert report["producer"]["run_id"] == hashlib.sha256(preimage).hexdigest()
    assert "file_path" not in report and "timestamp" not in report
    if expected_status != "complete":
        assert len(report["observations"]) == 1
        assert report["observations"][0]["status"] == "indeterminate"
        assert report["observations"][0]["raw_value"] is None
        assert report["observations"][0]["normalized_value"] is None
        assert report["observations"][0]["evidence_ids"] == []
        assert report["evidence"] == []
        assert report["diagnostics"][0]["severity"] == "warning"
        assert report["diagnostics"][0]["code"] in (
            "SECTION_COFF_TRUNCATED", "SECTION_TABLE_TRUNCATED",
            "SECTION_COUNT_LIMIT",
        )
        return report

    count, coff, table = fields(data)
    assert 0 <= count <= 32
    assert report["diagnostics"] == []
    if not count:
        assert len(report["observations"]) == 1
        assert report["observations"][0]["status"] == "absent_in_scope"
        assert report["evidence"][0]["location"] == {
            "kind": "file_offset", "start": coff + 2, "length": 2
        }
        assert data[coff + 2:coff + 4] == b"\0\0"
        return report

    assert len(report["observations"]) == len(report["evidence"]) == count
    for index in range(count):
        pos = table + index * 40
        record = data[pos:pos + 40]
        assert len(record) == 40
        name = record[:8].hex()
        virtual_size, rva, raw_size, raw_pointer = struct.unpack_from("<4I", record, 8)
        flags = struct.unpack_from("<I", record, 36)[0]
        expected_value = (
            f"name_hex={name};virtual_size=0x{virtual_size:08x};"
            f"rva=0x{rva:08x};raw_size=0x{raw_size:08x};"
            f"raw_pointer=0x{raw_pointer:08x};characteristics=0x{flags:08x}"
        )
        observation = report["observations"][index]
        evidence = report["evidence"][index]
        assert observation["id"] == f"section-{index:03}"
        assert observation["status"] == "present"
        assert observation["predicate"] == "pe.section_headers.record"
        assert observation["raw_value"] == record.hex()
        assert observation["normalized_value"] == expected_value
        assert observation["evidence_ids"] == [evidence["id"]]
        assert evidence["subject_sha256"] == report["subject"]["sha256"]
        assert evidence["location"] == {
            "kind": "file_offset", "start": pos, "length": 40
        }
    return report


def rejected(binary: Path, path: Path) -> None:
    result = run(binary, path)
    assert result.returncode != 0 and result.stderr and not result.stdout



def verify_non_utf8_section_fallback(inspector: Path, observer: Path, folder: Path) -> None:
    """The same controlled bytes must be rejected by v1 and preserved by EX-01."""
    fixtures = ROOT / "fixtures"
    for filename in ("pe32-basic.exe", "pe64-basic.exe"):
        original = (fixtures / filename).read_bytes()
        original_path = folder / f"baseline-{filename}"
        original_path.write_bytes(original)
        accepted = subprocess.run(
            [str(inspector), "analyze", str(original_path)],
            text=True, capture_output=True, check=False, timeout=20,
        )
        assert accepted.returncode == 0, accepted.stderr
        baseline = json.loads(accepted.stdout)
        assert baseline["schema_version"] == "1.0.0"
        assert baseline["sections"][0]["name"] == ".text"

        count, _, table = fields(original)
        assert count >= 1
        assert original[table:table + 8] == b".text\0\0\0"
        for invalid_byte in (0xff, 0xfe):
            # Exactly one 8-byte section-header field changes, never the
            # original tracked fixture. No PE or DLL is executed or loaded.
            mutated = bytearray(original)
            bad_name = b".bad" + bytes([invalid_byte]) + b"\0\0\0"
            mutated[table:table + 8] = bad_name
            path = folder / f"{filename}-name-{invalid_byte:02x}.exe"
            path.write_bytes(mutated)

            strict = subprocess.run(
                [str(inspector), "analyze", str(path)],
                text=True, capture_output=True, check=False, timeout=20,
            )
            assert strict.returncode != 0
            assert not strict.stdout, "unrepresentable v1 name must not publish a manifest"
            assert "section name cannot be decoded as UTF-8" in strict.stderr

            report = verify(observer, path, "complete")
            verify_source_evidence(report, bytes(mutated))
            first = report["observations"][0]
            assert first["raw_value"][:16] == bad_name.hex()
            assert first["normalized_value"].startswith(f"name_hex={bad_name.hex()};")
            assert report["evidence"][0]["location"] == {
                "kind": "file_offset", "start": table, "length": 40
            }
            assert report["scope"]["domain"] == "pe.section_headers"
            # Complete refers only to the bytes of declared header records:
            # it makes no claim about overall PE validity.
            assert report["scope"]["status"] == "complete"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--inspector", type=Path, help="optional v1 rejection cross-check")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    inspector = args.inspector.resolve(strict=True) if args.inspector else None
    fixtures = ROOT / "fixtures"
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp)
        if inspector is not None:
            verify_non_utf8_section_fallback(inspector, binary, folder)
        for filename in ("pe32-basic.exe", "pe64-basic.exe"):
            fixture = fixtures / filename
            reference = verify(binary, fixture, "complete")
            copy = folder / filename
            shutil.copyfile(fixture, copy)
            assert verify(binary, copy, "complete") == reference

        raw = (fixtures / "pe32-basic.exe").read_bytes()
        count, coff, table = fields(raw)
        assert 0 < count <= 32
        for end in (coff + 19, table - 1, table, table + count * 40 - 1):
            assert end >= coff + 4 and end < len(raw)
            truncated = folder / f"partial-{end}.exe"
            truncated.write_bytes(raw[:end])
            verify(binary, truncated, "partial")
        above_limit = bytearray(raw)
        struct.pack_into("<H", above_limit, coff + 2, 33)
        too_many = folder / "over-count.exe"
        too_many.write_bytes(above_limit)
        verify(binary, too_many, "unsupported")
        no_sections = bytearray(raw)
        struct.pack_into("<H", no_sections, coff + 2, 0)
        empty = folder / "empty-declaration.exe"
        empty.write_bytes(no_sections)
        verify(binary, empty, "complete")

        invalid = folder / "invalid.exe"
        for content in (b"", b"MZ", b"not-a-PE"):
            invalid.write_bytes(content)
            rejected(binary, invalid)
        oversized = folder / "oversized.exe"
        with oversized.open("wb") as output:
            output.truncate(2 * 1024 * 1024 + 1)
        rejected(binary, oversized)
    print("PASS EX-01 section headers: exact 40-byte proofs, limits, partial abstention, reproducible ID; optional non-UTF8 v1/EX-01 integration")


if __name__ == "__main__":
    main()
