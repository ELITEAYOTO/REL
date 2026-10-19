#!/usr/bin/env python3
"""Independent end-to-end oracle for the experimental COFF Machine domain."""
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

ROOT = Path(__file__).resolve().parents[1]
CONFIG = b"rel-observe:coff-machine:v1;limit=2097152;require-mz-and-pe-signatures"


def run(binary: Path, path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(binary), "coff-machine", str(path)],
        capture_output=True, text=True, timeout=20, check=False,
    )


def expected_run_id(data: bytes, version: str) -> str:
    payload = (
        b"REL-EX01-RUN-v1\0"
        + hashlib.sha256(data).digest()
        + hashlib.sha256(CONFIG).digest()
        + b"pe.coff_machine\0"
        + version.encode("ascii")
    )
    return hashlib.sha256(payload).hexdigest()


def check(binary: Path, path: Path, expected: str | None) -> dict:
    data = path.read_bytes()
    first, second = run(binary, path), run(binary, path)
    assert first.returncode == second.returncode == 0, (first.stderr, second.stderr)
    assert first.stdout == second.stdout, "COFF reports must be byte-identical"
    report = json.loads(first.stdout)
    validate(report)
    assert report["subject"]["sha256"] == hashlib.sha256(data).hexdigest()
    assert report["subject"]["size_bytes"] == len(data)
    assert report["producer"]["config_sha256"] == hashlib.sha256(CONFIG).hexdigest()
    assert report["producer"]["run_id"] == expected_run_id(
        data, report["producer"]["version"]
    )
    assert report["scope"]["domain"] == "pe.coff_machine"
    assert "file_path" not in report and "timestamp" not in report

    nt = struct.unpack_from("<I", data, 0x3c)[0]
    assert data[nt:nt + 4] == b"PE\0\0"
    position = nt + 4
    observation = report["observations"][0]
    assert observation["predicate"] == "pe.coff_machine.value"
    if expected is not None:
        machine = struct.unpack_from("<H", data, position)[0]
        assert observation["raw_value"] == f"0x{machine:04x}"
        assert observation["normalized_value"] == expected
        assert observation["status"] == "present"
        assert report["scope"]["status"] == "complete"
        assert report["diagnostics"] == []
        assert len(report["evidence"]) == 1
        proof = report["evidence"][0]
        assert proof["subject_sha256"] == report["subject"]["sha256"]
        assert proof["location"] == {
            "kind": "file_offset", "start": position, "length": 2
        }
        assert proof["id"] in observation["evidence_ids"]
        assert data[position:position + 2] == struct.pack("<H", machine)
    else:
        assert len(data[position:position + 2]) < 2
        assert report["scope"]["status"] == "partial"
        assert observation["status"] == "indeterminate"
        assert observation["raw_value"] is None
        assert observation["normalized_value"] is None
        assert observation["evidence_ids"] == []
        assert report["evidence"] == []
        assert report["diagnostics"][0]["code"] == "COFF_MACHINE_TRUNCATED"
    return report


def rejected(binary: Path, path: Path) -> None:
    result = run(binary, path)
    assert result.returncode and result.stderr and not result.stdout


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    reference = ROOT / "fixtures"
    pe32 = reference / "pe32-basic.exe"
    pe64 = reference / "pe64-basic.exe"
    x86 = check(binary, pe32, "x86")
    x64 = check(binary, pe64, "x86_64")
    assert x86["producer"]["run_id"] != x64["producer"]["run_id"]

    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp)
        renamed = folder / "same-content.exe"
        shutil.copyfile(pe32, renamed)
        assert check(binary, renamed, "x86") == x86
        raw = pe32.read_bytes()
        nt = struct.unpack_from("<I", raw, 0x3c)[0]
        for width in (0, 1):
            partial = folder / f"missing-{width}.exe"
            partial.write_bytes(raw[:nt + 4 + width])
            check(binary, partial, None)
        uncommon = bytearray(raw)
        struct.pack_into("<H", uncommon, nt + 4, 0x9999)
        variant = folder / "unrecognized-machine.exe"
        variant.write_bytes(uncommon)
        check(binary, variant, "0x9999")
        invalid = folder / "invalid.exe"
        invalid.write_bytes(b"MZ")
        rejected(binary, invalid)
        invalid.write_bytes(b"not-a-pe")
        rejected(binary, invalid)
        oversized = folder / "over-limit.exe"
        with oversized.open("wb") as file:
            file.truncate(2 * 1024 * 1024 + 1)
        rejected(binary, oversized)
    print("PASS EX-01 COFF Machine: real offsets, partial abstention, deterministic ID")


if __name__ == "__main__":
    main()
