#!/usr/bin/env python3
"""Independent report/source audit and deliberate EX-01 tampering regression."""
from __future__ import annotations

import argparse
import copy
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from verify_observation_evidence import verify  # noqa: E402
from jsonschema import ValidationError  # noqa: E402


def run(binary: Path, command: str, path: Path) -> dict:
    result = subprocess.run(
        [str(binary), command, str(path)],
        text=True, capture_output=True, check=False, timeout=20,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def must_reject(report: dict, data: bytes, label: str) -> None:
    try:
        verify(report, data)
    except (ValueError, ValidationError):
        print("PASS rejects", label)
        return
    raise AssertionError(f"evidence verifier accepted falsification: {label}")


def mutate(base: dict, field: str, value: object) -> dict:
    result = copy.deepcopy(base)
    result[field] = value
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    pe32 = (ROOT / "fixtures/pe32-basic.exe").read_bytes()
    pe64 = (ROOT / "fixtures/pe64-basic.exe").read_bytes()

    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        for fixture in ("pe32-basic.exe", "pe64-basic.exe"):
            path = ROOT / "fixtures" / fixture
            data = path.read_bytes()
            for command in ("dos-magic", "coff-machine", "section-headers"):
                report = run(binary, command, path)
                verify(report, data)
                report_path = work / "report.json"
                report_path.write_text(json.dumps(report), encoding="utf-8")
                cli = subprocess.run(
                    [sys.executable, str(ROOT / "scripts/verify_observation_evidence.py"),
                     "--input", str(path), "--report", str(report_path)],
                    text=True, capture_output=True, check=False, timeout=20,
                )
                assert cli.returncode == 0, cli.stderr
        original = ROOT / "fixtures/pe32-basic.exe"
        pe_report = run(binary, "section-headers", original)
        dos_report = run(binary, "dos-magic", original)
        machine_report = run(binary, "coff-machine", original)

        def bad(report: dict, label: str, changer) -> None:
            wrong = copy.deepcopy(report)
            changer(wrong)
            must_reject(wrong, pe32, label)

        bad(pe_report, "changed 40-byte source record",
            lambda r: r["observations"][0].update(raw_value="00"*40))
        bad(pe_report, "fabricated normalized RVA",
            lambda r: r["observations"][0].update(normalized_value="invented"))
        bad(pe_report, "shifted evidence file offset",
            lambda r: r["evidence"][0]["location"].update(start=0))
        bad(pe_report, "evidence record length",
            lambda r: r["evidence"][0]["location"].update(length=1))
        bad(pe_report, "dropped section observation",
            lambda r: r["observations"].pop())
        bad(pe_report, "changed method despite plausible offset",
            lambda r: r["evidence"][0].update(method="unsupported-method"))
        bad(pe_report, "fake source identity",
            lambda r: r["subject"].update(sha256="f"*64))
        bad(pe_report, "inconsistent run ID",
            lambda r: r["producer"].update(run_id="f"*64))
        bad(pe_report, "fake extractor config",
            lambda r: r["producer"].update(config_sha256="f"*64))
        bad(pe_report, "different domain in valid schema",
            lambda r: r["scope"].update(domain="pe.fake_domain"))
        bad(pe_report, "unexpected successful diagnostic",
            lambda r: r["diagnostics"].append({
                "code": "FAKE", "severity": "info", "stage": "test", "message": "not true"
            }))
        bad(dos_report, "unsupported MZ negative claim",
            lambda r: r["observations"][0].update(
                status="absent_in_scope", raw_value=None, normalized_value=None
            ))
        bad(machine_report, "machine value tampering",
            lambda r: r["observations"][0].update(raw_value="0xffff"))
        must_reject(pe_report, pe64, "same report on a different PE")
        must_reject(mutate(pe_report, "producer", {**pe_report["producer"],
                                                  "component": "impostor"}), pe32,
                    "unrecognized producer")

        nt = struct.unpack_from("<I", pe32, 0x3c)[0]
        coff = nt + 4
        count = struct.unpack_from("<H", pe32, coff + 2)[0]
        table = coff + 20 + struct.unpack_from("<H", pe32, coff + 16)[0]
        assert 0 < count <= 32

        variants = [
            (pe32[:coff + 19], "partial", "SECTION_COFF_TRUNCATED"),
            (pe32[:table + count*40 - 1], "partial", "SECTION_TABLE_TRUNCATED"),
        ]
        for index, (source, status, code) in enumerate(variants):
            path = work / f"partial-{index}.exe"
            path.write_bytes(source)
            report = run(binary, "section-headers", path)
            verify(report, source)
            assert report["scope"]["status"] == status
            fake = copy.deepcopy(report)
            fake["diagnostics"][0]["code"] = "SECTION_COUNT_LIMIT"
            must_reject(fake, source, "wrong diagnostic for " + code)
            fake = copy.deepcopy(report)
            fake["scope"]["status"] = "complete"
            must_reject(fake, source, "false complete after truncated input")

        too_many = bytearray(pe32)
        struct.pack_into("<H", too_many, coff + 2, 33)
        path = work / "too-many.exe"
        path.write_bytes(too_many)
        unsupported = run(binary, "section-headers", path)
        verify(unsupported, bytes(too_many))
        assert unsupported["scope"]["status"] == "unsupported"

        no_sections = bytearray(pe32)
        struct.pack_into("<H", no_sections, coff + 2, 0)
        path = work / "zero-sections.exe"
        path.write_bytes(no_sections)
        absent = run(binary, "section-headers", path)
        verify(absent, bytes(no_sections))
        fake = copy.deepcopy(absent)
        fake["evidence"][0]["location"]["start"] += 1
        must_reject(fake, bytes(no_sections), "shifted negative evidence")

        truncated = pe32[:nt + 5]
        path = work / "one-machine-byte.exe"
        path.write_bytes(truncated)
        partial_machine = run(binary, "coff-machine", path)
        verify(partial_machine, truncated)
        wrong = copy.deepcopy(partial_machine)
        wrong["observations"][0].update(
            status="present", raw_value="0x014c", normalized_value="x86",
            evidence_ids=["invented"],
        )
        must_reject(wrong, truncated, "fabricated machine on truncated input")
    print("PASS EX-01 independent evidence audit and falsification regressions")


if __name__ == "__main__":
    main()
