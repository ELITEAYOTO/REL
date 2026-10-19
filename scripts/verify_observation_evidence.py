#!/usr/bin/env python3
"""Recheck selected EX-01 claims against original controlled PE file bytes.

This is intentionally stricter than the experimental JSON Schema: it only
recognizes the three rel-observe domains whose source-byte semantics are known.
It checks byte correspondence, not file authenticity or execution behavior.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

from jsonschema import ValidationError
from validate_observation_envelope import validate

MAX_INPUT = 2 * 1024 * 1024
CONFIGS = {
    "pe.dos_magic": b"rel-observe:dos-magic:v1;limit=2097152;require-mz-and-pe-signatures",
    "pe.coff_machine": b"rel-observe:coff-machine:v1;limit=2097152;require-mz-and-pe-signatures",
    "pe.section_headers": b"rel-observe:section-headers:v1;limit=2097152;max=32;record=40",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(test: bool, explanation: str) -> None:
    if not test:
        raise ValueError(explanation)


def framing(data: bytes) -> int:
    require(data[:2] == b"MZ", "source does not have MZ bytes")
    require(len(data) >= 0x40, "source has no full e_lfanew")
    nt = struct.unpack_from("<I", data, 0x3c)[0]
    require(data[nt:nt + 4] == b"PE\0\0", "source does not have the minimal PE signature")
    return nt


def observation(identifier: str, predicate: str, status: str,
                raw: str | None, normalized: str | None,
                evidence_ids: list[str]) -> dict:
    return {
        "id": identifier, "predicate": predicate, "status": status,
        "raw_value": raw, "normalized_value": normalized,
        "evidence_ids": evidence_ids,
    }


def evidence(identifier: str, subject: str, start: int, length: int,
             method: str, version: str) -> dict:
    return {
        "id": identifier,
        "subject_sha256": subject,
        "location": {"kind": "file_offset", "start": start, "length": length},
        "method": method,
        "extractor_version": version,
    }


def expected_dos(data: bytes, nt: int, subject: str, version: str) -> tuple:
    del data, nt
    return (
        "complete",
        [
            observation("dos-mz-present", "equals.MZ", "present", "MZ", "MZ", ["dos-prefix"]),
            observation("dos-ne-absent", "equals.NE", "absent_in_scope", None, None, ["dos-prefix"]),
        ],
        [evidence("dos-prefix", subject, 0, 2, "exact-two-byte-comparison", version)],
        None,
    )


def expected_coff(data: bytes, nt: int, subject: str, version: str) -> tuple:
    position = nt + 4
    raw = data[position:position + 2]
    if len(raw) != 2:
        return (
            "partial",
            [observation("coff-machine-value", "pe.coff_machine.value",
                         "indeterminate", None, None, [])],
            [],
            ("COFF_MACHINE_TRUNCATED", "warning", "coff_machine"),
        )
    value = struct.unpack("<H", raw)[0]
    code = f"0x{value:04x}"
    normalized = {0x014c: "x86", 0x8664: "x86_64"}.get(value, code)
    return (
        "complete",
        [observation("coff-machine-value", "pe.coff_machine.value",
                     "present", code, normalized, ["coff-machine-field"])],
        [evidence("coff-machine-field", subject, position, 2,
                  "exact-le-u16-field-extraction", version)],
        None,
    )


def indeterminate(domain: str, code: str, state: str = "partial") -> tuple:
    return (
        state,
        [observation("section-headers-undetermined", "pe.section_headers.records",
                     "indeterminate", None, None, [])],
        [],
        (code, "warning", "section_headers"),
    )


def expected_sections(data: bytes, nt: int, subject: str, version: str) -> tuple:
    coff = nt + 4
    if len(data[coff:coff + 20]) != 20:
        return indeterminate("pe.section_headers", "SECTION_COFF_TRUNCATED")
    count = struct.unpack_from("<H", data, coff + 2)[0]
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    if count > 32:
        return indeterminate("pe.section_headers", "SECTION_COUNT_LIMIT", "unsupported")
    start = coff + 20 + optional_size
    finish = start + count * 40
    if len(data) < start or len(data) < finish:
        return indeterminate("pe.section_headers", "SECTION_TABLE_TRUNCATED")
    if count == 0:
        return (
            "complete",
            [observation("section-headers-empty", "pe.section_headers.records",
                         "absent_in_scope", None, None, ["coff-section-count"])],
            [evidence("coff-section-count", subject, coff + 2, 2,
                      "exact-le-u16-section-count", version)],
            None,
        )

    observations, proofs = [], []
    for index in range(count):
        offset = start + index * 40
        record = data[offset:offset + 40]
        virtual_size, rva, raw_size, raw_pointer = struct.unpack_from("<4I", record, 8)
        flags = struct.unpack_from("<I", record, 36)[0]
        normalized = (
            f"name_hex={record[:8].hex()};virtual_size=0x{virtual_size:08x};"
            f"rva=0x{rva:08x};raw_size=0x{raw_size:08x};"
            f"raw_pointer=0x{raw_pointer:08x};characteristics=0x{flags:08x}"
        )
        item = f"section-{index:03}"
        proof = f"{item}-header"
        observations.append(observation(item, "pe.section_headers.record",
                                        "present", record.hex(), normalized, [proof]))
        proofs.append(evidence(proof, subject, offset, 40,
                               "exact-40-byte-coff-section-record", version))
    return "complete", observations, proofs, None


def verify(report: dict, data: bytes) -> None:
    """Raise ValueError/ValidationError for any unsupported or unproven claim."""
    require(len(data) <= MAX_INPUT, "source exceeds controlled-input limit")
    validate(report)
    domain = report["scope"]["domain"]
    require(domain in CONFIGS, "unrecognized EX-01 observation domain")
    subject = sha256(data)
    require(report["subject"]["sha256"] == subject, "source SHA-256 mismatch")
    require(report["subject"]["size_bytes"] == len(data), "source byte length mismatch")

    producer = report["producer"]
    require(producer["component"] == "rel-observe", "unsupported report producer")
    require(producer["backend"] == "rust-static-byte-reader", "unsupported backend")
    version = producer["version"]
    require(producer["backend_version"] == version, "backend version mismatch")
    config = CONFIGS[domain]
    config_sha = hashlib.sha256(config).digest()
    require(producer["config_sha256"] == config_sha.hex(), "configuration hash mismatch")
    preimage = (
        b"REL-EX01-RUN-v1\0" + hashlib.sha256(data).digest()
        + config_sha + domain.encode("ascii") + b"\0" + version.encode("ascii")
    )
    require(producer["run_id"] == sha256(preimage), "deterministic run ID mismatch")

    nt = framing(data)
    generator = {
        "pe.dos_magic": expected_dos,
        "pe.coff_machine": expected_coff,
        "pe.section_headers": expected_sections,
    }[domain]
    state, expected_observations, expected_proofs, diagnostic = generator(
        data, nt, subject, version
    )
    require(report["scope"]["status"] == state, "incorrect source coverage status")
    require(report["observations"] == expected_observations,
            "source observation values or scope claims do not match")
    require(report["evidence"] == expected_proofs,
            "file offset, evidence method, or subject proof mismatch")
    actual_diagnostics = report["diagnostics"]
    if diagnostic is None:
        require(actual_diagnostics == [], "unexpected diagnostics on complete coverage")
    else:
        require(len(actual_diagnostics) == 1, "incomplete coverage requires one diagnostic")
        code, severity, stage = diagnostic
        item = actual_diagnostics[0]
        require(
            (item["code"], item["severity"], item["stage"]) == (code, severity, stage),
            "diagnostic is inconsistent with actual source coverage",
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="controlled PE file")
    parser.add_argument("--report", type=Path, required=True, help="EX-01 JSON report")
    args = parser.parse_args()
    try:
        if args.input.stat().st_size > MAX_INPUT:
            raise ValueError("input exceeds 2 MiB")
        data = args.input.read_bytes()
        report = json.loads(args.report.read_text(encoding="utf-8"))
        verify(report, data)
    except (ValueError, ValidationError, OSError, TypeError) as error:
        print(f"FAIL EX-01 evidence verification: {error}", file=sys.stderr)
        return 1
    print("PASS EX-01 source-backed evidence verification")
    return 0


if __name__ == "__main__":
    sys.exit(main())
