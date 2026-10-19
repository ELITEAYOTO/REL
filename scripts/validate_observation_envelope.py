#!/usr/bin/env python3
"""Validate REL's standalone EX-01 experimental observation envelope.

Does not execute or parse a binary and cannot prove that observations are true.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "contracts/experimental/observation-envelope.schema.json"


def validate(payload: dict) -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(payload)
    scope = payload["scope"]["status"]
    observations = payload["observations"]
    evidence = payload["evidence"]
    diagnostics = payload["diagnostics"]

    if scope != "complete" and not diagnostics:
        raise ValueError("incomplete coverage requires diagnostics")
    if scope == "failed" and not any(d["severity"] == "error" for d in diagnostics):
        raise ValueError("failed coverage requires an error diagnostic")
    for key, items in (("observation", observations), ("evidence", evidence)):
        ids = [entry["id"] for entry in items]
        if len(ids) != len(set(ids)):
            raise ValueError(f"duplicate {key} ID")
    evidence_ids = {item["id"] for item in evidence}
    subject = payload["subject"]
    for entry in evidence:
        if entry["subject_sha256"] != subject["sha256"]:
            raise ValueError("evidence subject hash mismatch")
        location = entry["location"]
        if location["kind"] == "file_offset":
            start, length = location["start"], location["length"]
            if start > subject["size_bytes"] or length > subject["size_bytes"] - start:
                raise ValueError("file evidence exceeds subject size")
    for entry in observations:
        status = entry["status"]
        if not set(entry["evidence_ids"]).issubset(evidence_ids):
            raise ValueError("missing referenced evidence")
        if status == "present":
            if scope != "complete" or not entry["evidence_ids"]:
                raise ValueError("present requires complete coverage and evidence")
            if entry["raw_value"] is None or entry["normalized_value"] is None:
                raise ValueError("present requires raw and normalized values")
        elif status == "absent_in_scope":
            if (
                scope != "complete"
                or not entry["evidence_ids"]
                or entry["raw_value"] is not None
                or entry["normalized_value"] is not None
            ):
                raise ValueError("absence requires complete coverage, evidence, and no invented value")
        else:
            if entry["raw_value"] is not None or entry["normalized_value"] is not None or entry["evidence_ids"]:
                raise ValueError("indeterminate cannot claim a value or decisive evidence")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    validate(json.loads(args.report.read_text(encoding="utf-8")))
    print(f"PASS experimental EX-01 contract: {args.report.name}")


if __name__ == "__main__":
    main()
