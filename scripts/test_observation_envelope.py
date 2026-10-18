#!/usr/bin/env python3
"""EX-01 contract tests; controlled examples, not an extractor implementation."""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from validate_observation_envelope import validate  # noqa: E402

FOLDER = ROOT / "fixtures/experimental/observation"


def rejects(bad: dict, description: str) -> None:
    try:
        validate(bad)
    except (ValidationError, ValueError):
        print("PASS rejects", description)
        return
    raise AssertionError(f"accepted invalid envelope: {description}")


def main() -> None:
    samples = {
        name: json.loads((FOLDER / f"{name}.json").read_text(encoding="utf-8"))
        for name in ("present", "absent_in_scope", "partial", "failed", "unsupported")
    }
    binary = (ROOT / "fixtures/pe32-basic.exe").read_bytes()
    for name, sample in samples.items():
        validate(sample)
        assert sample["scope"]["status"] == ("complete" if name in ("present", "absent_in_scope") else name)
        assert sample["subject"]["sha256"] == hashlib.sha256(binary).hexdigest()
        assert sample["subject"]["size_bytes"] == len(binary)
        for ev in sample["evidence"]:
            if ev["location"]["kind"] == "file_offset":
                start, length = ev["location"]["start"], ev["location"]["length"]
                assert binary[start:start + length] == b"MZ"
        canonical = lambda x: json.dumps(x, sort_keys=True, separators=(",", ":"))
        assert canonical(sample) == canonical(dict(reversed(list(sample.items()))))
        print("PASS golden", name)

    good = samples["present"]
    cases = []
    def mutate(label, modifier):
        item = copy.deepcopy(good)
        modifier(item)
        cases.append((label, item))
    mutate("v1 schema version", lambda x: x.update(schema_version="1.0.0"))
    mutate("unknown property", lambda x: x.update(path="private.exe"))
    mutate("invalid producer version", lambda x: x["producer"].update(version="latest"))
    mutate("negative offset", lambda x: x["evidence"][0]["location"].update(start=-1))
    mutate("out of range", lambda x: x["evidence"][0]["location"].update(start=2047,length=2))
    mutate("wrong evidence subject", lambda x: x["evidence"][0].update(subject_sha256="f"*64))
    mutate("dangling reference", lambda x: x["observations"][0].update(evidence_ids=["not-found"]))
    mutate("duplicate evidence", lambda x: x["evidence"].append(copy.deepcopy(x["evidence"][0])))
    mutate("empty present proof", lambda x: x["observations"][0].update(evidence_ids=[]))
    mutate("partial present claim", lambda x: x["scope"].update(status="partial"))
    mutate("present without raw value", lambda x: x["observations"][0].update(raw_value=None))
    for name, item in cases:
        rejects(item, name)
    partial_absent = copy.deepcopy(samples["absent_in_scope"])
    partial_absent["scope"]["status"] = "partial"
    rejects(partial_absent, "absence with partial coverage")
    no_diag = copy.deepcopy(samples["unsupported"])
    no_diag["diagnostics"] = []
    rejects(no_diag, "unsupported without diagnostic")
    failed = copy.deepcopy(samples["failed"])
    failed["diagnostics"][0]["severity"] = "warning"
    rejects(failed, "failed without error diagnostic")

    legacy_schema = json.loads((ROOT / "contracts/schemas/binary-manifest.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(legacy_schema)
    assert legacy_schema["properties"]["schema_version"] == {"const": "1.0.0"}
    try:
        Draft202012Validator(legacy_schema).validate(good)
    except ValidationError:
        pass
    else:
        raise AssertionError("experimental envelope incorrectly conforms to v1")
    print("PASS v1 manifest remains separate")


if __name__ == "__main__":
    main()
