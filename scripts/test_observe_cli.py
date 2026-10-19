#!/usr/bin/env python3
"""EX-01 end-to-end test of the real bounded DOS-magic producer."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from validate_observation_envelope import validate

ROOT = Path(__file__).resolve().parents[1]
CONFIG = b"rel-observe:dos-magic:v1;limit=2097152;require-mz-and-pe-signatures"


def call(binary: Path, path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(binary), "dos-magic", str(path)],
        text=True, capture_output=True, timeout=20, check=False,
    )


def check(binary: Path, path: Path) -> dict:
    raw = path.read_bytes()
    first = call(binary, path)
    second = call(binary, path)
    assert first.returncode == second.returncode == 0, (first.stderr, second.stderr)
    assert first.stdout == second.stdout, "same input/config must be byte-reproducible"
    report = json.loads(first.stdout)
    validate(report)
    assert report["subject"]["sha256"] == hashlib.sha256(raw).hexdigest()
    assert report["subject"]["size_bytes"] == len(raw)
    assert report["subject"]["format"] == "PE"
    producer = report["producer"]
    assert producer["config_sha256"] == hashlib.sha256(CONFIG).hexdigest()
    run_input = (
        b"REL-EX01-RUN-v1\0"
        + hashlib.sha256(raw).digest()
        + hashlib.sha256(CONFIG).digest()
        + b"pe.dos_magic\0"
        + producer["version"].encode("ascii")
    )
    assert producer["run_id"] == hashlib.sha256(run_input).hexdigest()
    assert report["scope"]["domain"] == "pe.dos_magic"
    assert report["scope"]["status"] == "complete"
    assert report["observations"][0]["status"] == "present"
    assert report["observations"][1]["status"] == "absent_in_scope"
    assert report["observations"][0]["raw_value"] == raw[:2].decode("ascii") == "MZ"
    ev = report["evidence"][0]
    assert ev["subject_sha256"] == report["subject"]["sha256"]
    assert ev["location"] == {"kind": "file_offset", "start": 0, "length": 2}
    assert raw[ev["location"]["start"]:ev["location"]["start"] + ev["location"]["length"]] == b"MZ"
    assert "file_path" not in report and "timestamp" not in report
    return report


def rejected(binary: Path, path: Path) -> None:
    result = call(binary, path)
    assert result.returncode != 0 and result.stderr, str(path)
    assert not result.stdout, "failure must not emit a false complete report"


def main() -> None:
    cli = argparse.ArgumentParser()
    cli.add_argument("--binary", type=Path, required=True)
    args = cli.parse_args()
    binary = args.binary.resolve(strict=True)
    reference = ROOT / "fixtures"
    a = check(binary, reference / "pe32-basic.exe")
    b = check(binary, reference / "pe64-basic.exe")
    assert a["subject"]["sha256"] != b["subject"]["sha256"]
    assert a["producer"]["run_id"] != b["producer"]["run_id"]

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        alias = root / "renamed-copy.exe"
        shutil.copyfile(reference / "pe32-basic.exe", alias)
        assert check(binary, alias) == a, "file names must not influence reports"
        bad = root / "truncated.exe"
        bad.write_bytes(b"MZ")
        rejected(binary, bad)
        bad.write_bytes(b"not a PE")
        rejected(binary, bad)
        bad.write_bytes(b"MZ" + b"\0" * 62)
        rejected(binary, bad)
        oversized = root / "oversized.exe"
        with oversized.open("wb") as output:
            output.truncate(2 * 1024 * 1024 + 1)
        rejected(binary, oversized)
        rejected(binary, root)
        try:
            symlink = root / "symlink.exe"
            symlink.symlink_to(alias)
        except (OSError, NotImplementedError):
            print("SKIP symlink creation unavailable; Rust leaf type check still active")
        else:
            rejected(binary, symlink)
    print("PASS EX-01 real producer: SHA, evidence, deterministic run ID, controlled failures")


if __name__ == "__main__":
    main()
