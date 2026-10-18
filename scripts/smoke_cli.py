#!/usr/bin/env python3
"""P1 integration test: exercise the actual compiled CLI, not an implementation mock."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def call(binary: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(binary), *arguments], text=True, capture_output=True, timeout=30, check=False
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    binary = parser.parse_args().binary.resolve(strict=True)
    fixtures = ROOT / "fixtures"
    expected = json.loads((fixtures / "expected.json").read_text(encoding="utf-8"))
    from jsonschema import Draft202012Validator

    schema = json.loads(
        (ROOT / "contracts/schemas/binary-manifest.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    version = call(binary, "--version")
    assert version.returncode == 0 and version.stdout.startswith("rel-inspect 0.1.")

    for filename, truth in expected.items():
        source = fixtures / filename
        assert hashlib.sha256(source.read_bytes()).hexdigest() == truth["sha256"]
        result = call(binary, "analyze", str(source))
        assert result.returncode == 0, (filename, result.stderr)
        manifest = json.loads(result.stdout)
        validator.validate(manifest)
        assert manifest["binary_sha256"] == truth["sha256"]
        assert manifest["size_bytes"] == truth["size_bytes"]
        assert manifest["arch"] == truth["arch"]
        assert manifest["format"] == truth["format"]
        assert [section["name"] for section in manifest["sections"]] == truth["sections"]
        assert manifest["imports"] == truth["imports"], manifest["imports"]
        assert manifest["exports"] == truth["exports"], manifest["exports"]
        print("PASS", filename)

    with tempfile.TemporaryDirectory() as directory:
        destination = Path(directory) / "result.json"
        source = fixtures / "pe64-basic.exe"
        first = call(binary, "analyze", str(source), "--output", str(destination))
        assert first.returncode == 0, first.stderr
        second = call(binary, "analyze", str(source), "--output", str(destination))
        assert second.returncode != 0, "existing reports must not be silently overwritten"
        assert json.loads(destination.read_text(encoding="utf-8"))["binary_sha256"] == expected[
            "pe64-basic.exe"
        ]["sha256"]

        for name, content in [("bad.exe", b"MZ"), ("other.txt", b"plain text")]:
            invalid = Path(directory) / name
            invalid.write_bytes(content)
            result = call(binary, "analyze", str(invalid))
            assert result.returncode != 0 and result.stderr, name

        same_path = call(binary, "analyze", str(source), "--output", str(source))
        assert same_path.returncode != 0, "input must not be overwritten"
    print("PASS CLI failure and overwrite guard scenarios")


if __name__ == "__main__":
    main()
