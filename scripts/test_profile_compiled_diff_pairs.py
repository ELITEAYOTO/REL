#!/usr/bin/env python3
"""Offline regressions for compiler-derived EX-02 resource evidence."""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from profile_compiled_diff_pairs import (
    PAIRS, diff_counts, static_inspect, validate_manifest, verify_oracle,
)

ROOT = Path(__file__).resolve().parents[1]


def manifest(source: bytes, *, imports=None, exports=None, sections=None) -> dict:
    return {
        "schema_version": "1.0.0",
        "format": "PE",
        "binary_sha256": hashlib.sha256(source).hexdigest(),
        "size_bytes": len(source),
        "warnings": [],
        "imports": imports if imports is not None else ["KERNEL32.dll!A"],
        "exports": exports if exports is not None else ["A"],
        "sections": sections if sections is not None else [
            {"name": ".text", "offset": 512, "size": 64, "virtual_address": 4096}
        ],
    }


class CompiledProfileTests(unittest.TestCase):
    def test_selected_pairs_are_valid_and_span_compilers(self) -> None:
        self.assertEqual(len(PAIRS), 3)
        self.assertEqual(len(set(PAIRS)), len(PAIRS))
        self.assertTrue(any(a.startswith("msvc") and b.startswith("clang")
                            for a, b in PAIRS))
        for a, b in PAIRS:
            self.assertRegex(a, r"^(msvc|clang)-v[1-4]$")
            self.assertRegex(b, r"^(msvc|clang)-v[1-4]$")
            self.assertNotEqual(a, b)

    def test_delta_counts_match_contract_with_changes(self) -> None:
        raw = b"controlled-input"
        left = manifest(raw)
        right = manifest(
            raw,
            imports=["KERNEL32.dll!B", "USER32.dll!C"],
            exports=["B", "C"],
            sections=[
                {"name": ".text", "offset": 512, "size": 80, "virtual_address": 4096},
                {"name": ".rdata", "offset": 1024, "size": 32, "virtual_address": 8192},
            ],
        )
        self.assertEqual(diff_counts(left, right), (2, 2, 1, 0, 1))
        self.assertEqual(diff_counts(right, left), (1, 1, 0, 1, 1))
        self.assertEqual(diff_counts(left, left), (0, 0, 0, 0, 0))

    def test_ambiguous_sections_abstain_without_masking_import_deltas(self) -> None:
        raw = b"controlled-input"
        left = manifest(raw)
        right = manifest(raw, imports=["OTHER.dll!B"], sections=[
            {"name": ".dup", "offset": 100},
            {"name": ".dup", "offset": 200},
        ])
        self.assertEqual(diff_counts(left, right), (1, 0, 0, 0, 0))

    def test_manifest_rejects_hash_warnings_and_duplicate_observations(self) -> None:
        raw = b"fixture-pe-bytes"
        doc = manifest(raw)
        validate_manifest(doc, raw)
        for edit, message in (
            ({"binary_sha256": "f" * 64}, "identity"),
            ({"size_bytes": 100}, "identity"),
            ({"warnings": ["partial-imports"]}, "incomplete"),
            ({"imports": ["same", "same"]}, "repeated imports"),
            ({"sections": [{"name": 42}]}, "section names"),
            ({"schema_version": "1.1.0"}, "manifest v1.0.0"),
        ):
            with self.subTest(edit=edit):
                with self.assertRaisesRegex(ValueError, message):
                    validate_manifest({**doc, **edit}, raw)

    def test_static_inspector_never_executes_pe_input(self) -> None:
        raw = b"MZ" + bytes(80)
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "probe.exe"
            path.write_bytes(raw)
            output = manifest(raw)
            class Result:
                returncode = 0
                stderr = b""
                stdout = json.dumps(output).encode()
            with patch("profile_compiled_diff_pairs.subprocess.run", return_value=Result()) as call:
                actual, original = static_inspect(Path("rel-inspect.exe"), path)
            self.assertEqual(actual, output)
            self.assertEqual(original, raw)
            invocation = call.call_args.args[0]
            self.assertEqual(invocation[1], "analyze")
            self.assertEqual(invocation[2], str(path))
            self.assertNotEqual(invocation[0], str(path))
            with patch("profile_compiled_diff_pairs.subprocess.run") as call:
                with self.assertRaisesRegex(ValueError, "non-symlink"):
                    static_inspect(Path("rel-inspect.exe"), Path(work))

    def test_independent_oracle_must_match_exact_profiled_pe_bytes(self) -> None:
        hashes = {"msvc-v1": "a" * 64, "clang-v3": "b" * 64}
        oracle = {
            "schema_version": "rel-ex02-compiler-pair-evidence-v1",
            "link_mode": "standard",
            "case_count": 8,
            "cases": [
                {"id": name, "sha256": hashes.get(name, "c" * 64)}
                for name in ("msvc-v1", "msvc-v2", "msvc-v3", "msvc-v4",
                             "clang-v1", "clang-v2", "clang-v3", "clang-v4")
            ],
        }
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "oracle.json"
            def write() -> None:
                path.write_text(json.dumps(oracle), encoding="utf-8")
            write()
            self.assertEqual(verify_oracle(path, hashes),
                             hashlib.sha256(path.read_bytes()).hexdigest())
            oracle["cases"][0]["sha256"] = "0" * 64
            write()
            with self.assertRaisesRegex(ValueError, "differ from oracle"):
                verify_oracle(path, hashes)
            oracle["cases"][0]["sha256"] = "a" * 64
            oracle["cases"][1]["id"] = "msvc-v1"
            write()
            with self.assertRaisesRegex(ValueError, "duplicate"):
                verify_oracle(path, hashes)
            oracle["cases"][1]["id"] = "msvc-v2"
            oracle["case_count"] = 7
            write()
            with self.assertRaisesRegex(ValueError, "incomplete"):
                verify_oracle(path, hashes)

    def test_ci_gate_after_compiler_oracle_and_before_corpus_rebuild(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        checkpoints = [
            "Independent EX-02 compiler-built PE pair oracle (Windows)",
            "python scripts/profile_compiled_diff_pairs.py",
            "Repeat same-source compiler builds (Windows; PE files never executed)",
        ]
        places = [ci.index(value) for value in checkpoints]
        self.assertEqual(places, sorted(places))
        self.assertIn("python scripts/test_profile_compiled_diff_pairs.py", ci)
        self.assertIn("rel-ex02-compiler-resource-windows", ci)


if __name__ == "__main__":
    unittest.main(verbosity=2)
