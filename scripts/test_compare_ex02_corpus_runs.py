#!/usr/bin/env python3
"""Self-contained cross-run evidence-validator regressions (no external packages)."""
import copy
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from compare_ex02_corpus_runs import compare_reports, load_report


def sample(mode="brepro"):
    cases = [
        {
            "id": f"{compiler}-v{variant}",
            "sha256": f"{variant + (10 if compiler == 'clang' else 0):064x}",
            "size_bytes": 1024,
        }
        for compiler in ("msvc", "clang")
        for variant in range(1, 5)
    ]
    return {
        "schema_version": "rel-ex02-compiler-pair-evidence-v1",
        "source_sha256": "f" * 64,
        "compilers": {"msvc": "MSVC test", "clang": "clang test"},
        "build_script": "scripts/build_windows_diff_pairs.cmd",
        "link_mode": mode,
        "link_flags": "/INCREMENTAL:NO /Brepro" if mode == "brepro" else "/INCREMENTAL:NO",
        "github_sha": "a" * 40,
        "cases": cases,
    }


class CorpusCrossRunTests(unittest.TestCase):
    def test_matching_sha_is_a_strict_pass(self):
        baseline = sample()
        result = compare_reports(baseline, copy.deepcopy(baseline), require_identical=True)
        self.assertEqual(result["identical_raw_build_count"], 8)
        self.assertEqual(result["different_cases"], [])

    def test_drift_reported_and_strictly_rejected(self):
        baseline = sample()
        second = copy.deepcopy(baseline)
        second["cases"][2]["sha256"] = "b" * 64
        result = compare_reports(baseline, second, require_identical=False)
        self.assertEqual(result["identical_raw_build_count"], 7)
        self.assertEqual(result["different_cases"], ["msvc-v3"])
        with self.assertRaises(AssertionError):
            compare_reports(baseline, second, require_identical=True)

    def test_mismatched_provenance_is_not_comparable(self):
        baseline = sample()
        second = copy.deepcopy(baseline)
        second["compilers"]["msvc"] = "new compiler"
        with self.assertRaisesRegex(ValueError, "provenance"):
            compare_reports(baseline, second, require_identical=False)

    def test_reject_missing_and_duplicate_case_ids(self):
        with tempfile.TemporaryDirectory() as work:
            file = Path(work) / "bad.json"
            report = sample()
            report["cases"][0]["id"] = report["cases"][1]["id"]
            file.write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                load_report(file, "brepro")
            report["cases"][0]["id"] = "msvc-v1"
            report["cases"][0]["sha256"] = "not-a-hash"
            file.write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "malformed"):
                load_report(file, "brepro")

    def test_artifact_zip_input_and_mode_boundary(self):
        with tempfile.TemporaryDirectory() as work:
            archive = Path(work) / "ci-artifact.zip"
            with zipfile.ZipFile(archive, "w") as z:
                z.writestr("rel-ex02-brepro-pairs.json", json.dumps(sample()))
            loaded = load_report(archive, "brepro")
            self.assertEqual(len(loaded["cases"]), 8)
            with self.assertRaisesRegex(ValueError, "expected exactly one"):
                load_report(archive, "standard")


if __name__ == "__main__":
    unittest.main()
