#!/usr/bin/env python3
"""Self-contained cross-run evidence-validator regressions (no external packages)."""
import copy
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from compare_ex02_corpus_runs import (
    EXPECTED_PAIRS,
    MAX_EVIDENCE_BYTES,
    compare_reports,
    load_report,
)


def sample(mode="brepro"):
    cases = [
        {
            "id": f"{compiler}-v{variant}",
            "compiler": compiler,
            "variant": variant,
            "source_sha256": "f" * 64,
            "sha256": f"{variant + (10 if compiler == 'clang' else 0):064x}",
            "size_bytes": 1024,
            "import_count": variant,
            "export_count": variant,
        }
        for compiler in ("msvc", "clang")
        for variant in range(1, 5)
    ]
    pairs = [
        {
            "left": left,
            "right": right,
            "oracle": "pefile-independent-PE-structures",
            "import_added": [],
            "import_removed": [],
            "export_added": [],
            "export_removed": [],
            "section_status": "unchanged",
        }
        for left, right in sorted(EXPECTED_PAIRS)
    ]
    return {
        "schema_version": "rel-ex02-compiler-pair-evidence-v1",
        "source": "fixtures/probes/diff_version_probe.c",
        "source_sha256": "f" * 64,
        "compilers": {"msvc": "MSVC test", "clang": "clang test"},
        "linker_banner": "LINK 14.51 test",
        "build_environment": {
            "windows_sdk_version": "10.0.1",
            "vc_tools_version": "14.51",
            "image_os": "win25-vs2026",
            "image_version": "20261007.264.1",
        },
        "build_script": "scripts/build_windows_diff_pairs.cmd",
        "build_script_sha256": "a" * 64,
        "link_mode": mode,
        "link_flags": "/INCREMENTAL:NO /Brepro" if mode == "brepro" else "/INCREMENTAL:NO",
        "github_sha": "a" * 40,
        "case_count": len(cases),
        "pair_count": len(pairs),
        "cases": cases,
        "pairs": pairs,
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
        second = copy.deepcopy(baseline)
        second["build_environment"]["windows_sdk_version"] = "10.0.2"
        with self.assertRaisesRegex(ValueError, "provenance"):
            compare_reports(baseline, second, require_identical=True)
        second = copy.deepcopy(baseline)
        second["build_script_sha256"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "provenance"):
            compare_reports(baseline, second, require_identical=True)

    def test_missing_provenance_is_rejected_even_when_both_sides_omit_it(self):
        for key in (
            "source_sha256",
            "build_script_sha256",
            "linker_banner",
            "build_environment",
            "compilers",
        ):
            a = sample()
            b = sample()
            del a[key]
            del b[key]
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "provenance"):
                compare_reports(a, b, require_identical=True)

    def test_missing_sdk_image_or_compiler_version_is_rejected(self):
        for key in ("windows_sdk_version", "vc_tools_version", "image_os", "image_version"):
            a = sample()
            a["build_environment"][key] = None
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "provenance"):
                compare_reports(a, sample(), require_identical=True)
        a = sample()
        a["compilers"]["clang"] = ""
        with self.assertRaisesRegex(ValueError, "compiler version"):
            compare_reports(a, sample(), require_identical=True)

    def test_missing_link_mode_rejected_even_when_both_sides_omit_it(self):
        a = sample()
        b = sample()
        del a["link_mode"]
        del b["link_mode"]
        with self.assertRaisesRegex(ValueError, "linker mode"):
            compare_reports(a, b, require_identical=True)

    def test_invalid_linker_flags_rejected(self):
        a = sample()
        a["link_flags"] = "/INCREMENTAL:NO"
        with self.assertRaisesRegex(ValueError, "flags disagree"):
            compare_reports(a, sample(), require_identical=True)

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

    def test_reject_inconsistent_case_identity_and_source(self):
        for key, value in (
            ("compiler", "clang"),
            ("variant", 2),
            ("source_sha256", "0" * 64),
            ("import_count", -1),
            ("size_bytes", True),
        ):
            damaged = sample()
            damaged["cases"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                compare_reports(damaged, sample(), require_identical=True)

    def test_reject_missing_duplicate_and_corrupt_pair_observations(self):
        changed = sample()
        changed["pairs"] = changed["pairs"][:-1]
        with self.assertRaisesRegex(ValueError, "pair observations"):
            compare_reports(changed, sample(), require_identical=True)
        changed = sample()
        changed["pairs"][0] = copy.deepcopy(changed["pairs"][1])
        with self.assertRaisesRegex(ValueError, "A/B pair"):
            compare_reports(changed, sample(), require_identical=True)
        changed = sample()
        changed["pairs"][0]["import_added"] = ["Z!B", "A!A"]
        with self.assertRaisesRegex(ValueError, "noncanonical"):
            compare_reports(changed, sample(), require_identical=True)
        changed = sample()
        changed["pairs"][0]["import_added"] = ["X!Y"]
        changed["pairs"][0]["import_removed"] = ["X!Y"]
        with self.assertRaisesRegex(ValueError, "both added"):
            compare_reports(changed, sample(), require_identical=True)

    def test_reject_disagreeing_counts(self):
        changed = sample()
        changed["case_count"] = 7
        with self.assertRaisesRegex(ValueError, "case count"):
            compare_reports(changed, sample(), require_identical=True)
        changed = sample()
        changed["pair_count"] = 15
        with self.assertRaisesRegex(ValueError, "pair count"):
            compare_reports(changed, sample(), require_identical=True)

    def test_duplicate_json_keys_in_plain_and_zip_evidence(self):
        # Repeated keys could otherwise silently override provenance in json.loads.
        malformed = json.dumps(sample()).replace(
            '"schema_version": ', '"schema_version": "fake", "schema_version": ', 1
        )
        with tempfile.TemporaryDirectory() as work:
            plain = Path(work) / "duplicate.json"
            plain.write_text(malformed, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON object key"):
                load_report(plain, "brepro")
            archived = Path(work) / "duplicate.zip"
            with zipfile.ZipFile(archived, "w", compression=zipfile.ZIP_DEFLATED) as z:
                z.writestr("rel-ex02-brepro-pairs.json", malformed)
            with self.assertRaisesRegex(ValueError, "duplicate JSON object key"):
                load_report(archived, "brepro")

    def test_malformed_identity_type_is_not_accepted(self):
        report = sample()
        report["cases"][0]["id"] = ["msvc-v1"]
        with self.assertRaisesRegex(ValueError, "variant IDs"):
            compare_reports(report, sample(), require_identical=True)
        report = sample()
        report["pairs"][0]["left"] = ["msvc-v1"]
        with self.assertRaisesRegex(ValueError, "pair identity"):
            compare_reports(report, sample(), require_identical=True)

    def test_standard_linker_mode_cannot_request_strict_gate_directly(self):
        with self.assertRaisesRegex(ValueError, "requires /Brepro"):
            compare_reports(sample("standard"), sample("standard"), require_identical=True)

    def test_conflicting_metadata_for_identical_raw_pe_is_rejected(self):
        for field in ("import_count", "export_count"):
            changed = sample()
            changed["cases"][0][field] += 1
            with self.subTest(field=field), self.assertRaisesRegex(
                ValueError, "conflicting"
            ):
                compare_reports(sample(), changed, require_identical=True)
        changed = sample()
        changed["pairs"][0]["import_added"] = ["KERNEL32.dll!Other"]
        with self.assertRaisesRegex(ValueError, "conflicting oracle"):
            compare_reports(sample(), changed, require_identical=True)

    def test_an_actual_binary_change_does_not_assert_same_oracle(self):
        changed = sample()
        changed["cases"][0]["sha256"] = "b" * 64
        affected = next(
            pair for pair in changed["pairs"] if pair["left"] == "msvc-v1"
        )
        affected["import_added"] = ["KERNEL32.dll!Other"]
        result = compare_reports(sample(), changed, require_identical=False)
        self.assertEqual(result["different_cases"], ["msvc-v1"])


    def test_identical_sha_within_one_report_requires_consistent_evidence(self):
        report = sample()
        # Simulate two compiler variants that emitted byte-identical PEs.
        report["cases"][1]["sha256"] = report["cases"][0]["sha256"]
        report["cases"][1]["import_count"] = report["cases"][0]["import_count"]
        report["cases"][1]["export_count"] = report["cases"][0]["export_count"]
        accepted = compare_reports(report, copy.deepcopy(report), require_identical=True)
        self.assertEqual(accepted["identical_raw_build_count"], 8)

        for field in ("size_bytes", "import_count", "export_count"):
            malformed = copy.deepcopy(report)
            malformed["cases"][1][field] += 1
            with self.subTest(field=field), self.assertRaisesRegex(
                ValueError, "identical raw PE"
            ):
                compare_reports(malformed, copy.deepcopy(malformed), require_identical=True)

        for field in (
            "import_added", "import_removed", "export_added", "export_removed",
            "section_status",
        ):
            malformed = copy.deepcopy(report)
            pair = next(
                item for item in malformed["pairs"]
                if (item["left"], item["right"]) == ("msvc-v1", "msvc-v2")
            )
            pair[field] = "changed" if field == "section_status" else ["KERNEL32.dll!X"]
            with self.subTest(field=field), self.assertRaisesRegex(
                ValueError, "contradictory delta for identical raw PE"
            ):
                compare_reports(malformed, copy.deepcopy(malformed), require_identical=True)

    def test_report_source_and_version_must_match_known_contract(self):
        changed = sample()
        changed["source"] = "different-source.c"
        with self.assertRaisesRegex(ValueError, "source identity"):
            compare_reports(sample(), changed, require_identical=True)
        changed = sample()
        changed["schema_version"] = "some-other-schema"
        with self.assertRaisesRegex(ValueError, "version"):
            compare_reports(sample(), changed, require_identical=True)

    def test_reject_oversized_json_and_decompressed_zip_evidence(self):
        oversized = b" " * (MAX_EVIDENCE_BYTES + 1)
        with tempfile.TemporaryDirectory() as work:
            plain = Path(work) / "oversized.json"
            plain.write_bytes(oversized)
            with self.assertRaisesRegex(ValueError, "2 MiB"):
                load_report(plain, "brepro")
            archive = Path(work) / "oversized.zip"
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as z:
                z.writestr("rel-ex02-brepro-pairs.json", oversized)
            with self.assertRaisesRegex(ValueError, "2 MiB"):
                load_report(archive, "brepro")

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
