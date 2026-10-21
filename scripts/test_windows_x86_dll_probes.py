#!/usr/bin/env python3
"""Portable negative regression tests for the controlled PE32 DLL oracle."""
from __future__ import annotations

import copy
import unittest

from scripts.check_windows_x86_dll_probes import (
    EXPECTED_DELAY_SYMBOL,
    EXPECTED_DELAY_WARNING,
    verify_delay_load_evidence,
    verify_manifest_evidence,
    verify_ordinal_import_evidence,
    EXPECTED_ORDINAL_WARNING,
    EXPECTED_NAMED_SYMBOL,
)

SECTIONS = [
    {"name": ".text", "offset": 1024, "size": 512, "virtual_address": 4096},
    {"name": ".rdata", "offset": 1536, "size": 512, "virtual_address": 8192},
]
IMPORTS = ["KERNEL32.dll!GetTickCount64", "KERNEL32.dll!SetLastError"]
EXPORTS = ["rel_dll_probe_transform", "rel_dll_probe_aux"]


def sample() -> dict:
    return {
        "sections": copy.deepcopy(SECTIONS), "imports": list(IMPORTS),
        "exports": list(EXPORTS), "warnings": [],
    }


def check(report: dict) -> None:
    verify_manifest_evidence(report, SECTIONS, IMPORTS, EXPORTS)


class CompleteX86DllOracleTests(unittest.TestCase):
    def test_accepts_complete_named_observation(self):
        check(sample())

    def test_rejects_missing_section_or_modified_raw_metadata(self):
        for mode in ("missing", "offset", "size", "virtual_address"):
            report = sample()
            if mode == "missing":
                report["sections"].pop()
            else:
                report["sections"][0][mode] += 1
            with self.subTest(mode=mode), self.assertRaisesRegex(
                AssertionError, "section table mismatch"
            ):
                check(report)

    def test_rejects_missing_or_extra_named_import(self):
        for mode in ("missing", "extra"):
            report = sample()
            if mode == "missing":
                report["imports"].pop()
            else:
                report["imports"].append("KERNEL32.dll!Unexpected")
            with self.subTest(mode=mode), self.assertRaisesRegex(
                AssertionError, "named import mismatch"
            ):
                check(report)

    def test_rejects_missing_or_extra_named_export(self):
        for mode in ("missing", "extra"):
            report = sample()
            if mode == "missing":
                report["exports"].pop()
            else:
                report["exports"].append("unexpected_export")
            with self.subTest(mode=mode), self.assertRaisesRegex(
                AssertionError, "named export mismatch"
            ):
                check(report)

    def test_rejects_extractors_with_warnings(self):
        report = sample()
        report["warnings"] = ["partial import enumeration"]
        with self.assertRaisesRegex(AssertionError, "has warnings"):
            check(report)
    def test_delay_import_oracle_rejects_missing_warning_and_false_completeness(self):
        baseline = {"imports": list(IMPORTS), "warnings": [EXPECTED_DELAY_WARNING]}
        verify_delay_load_evidence(baseline, IMPORTS, [EXPECTED_DELAY_SYMBOL])
        cases = [
            ({"imports": list(IMPORTS), "warnings": []},
             [EXPECTED_DELAY_SYMBOL]),
            ({"imports": list(IMPORTS), "warnings": ["unrelated"]},
             [EXPECTED_DELAY_SYMBOL]),
            ({"imports": list(IMPORTS) + [EXPECTED_DELAY_SYMBOL],
              "warnings": [EXPECTED_DELAY_WARNING]}, [EXPECTED_DELAY_SYMBOL]),
            (baseline, []),
            (baseline, ["other.dll!unexpected"]),
        ]
        for report, delayed in cases:
            with self.subTest(report=report, delayed=delayed), self.assertRaises(
                AssertionError
            ):
                verify_delay_load_evidence(report, IMPORTS, delayed)
    def test_real_ordinal_oracle_refuses_false_completeness(self):
        direct = list(IMPORTS) + ["rel-ordinal-target.dll!ORDINAL 42",
                                  EXPECTED_NAMED_SYMBOL]
        observed = {"imports": list(direct), "exports": [],
                    "warnings": [EXPECTED_ORDINAL_WARNING]}
        verify_ordinal_import_evidence(
            observed, direct, "rel-ordinal-target.dll!ORDINAL 42"
        )
        cases = [
            ({"imports": list(direct), "exports": [], "warnings": []},
             direct, "rel-ordinal-target.dll!ORDINAL 42"),
            ({"imports": list(direct), "exports": [],
              "warnings": ["unrelated warning"]},
             direct, "rel-ordinal-target.dll!ORDINAL 42"),
            ({"imports": list(direct[:-1]), "exports": [],
              "warnings": [EXPECTED_ORDINAL_WARNING]},
             direct, "rel-ordinal-target.dll!ORDINAL 42"),
            ({"imports": list(direct[:-1]), "exports": [],
              "warnings": [EXPECTED_ORDINAL_WARNING]},
             direct, "rel-ordinal-target.dll!ORDINAL 42"),
            ({"imports": list(direct) + ["rel-ordinal-target.dll!spurious"],
              "exports": [], "warnings": [EXPECTED_ORDINAL_WARNING]},
             direct, "rel-ordinal-target.dll!ORDINAL 42"),
            (observed, direct, "rel-ordinal-target.dll!ORDINAL 43"),
            (observed, direct, "rel-ordinal-target.dll!rel_ordinal_probe"),
        ]
        for manifest, expected, ordinal in cases:
            with self.subTest(ordinal=ordinal, manifest=manifest), self.assertRaises(
                AssertionError
            ):
                verify_ordinal_import_evidence(manifest, expected, ordinal)


if __name__ == "__main__":
    unittest.main()
