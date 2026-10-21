#!/usr/bin/env python3
"""Portable negative regressions for the independent structured PE oracle."""
from __future__ import annotations

import copy
import unittest

from scripts.check_windows_structured_probe import verify_manifest_evidence

HASH = "a" * 64
SECTIONS = [
    {"name": ".text", "offset": 1024, "size": 512, "virtual_address": 4096},
    {"name": ".rsrc", "offset": 1536, "size": 512, "virtual_address": 8192},
    {"name": ".reloc", "offset": 2048, "size": 512, "virtual_address": 12288},
]
IMPORTS = ["KERNEL32.dll!GetTickCount", "VCRUNTIME140.dll!memcpy"]
EXPORTS = ["rel_structured_pointer", "rel_structured_query"]


def sample() -> dict:
    return {
        "schema_version": "1.0.0", "format": "PE", "arch": "x86_64",
        "binary_sha256": HASH, "size_bytes": 4096,
        "sections": copy.deepcopy(SECTIONS),
        "imports": list(IMPORTS), "exports": list(EXPORTS), "warnings": [],
    }


def check(report: dict) -> None:
    verify_manifest_evidence(
        report, sha256=HASH, size_bytes=4096,
        sections=SECTIONS, imports=IMPORTS, exports=EXPORTS,
    )


class StructuredOracleCompletenessTests(unittest.TestCase):
    def test_complete_manifest_is_accepted(self):
        check(sample())

    def test_missing_text_or_altered_section_metadata_is_rejected(self):
        for mode in ("missing", "raw_offset", "virtual_address", "raw_size"):
            report = sample()
            if mode == "missing":
                report["sections"].pop(0)
            else:
                field = {"raw_offset": "offset", "virtual_address": "virtual_address",
                         "raw_size": "size"}[mode]
                report["sections"][0][field] += 1
            with self.subTest(mode=mode), self.assertRaisesRegex(
                AssertionError, "sections differ"
            ):
                check(report)

    def test_missing_or_extra_import_is_rejected(self):
        for mode in ("missing", "extra"):
            report = sample()
            if mode == "missing":
                report["imports"].clear()
            else:
                report["imports"].append("KERNEL32.dll!Other")
            with self.subTest(mode=mode), self.assertRaisesRegex(
                AssertionError, "imports differ"
            ):
                check(report)

    def test_missing_or_extra_export_is_rejected(self):
        for mode in ("missing", "extra"):
            report = sample()
            if mode == "missing":
                report["exports"].pop(0)
            else:
                report["exports"].append("unexpected_export")
            with self.subTest(mode=mode), self.assertRaisesRegex(
                AssertionError, "exports differ"
            ):
                check(report)

    def test_unreported_extraction_warning_is_rejected(self):
        report = sample()
        report["warnings"] = ["some data not decoded"]
        with self.assertRaisesRegex(AssertionError, "incomplete"):
            check(report)


if __name__ == "__main__":
    unittest.main()
