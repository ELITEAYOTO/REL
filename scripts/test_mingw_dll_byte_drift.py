#!/usr/bin/env python3
"""Pure, portable regressions for same-job MinGW-w64 DLL byte diagnostics."""
from __future__ import annotations

import unittest

from scripts.check_mingw_dll_byte_drift import describe_differences


REGIONS = {
    "coff_timestamp_offset": 4,
    "debug_directory_timestamps": [{"offset": 16, "value": 123}],
    "sections": [{"name": ".text", "offset": 8, "size": 6}],
    "debug_blobs": [],
}


class MinGWDriftTests(unittest.TestCase):
    def test_identical_bytes_are_not_reported_as_timestamp_drifts(self):
        result = describe_differences(b"x" * 25, b"x" * 25, REGIONS)
        self.assertTrue(result["raw_byte_identical"])
        self.assertFalse(result["only_timestamp_field_bytes_changed"])
        self.assertEqual(result["changed_byte_count"], 0)

    def test_two_timestamp_fields_are_scoped_correctly(self):
        first = bytearray(b"x" * 25)
        second = bytearray(first)
        second[5] = ord("y")
        second[18] = ord("y")
        result = describe_differences(first, second, REGIONS)
        self.assertEqual(result["changed_byte_count"], 2)
        self.assertTrue(result["only_timestamp_field_bytes_changed"])
        self.assertEqual(result["changed_bytes_by_first_file_region"], {
            "coff-timestamp": 1, "debug-directory-timestamp": 1,
        })

    def test_non_timestamp_section_change_is_not_misclassified(self):
        first = bytearray(b"x" * 25)
        second = bytearray(first)
        second[9] = ord("y")
        result = describe_differences(first, second, REGIONS)
        self.assertFalse(result["only_timestamp_field_bytes_changed"])
        self.assertEqual(result["changed_bytes_by_first_file_region"], {
            "section:.text": 1,
        })

    def test_trailing_bytes_count_but_are_not_causally_explained(self):
        result = describe_differences(b"x" * 25, b"x" * 27, REGIONS)
        self.assertEqual(result["changed_byte_count"], 2)
        self.assertEqual(result["changed_range_count"], 1)
        self.assertEqual(result["changed_bytes_by_first_file_region"], {
            "header-or-overlay": 2,
        })


if __name__ == "__main__":
    unittest.main()
