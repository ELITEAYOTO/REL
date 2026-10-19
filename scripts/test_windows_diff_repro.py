#!/usr/bin/env python3
"""Portable regressions for byte-difference diagnostics, without PE execution."""
import tempfile
import unittest
from pathlib import Path

from check_windows_diff_repro import CASE_NAMES, category, differing_ranges, snapshot


class ByteDifferenceTests(unittest.TestCase):
    def test_identical_input(self):
        self.assertEqual(differing_ranges(b"ABC", b"ABC"), [])

    def test_disjoint_ranges(self):
        self.assertEqual(differing_ranges(b"ABCDEF", b"ABXDYF"), [(2, 3), (4, 5)])

    def test_shorter_and_longer_tail(self):
        self.assertEqual(differing_ranges(b"ab", b"abcd"), [(2, 4)])
        self.assertEqual(differing_ranges(b"abcd", b"ab"), [(2, 4)])
        self.assertEqual(differing_ranges(b"", b"hello"), [(0, 5)])

    def test_region_assignment_from_first_build(self):
        regions = {
            "coff_timestamp_offset": 8,
            "debug_directory_timestamps": [{"offset": 105, "value": 123}],
            "sections": [{"name": ".text", "offset": 64, "size": 20}],
            "debug_blobs": [{"offset": 100, "size": 10}],
        }
        self.assertEqual(category(10, regions), "coff-timestamp")
        self.assertEqual(category(12, regions), "header-or-overlay")
        self.assertEqual(category(64, regions), "section:.text")
        self.assertEqual(category(83, regions), "section:.text")
        self.assertEqual(category(84, regions), "header-or-overlay")
        self.assertEqual(category(101, regions), "debug-data")
        self.assertEqual(category(106, regions), "debug-directory-timestamp")

    def test_capture_preserves_exact_raw_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "source"
            source.mkdir()
            target = Path(temp) / "snapshot"
            for name in CASE_NAMES:
                (source / name).write_bytes(b"MZ\x00\xff" + name.encode())
            for name in ("msvc-version.txt", "clang-cl-version.txt"):
                (source / name).write_text("compiler version\n", encoding="utf-8")
            snapshot(source, target)
            self.assertEqual(
                {p.name for p in target.iterdir()},
                {*CASE_NAMES, "msvc-version.txt", "clang-cl-version.txt"},
            )
            for name in CASE_NAMES:
                self.assertEqual((target / name).read_bytes(), (source / name).read_bytes())
            with self.assertRaises(FileExistsError):
                snapshot(source, target)


if __name__ == "__main__":
    unittest.main()
