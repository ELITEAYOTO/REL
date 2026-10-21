#!/usr/bin/env python3
"""Unit regressions for EX-02 resource-profile output identity accounting."""
from __future__ import annotations

import unittest

from profile_manifest_diff import summarize


class ProfileResultTests(unittest.TestCase):
    @staticmethod
    def sample(report_bytes: int = 100, digest: str = "a" * 64) -> dict:
        return {
            "wall_ms": 3.0,
            "report_bytes": report_bytes,
            "report_sha256": digest,
            "sampled_peak_rss_bytes": 4096,
            "kernel_peak_rss_bytes": None,
            "kernel_cpu_ms": None,
            "windows_peak_working_set_bytes": None,
            "windows_cpu_ms": None,
        }

    def test_identical_bytes_and_digest_produce_stable_summary(self) -> None:
        result = summarize([self.sample(), self.sample(), self.sample()])
        self.assertEqual(result["report_bytes"], 100)
        self.assertEqual(result["report_sha256"], "a" * 64)
        self.assertEqual(result["max_sampled_rss_bytes"], 4096)

    def test_lifetime_usage_maxima_and_missing_platform_stay_distinct(self) -> None:
        first = self.sample()
        first.update(kernel_peak_rss_bytes=12_288, kernel_cpu_ms=2.0)
        second = self.sample()
        second.update(kernel_peak_rss_bytes=24_576, kernel_cpu_ms=0.0)
        summary = summarize([first, second])
        self.assertEqual(summary["max_kernel_peak_rss_bytes"], 24_576)
        self.assertEqual(summary["max_kernel_cpu_ms"], 2.0)
        self.assertIsNone(summary["max_windows_peak_working_set_bytes"])
        self.assertIsNone(summary["max_windows_cpu_ms"])

        windows = self.sample()
        windows.update(windows_peak_working_set_bytes=65_536, windows_cpu_ms=4.0)
        windows_summary = summarize([windows, windows])
        self.assertEqual(windows_summary["max_windows_peak_working_set_bytes"], 65_536)
        self.assertEqual(windows_summary["max_windows_cpu_ms"], 4.0)
        self.assertIsNone(windows_summary["max_kernel_peak_rss_bytes"])
        self.assertIsNone(windows_summary["max_kernel_cpu_ms"])

    def test_inconsistent_output_length_fails(self) -> None:
        with self.assertRaisesRegex(AssertionError, "different report bytes"):
            summarize([self.sample(), self.sample(101)])

    def test_same_length_but_different_json_fails(self) -> None:
        with self.assertRaisesRegex(AssertionError, "different report bytes"):
            summarize([self.sample(), self.sample(digest="b" * 64)])


if __name__ == "__main__":
    unittest.main(verbosity=2)
