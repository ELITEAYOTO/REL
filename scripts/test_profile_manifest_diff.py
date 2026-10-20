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
        }

    def test_identical_bytes_and_digest_produce_stable_summary(self) -> None:
        result = summarize([self.sample(), self.sample(), self.sample()])
        self.assertEqual(result["report_bytes"], 100)
        self.assertEqual(result["report_sha256"], "a" * 64)
        self.assertEqual(result["max_sampled_rss_bytes"], 4096)

    def test_inconsistent_output_length_fails(self) -> None:
        with self.assertRaisesRegex(AssertionError, "different report bytes"):
            summarize([self.sample(), self.sample(101)])

    def test_same_length_but_different_json_fails(self) -> None:
        with self.assertRaisesRegex(AssertionError, "different report bytes"):
            summarize([self.sample(), self.sample(digest="b" * 64)])


if __name__ == "__main__":
    unittest.main(verbosity=2)
