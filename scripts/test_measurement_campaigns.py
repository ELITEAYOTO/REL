#!/usr/bin/env python3
"""Controlled cross-run comparison tests; no compiled PE or CLI execution."""
from __future__ import annotations

import copy
import hashlib
import statistics
import unittest

from compare_measurement_campaigns import compare_campaigns
from measurement_environment import fingerprint
from test_measurement_evidence import make_pair


def campaign_pair() -> tuple[dict, dict, dict, dict]:
    """Create independent run IDs with identical observed hardware and PE."""
    a, b = make_pair()
    context = a["environment"]["measurement_context"]
    context.update({
        "kernel_release": "test-kernel", "logical_cpu_count_reported": 4,
        "host_ram_bytes_reported": 8 * 1024**3,
        "cargo_version": "cargo test", "python_version": "3.12",
        "psutil_version": "7.0.0",
    })
    for env in (a["environment"], b["environment"]):
        env["measurement_context"] = copy.deepcopy(context)
        env["measurement_context_sha256"] = fingerprint(context)
        env["samples"] = 5

    first = a["results"][0]
    first["all_ms"] = [1.0, 1.2, 1.5, 1.8, 2.0]
    first.update(
        iterations=5, median_ms=1.5, p95_ms=2.0, min_ms=1.0, max_ms=2.0
    )
    resource = b["scenarios"][0]
    resource["observations"] += [
        {"wall_ms": 2.0, "sampled_peak_rss_bytes": None,
         "last_sampled_cpu_ms": None, "resource_samples": 0},
        {"wall_ms": 2.2, "sampled_peak_rss_bytes": 170,
         "last_sampled_cpu_ms": 0.7, "resource_samples": 1},
    ]
    resource["wall_median_ms"] = statistics.median(
        observation["wall_ms"] for observation in resource["observations"]
    )
    resource["max_sampled_rss_bytes"] = 170
    resource["max_last_sampled_cpu_ms"] = 0.7

    c, d = copy.deepcopy(a), copy.deepcopy(b)
    for env in (c["environment"], d["environment"]):
        env["measurement_context"]["github_run_id"] = "654321"
        env["measurement_context_sha256"] = fingerprint(env["measurement_context"])
    second = c["results"][0]
    second["all_ms"] = [1.4, 1.6, 1.8, 2.0, 2.2]
    second.update(
        median_ms=1.8, p95_ms=2.2, min_ms=1.4, max_ms=2.2
    )
    return a, b, c, d


def change_context(a: dict, b: dict, field: str, value: object) -> None:
    for doc in (a, b):
        context = doc["environment"]["measurement_context"]
        context[field] = value
        doc["environment"]["measurement_context_sha256"] = fingerprint(context)


class CampaignComparisonTests(unittest.TestCase):
    def test_descriptive_same_environment_and_distinct_run(self) -> None:
        a, b, c, d = campaign_pair()
        result = compare_campaigns(a, b, c, d)
        self.assertEqual(result["status"], "descriptive_only")
        self.assertEqual(result["blockers"], [])
        self.assertEqual(len(result["cases"]), 1)
        self.assertEqual(result["cases"][0]["baseline_median_ms"], 1.5)
        self.assertEqual(result["cases"][0]["candidate_median_ms"], 1.8)
        self.assertAlmostEqual(result["cases"][0]["observed_median_ratio"], 1.2)

    def test_rejects_changed_compiler_without_ratios(self) -> None:
        a, b, c, d = campaign_pair()
        change_context(c, d, "rustc_version", "rustc other")
        result = compare_campaigns(a, b, c, d)
        self.assertEqual(result["status"], "not_comparable")
        self.assertEqual(result["cases"], [])
        self.assertIn("context mismatch: rustc_version", result["blockers"])

    def test_rejects_changed_cpu_and_host_ram(self) -> None:
        a, b, c, d = campaign_pair()
        change_context(c, d, "cpu_model_reported", "Different virtual processor")
        change_context(c, d, "host_ram_bytes_reported", 16 * 1024**3)
        result = compare_campaigns(a, b, c, d)
        self.assertIn("context mismatch: cpu_model_reported", result["blockers"])
        self.assertIn("context mismatch: host_ram_bytes_reported", result["blockers"])

    def test_rejects_binary_sha_mismatch(self) -> None:
        a, b, c, d = campaign_pair()
        change_context(c, d, "analyzer_binary_sha256", hashlib.sha256(b"new").hexdigest())
        result = compare_campaigns(a, b, c, d)
        self.assertIn("context mismatch: analyzer_binary_sha256", result["blockers"])

    def test_rejects_input_change_even_with_same_source_and_runner(self) -> None:
        a, b, c, d = campaign_pair()
        for doc in (c, d):
            doc["results" if "results" in doc else "scenarios"][0]["sha256"] = "f" * 64
        result = compare_campaigns(a, b, c, d)
        self.assertIn("pe32-reference: input/provenance mismatch: sha256", result["blockers"])

    def test_rejects_same_run_identity(self) -> None:
        a, b, c, d = campaign_pair()
        change_context(c, d, "github_run_id", "123456")
        result = compare_campaigns(a, b, c, d)
        self.assertIn("campaigns share the same run identity", result["blockers"])

    def test_rejects_missing_run_id(self) -> None:
        a, b, c, d = campaign_pair()
        change_context(c, d, "github_run_id", None)
        result = compare_campaigns(a, b, c, d)
        self.assertIn(
            "both campaigns require recorded run IDs and attempts", result["blockers"]
        )

    def test_rejects_mismatched_sampling_policy(self) -> None:
        a, b, c, d = campaign_pair()
        c["environment"]["warmup"] = 2
        d["environment"]["warmup"] = 2
        result = compare_campaigns(a, b, c, d)
        self.assertIn("timing policy mismatch: warmup", result["blockers"])

    def test_rejects_nonmatching_paired_context_before_comparison(self) -> None:
        a, b, c, d = campaign_pair()
        d["environment"]["measurement_context"]["github_run_id"] = "wrong"
        d["environment"]["measurement_context_sha256"] = fingerprint(
            d["environment"]["measurement_context"]
        )
        with self.assertRaisesRegex(ValueError, "measurement context mismatch"):
            compare_campaigns(a, b, c, d)

    def test_rejects_missing_cpu_model(self) -> None:
        a, b, c, d = campaign_pair()
        change_context(c, d, "cpu_model_reported", None)
        result = compare_campaigns(a, b, c, d)
        self.assertIn("candidate: missing observed cpu_model_reported", result["blockers"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
