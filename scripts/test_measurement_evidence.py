#!/usr/bin/env python3
"""Evidence-gate regressions with entirely synthetic JSON, no binary execution."""
from __future__ import annotations

import copy
import hashlib
import statistics
import unittest

from check_measurement_evidence import build_evidence


def make_pair() -> tuple[dict, dict]:
    sha = hashlib.sha256(b"controlled-file").hexdigest()
    shared = {
        "case_id": "pe32-reference", "kind": "synthetic-fixture",
        "source_fixture": "pe32-basic.exe", "source_sha256": "b" * 64,
        "provenance": "tracked-rel-synthetic",
        "redistribution_status": "not-established",
        "size_bytes": 2048, "sha256": sha,
    }
    benchmark = {
        "environment": {
            "kind": "rel-cli-benchmark-v1", "os": "Linux-example",
            "machine": "x86_64", "binary": "rel-inspect", "commit": "a" * 40,
            "corpus_policy": "docs/security/P15A_CORPUS_PROVENANCE.md",
            "warmup": 1, "samples": 3,
        },
        "results": [{**shared, "iterations": 3,
                     "all_ms": [1.0, 1.5, 2.0],
                     "median_ms": 1.5, "p95_ms": 2.0,
                     "min_ms": 1.0, "max_ms": 2.0}],
    }
    observations = [
        {"wall_ms": 1.0, "sampled_peak_rss_bytes": 120,
         "last_sampled_cpu_ms": 0.5, "resource_samples": 2},
        {"wall_ms": 1.4, "sampled_peak_rss_bytes": None,
         "last_sampled_cpu_ms": None, "resource_samples": 0},
        {"wall_ms": 1.8, "sampled_peak_rss_bytes": 150,
         "last_sampled_cpu_ms": 0.6, "resource_samples": 2},
    ]
    resources = {
        "environment": {
            "schema": "rel-resource-observations-v1", "os": "Linux-example",
            "machine": "x86_64", "analyzer": "rel-inspect", "git_sha": "a" * 40,
            "corpus_policy": "docs/security/P15A_CORPUS_PROVENANCE.md",
            "warmup": 1, "samples": 3,
        },
        "scenarios": [{
            **shared, "observations": observations,
            "wall_median_ms": statistics.median(x["wall_ms"] for x in observations),
            "max_sampled_rss_bytes": 150, "max_last_sampled_cpu_ms": 0.6,
        }],
    }
    return benchmark, resources


class EvidenceGateTests(unittest.TestCase):
    def test_paired_evidence_preserves_missing_rss_as_missing(self) -> None:
        a, b = make_pair()
        report = build_evidence(a, b, expected_cases=1)
        self.assertEqual(report["schema"], "rel-measurement-evidence-v1")
        case = report["cases"][0]
        self.assertEqual(case["rss_sampled_runs"], 2)
        self.assertEqual(case["cpu_sampled_runs"], 2)
        self.assertTrue(case["rss_observation_incomplete"])
        self.assertAlmostEqual(case["benchmark_relative_wall_spread"], 2 / 3, places=5)

    def test_rejects_missing_case_without_zero_padding(self) -> None:
        a, b = make_pair()
        b["scenarios"] = []
        with self.assertRaisesRegex(ValueError, "no cases"):
            build_evidence(a, b)

    def test_rejects_mismatched_binary_sha(self) -> None:
        a, b = make_pair()
        b["scenarios"][0]["sha256"] = "c" * 64
        with self.assertRaisesRegex(ValueError, "input/provenance mismatch on sha256"):
            build_evidence(a, b)

    def test_rejects_duplicate_cases(self) -> None:
        a, b = make_pair()
        a["results"].append(copy.deepcopy(a["results"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate case_id"):
            build_evidence(a, b)

    def test_rejects_corrupt_timing_aggregate(self) -> None:
        a, b = make_pair()
        a["results"][0]["median_ms"] = 90
        with self.assertRaisesRegex(ValueError, "inconsistent benchmark median"):
            build_evidence(a, b)

    def test_rejects_corrupt_resource_aggregate(self) -> None:
        a, b = make_pair()
        b["scenarios"][0]["max_sampled_rss_bytes"] = 5000
        with self.assertRaisesRegex(ValueError, "inconsistent sampled RSS maximum"):
            build_evidence(a, b)

    def test_rejects_nonfinite_observation(self) -> None:
        a, b = make_pair()
        b["scenarios"][0]["observations"][0]["last_sampled_cpu_ms"] = float("nan")
        with self.assertRaisesRegex(ValueError, "non-finite"):
            build_evidence(a, b)

    def test_rejects_cpu_observation_without_polling(self) -> None:
        a, b = make_pair()
        b["scenarios"][0]["observations"][1]["last_sampled_cpu_ms"] = 0
        with self.assertRaisesRegex(ValueError, "CPU recorded without sampling"):
            build_evidence(a, b)

    def test_rejects_environment_mismatch(self) -> None:
        a, b = make_pair()
        b["environment"]["machine"] = "arm64"
        with self.assertRaisesRegex(ValueError, "environment mismatch"):
            build_evidence(a, b)

    def test_rejects_corpus_count_drift(self) -> None:
        a, b = make_pair()
        with self.assertRaisesRegex(ValueError, "unexpected corpus size"):
            build_evidence(a, b, expected_cases=11)

    def test_rejects_optional_source_hash_drift(self) -> None:
        a, b = make_pair()
        a["results"][0]["resource_sha256"] = "d" * 64
        b["scenarios"][0]["resource_sha256"] = "e" * 64
        with self.assertRaisesRegex(ValueError, "input/provenance mismatch on resource_sha256"):
            build_evidence(a, b)

    def test_rejects_sample_count_mismatch(self) -> None:
        a, b = make_pair()
        a["results"][0]["all_ms"].pop()
        with self.assertRaisesRegex(ValueError, "sample count mismatch"):
            build_evidence(a, b)


if __name__ == "__main__":
    unittest.main(verbosity=2)
