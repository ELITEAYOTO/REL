#!/usr/bin/env python3
"""Evidence-gate regressions with entirely synthetic JSON, no binary execution."""
from __future__ import annotations

import copy
import hashlib
import statistics
import sys
import time
import unittest

import psutil
from profile_resources import poll_child_with_usage

from check_measurement_evidence import build_evidence
from _internal.measurement_environment import fingerprint


def make_pair() -> tuple[dict, dict]:
    sha = hashlib.sha256(b"controlled-file").hexdigest()
    context = {
        "schema": "rel-measurement-context-v1",
        "platform": "Linux-example", "machine": "x86_64",
        "cpu_model_reported": "Synthetic CPU",
        "analyzer_binary_sha256": hashlib.sha256(b"analyzer").hexdigest(),
        "github_run_id": "123456", "github_run_attempt": "1",
        "rustc_version": "rustc-test-version",
    }
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
            "measurement_context": copy.deepcopy(context),
            "measurement_context_sha256": fingerprint(context),
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
            "measurement_context": copy.deepcopy(context),
            "measurement_context_sha256": fingerprint(context),
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

    def test_rejects_same_commit_different_ci_run(self) -> None:
        a, b = make_pair()
        context = b["environment"]["measurement_context"]
        context["github_run_id"] = "different-run"
        b["environment"]["measurement_context_sha256"] = fingerprint(context)
        with self.assertRaisesRegex(ValueError, "measurement context mismatch"):
            build_evidence(a, b)

    def test_rejects_same_fixtures_different_cpu(self) -> None:
        a, b = make_pair()
        context = b["environment"]["measurement_context"]
        context["cpu_model_reported"] = "Different CPU"
        b["environment"]["measurement_context_sha256"] = fingerprint(context)
        with self.assertRaisesRegex(ValueError, "measurement context mismatch"):
            build_evidence(a, b)

    def test_rejects_different_analyzer_binary_even_same_commit(self) -> None:
        a, b = make_pair()
        context = b["environment"]["measurement_context"]
        context["analyzer_binary_sha256"] = "c" * 64
        b["environment"]["measurement_context_sha256"] = fingerprint(context)
        with self.assertRaisesRegex(ValueError, "measurement context mismatch"):
            build_evidence(a, b)

    def test_rejects_forged_measurement_context_digest(self) -> None:
        a, b = make_pair()
        b["environment"]["measurement_context_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "invalid measurement context fingerprint"):
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

    def test_rejects_mingw_toolchain_provenance_drift(self) -> None:
        a, b = make_pair()
        a["results"][0]["toolchain_version"] = "GCC 13 | GNU ld 2.42"
        b["scenarios"][0]["toolchain_version"] = "GCC 14 | GNU ld 2.42"
        with self.assertRaisesRegex(ValueError, "input/provenance mismatch on toolchain_version"):
            build_evidence(a, b)

    def test_kernel_usage_valid_even_without_polling_samples(self) -> None:
        a, b = make_pair()
        case = b["scenarios"][0]
        for i, reading in enumerate(case["observations"]):
            reading["kernel_peak_rss_bytes"] = 3_000_000 + i * 4096
            reading["kernel_cpu_ms"] = float(i + 1)
        case["max_kernel_peak_rss_bytes"] = 3_008_192
        case["max_kernel_cpu_ms"] = 3.0
        case["observations"][1]["resource_samples"] = 0
        self.assertEqual(
            build_evidence(a, b, require_kernel_usage=True)["cases"][0]["kernel_usage_runs"], 3
        )
        case["max_kernel_peak_rss_bytes"] += 4096
        with self.assertRaisesRegex(ValueError, "inconsistent kernel peak RSS"):
            build_evidence(a, b)

    def test_rejects_incomplete_or_invalid_kernel_metrics(self) -> None:
        a, b = make_pair()
        case = b["scenarios"][0]
        for obs in case["observations"]:
            obs["kernel_peak_rss_bytes"] = 300_000
            obs["kernel_cpu_ms"] = 1.0
        case["max_kernel_peak_rss_bytes"] = 300_000
        case["max_kernel_cpu_ms"] = 1.0
        case["observations"][1].pop("kernel_cpu_ms")
        with self.assertRaisesRegex(ValueError, "missing per-run kernel usage"):
            build_evidence(a, b)
        case["observations"][1]["kernel_cpu_ms"] = -1.0
        with self.assertRaisesRegex(ValueError, "negative/zero"):
            build_evidence(a, b)
        case["observations"][1]["kernel_cpu_ms"] = 1.0
        case["observations"][1]["kernel_peak_rss_bytes"] = None
        with self.assertRaisesRegex(ValueError, "incomplete kernel usage pair"):
            build_evidence(a, b)

    def test_required_native_evidence_fails_closed_on_legacy_report(self) -> None:
        a, b = make_pair()
        with self.assertRaisesRegex(ValueError, "missing Linux kernel usage"):
            build_evidence(a, b, require_kernel_usage=True)

    def windows_pair(self):
        a, b = make_pair()
        for env in (a["environment"], b["environment"]):
            env["os"] = "Windows-example"
            env["measurement_context"]["platform"] = env["os"]
            env["measurement_context_sha256"] = fingerprint(env["measurement_context"])
        b["environment"]["windows_usage_method"] = (
            "windows-retained-handle-PeakWorkingSetSize-GetProcessTimes")
        case = b["scenarios"][0]
        for obs in case["observations"]:
            obs["windows_peak_working_set_bytes"] = 8_000_000
            obs["windows_cpu_ms"] = 3.5
        case["max_windows_peak_working_set_bytes"] = 8_000_000
        case["max_windows_cpu_ms"] = 3.5
        return a, b

    def test_windows_native_usage_independent_of_sampling(self):
        a, b = self.windows_pair()
        case = build_evidence(a, b, require_windows_usage=True)["cases"][0]
        self.assertEqual(case["windows_usage_runs"], 3)
        self.assertFalse(case["windows_usage_incomplete"])
        self.assertTrue(case["rss_observation_incomplete"])

    def test_windows_native_evidence_rejects_tampering(self):
        mutations = (
            lambda c: c.update(max_windows_peak_working_set_bytes=9),
            lambda c: c.update(max_windows_cpu_ms=99),
            lambda c: c["observations"][0].pop("windows_cpu_ms"),
            lambda c: c["observations"][0].update(windows_cpu_ms=None),
            lambda c: c["observations"][0].update(windows_cpu_ms=float("nan")),
            lambda c: c["observations"][0].update(windows_cpu_ms=-1),
            lambda c: c["observations"][0].update(windows_peak_working_set_bytes=True),
            lambda c: c["observations"][0].update(windows_peak_working_set_bytes=0),
        )
        for mutation in mutations:
            a, b = self.windows_pair()
            mutation(b["scenarios"][0])
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                build_evidence(a, b, require_windows_usage=True)

    def test_windows_method_and_required_coverage_fail_closed(self):
        a, b = self.windows_pair()
        b["environment"]["windows_usage_method"] = "sampled"
        with self.assertRaisesRegex(ValueError, "method/platform"):
            build_evidence(a, b)
        a, b = self.windows_pair()
        b["scenarios"][0]["observations"][0].update(
            windows_peak_working_set_bytes=None, windows_cpu_ms=None)
        with self.assertRaisesRegex(ValueError, "missing Windows native"):
            build_evidence(a, b, require_windows_usage=True)
        a, b = make_pair()
        with self.assertRaises(ValueError):
            build_evidence(a, b, require_windows_usage=True)

    @unittest.skipUnless(sys.platform == "linux", "Linux wait4 resource accounting only")
    def test_linux_wait4_reaps_short_lived_children_with_kernel_peaks(self) -> None:
        for code, expected in (
            ("data = bytearray(8000000); print(len(data))", 0),
            ("import sys; sys.exit(7)", 7),
        ):
            with self.subTest(expected_exit=expected):
                proc = psutil.Popen([sys.executable, "-c", code])
                deadline = time.monotonic() + 10
                try:
                    while True:
                        status, rss, cpu_ms = poll_child_with_usage(proc)
                        if status is not None:
                            break
                        if time.monotonic() > deadline:
                            self.fail("wait4 short-lived child timeout")
                        time.sleep(0.001)
                    self.assertEqual(status, expected)
                    self.assertGreater(rss, 0)
                    self.assertGreaterEqual(cpu_ms, 0)
                    # wait4 already reaped the child. A second psutil wait()
                    # may return None, so retain the exact status from wait4.
                    self.assertEqual(proc.returncode, expected)
                finally:
                    if proc.returncode is None:
                        proc.kill()
                        proc.wait()

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
