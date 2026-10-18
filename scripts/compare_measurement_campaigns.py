#!/usr/bin/env python3
"""Compare independent measurement campaigns only when evidence is compatible.

This is a descriptive, abstaining offline tool. It does not execute REL or any
PE and never establishes performance or security limits from hosted CI runs.
"""
from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path

from check_measurement_evidence import CASE_FIELDS, build_evidence, index_cases

SESSION_FIELDS = frozenset(("github_run_id", "github_run_attempt"))
REQUIRED_OBSERVED = (
    "platform", "machine", "kernel_release", "cpu_model_reported",
    "logical_cpu_count_reported", "host_ram_bytes_reported",
    "rustc_version", "cargo_version", "python_version", "psutil_version",
    "analyzer_binary_sha256",
)


def context_differences(base: dict, candidate: dict) -> list[str]:
    """Strict comparison of every recorded field except the distinct run IDs."""
    issues = []
    for field in REQUIRED_OBSERVED:
        for label, context in (("baseline", base), ("candidate", candidate)):
            if context.get(field) is None or context.get(field) == "":
                issues.append(f"{label}: missing observed {field}")

    for key in sorted((base.keys() | candidate.keys()) - SESSION_FIELDS):
        if key not in base or key not in candidate:
            issues.append(f"context field missing: {key}")
        elif base[key] != candidate[key]:
            issues.append(f"context mismatch: {key}")
    return issues


def compatibility_issues(
    baseline_benchmark: dict, baseline_resource: dict,
    candidate_benchmark: dict, candidate_resource: dict,
) -> list[str]:
    """Validate each job's reports, then require matching input and build facts."""
    # This validates full per-job provenance, sample counts and aggregates.
    build_evidence(baseline_benchmark, baseline_resource)
    build_evidence(candidate_benchmark, candidate_resource)

    base_env = baseline_benchmark["environment"]
    new_env = candidate_benchmark["environment"]
    base_ctx, new_ctx = base_env["measurement_context"], new_env["measurement_context"]
    issues = context_differences(base_ctx, new_ctx)

    run_base = (base_ctx.get("github_run_id"), base_ctx.get("github_run_attempt"))
    run_new = (new_ctx.get("github_run_id"), new_ctx.get("github_run_attempt"))
    if not all(isinstance(x, str) and x for x in (*run_base, *run_new)):
        issues.append("both campaigns require recorded run IDs and attempts")
    elif run_base == run_new:
        issues.append("campaigns share the same run identity")

    for field in ("warmup", "samples", "corpus_policy"):
        if base_env.get(field) != new_env.get(field):
            issues.append(f"timing policy mismatch: {field}")
    if base_env.get("samples", 0) < 5 or new_env.get("samples", 0) < 5:
        issues.append("at least five timing samples per case are required")
    if baseline_resource["environment"].get("samples") != (
        candidate_resource["environment"].get("samples")
    ):
        issues.append("resource sample policy mismatch")
    if baseline_resource["environment"].get("samples", 0) < 5:
        issues.append("at least five resource samples per case are required")

    base_cases = index_cases(baseline_benchmark["results"], "baseline")
    new_cases = index_cases(candidate_benchmark["results"], "candidate")
    if base_cases.keys() != new_cases.keys():
        issues.append("case inventory mismatch")
    for name in sorted(base_cases.keys() & new_cases.keys()):
        for field in CASE_FIELDS:
            if base_cases[name].get(field) != new_cases[name].get(field):
                issues.append(f"{name}: input/provenance mismatch: {field}")
    return sorted(set(issues))


def compare_campaigns(
    baseline_benchmark: dict, baseline_resource: dict,
    candidate_benchmark: dict, candidate_resource: dict,
) -> dict:
    """Refuse ratios unless recorded environments, samples and inputs agree."""
    issues = compatibility_issues(
        baseline_benchmark, baseline_resource,
        candidate_benchmark, candidate_resource,
    )
    a_ctx = baseline_benchmark["environment"]["measurement_context"]
    b_ctx = candidate_benchmark["environment"]["measurement_context"]
    report = {
        "schema": "rel-measurement-campaign-comparison-v1",
        "interpretation": (
            "descriptive timing distributions only; hosted runner identity "
            "is not attested and no performance regression threshold is implied"
        ),
        "status": "not_comparable" if issues else "descriptive_only",
        "blockers": issues,
        "baseline_run": [a_ctx.get("github_run_id"), a_ctx.get("github_run_attempt")],
        "candidate_run": [b_ctx.get("github_run_id"), b_ctx.get("github_run_attempt")],
        "cases": [],
    }
    if issues:
        return report

    base_cases = index_cases(baseline_benchmark["results"], "baseline")
    new_cases = index_cases(candidate_benchmark["results"], "candidate")
    for name in sorted(base_cases):
        old_times = sorted(base_cases[name]["all_ms"])
        new_times = sorted(new_cases[name]["all_ms"])
        old_median, new_median = statistics.median(old_times), statistics.median(new_times)
        report["cases"].append({
            "case_id": name,
            "binary_sha256": base_cases[name]["sha256"],
            "baseline_samples": len(old_times),
            "candidate_samples": len(new_times),
            "baseline_median_ms": round(old_median, 4),
            "candidate_median_ms": round(new_median, 4),
            "observed_median_delta_ms": round(new_median - old_median, 4),
            "observed_median_ratio": round(new_median / old_median, 6),
            "baseline_min_max_ms": [old_times[0], old_times[-1]],
            "candidate_min_max_ms": [new_times[0], new_times[-1]],
        })
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("baseline-benchmark", "baseline-resources",
                 "candidate-benchmark", "candidate-resources"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        docs = [
            json.loads(getattr(args, x).read_text(encoding="utf-8"))
            for x in (
                "baseline_benchmark", "baseline_resources",
                "candidate_benchmark", "candidate_resources",
            )
        ]
        report = compare_campaigns(*docs)
        with args.output.open("x", encoding="utf-8") as output:
            json.dump(report, output, indent=2, allow_nan=False)
            output.write("\n")
    except (OSError, ValueError, KeyError, TypeError, ZeroDivisionError) as exc:
        parser.error(str(exc))
    if report["status"] == "not_comparable":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
