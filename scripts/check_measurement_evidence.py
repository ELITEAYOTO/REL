#!/usr/bin/env python3
"""Fail-closed integrity gate for paired CLI and sampled-resource observations.

This is an evidence-quality check, not a performance threshold or sandbox.
Never executes inspected PE files; only reads existing JSON observations.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import statistics

from _internal.measurement_environment import fingerprint
from pathlib import Path

CASE_FIELDS = (
    "case_id", "kind", "source_fixture", "source_sha256", "provenance",
    "redistribution_status", "toolchain_version", "resource_source",
    "resource_sha256", "size_bytes", "sha256",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def measured(value: object, label: str, *, positive: bool = False) -> float:
    require(
        type(value) in (int, float) and math.isfinite(value),
        f"{label}: non-finite or non-numeric value",
    )
    number = float(value)
    require(number > 0 if positive else number >= 0, f"{label}: negative/zero value")
    return number


def index_cases(records: object, label: str) -> dict[str, dict]:
    require(isinstance(records, list) and records, f"{label}: no cases")
    indexed: dict[str, dict] = {}
    for case in records:
        require(isinstance(case, dict), f"{label}: case is not an object")
        name = case.get("case_id")
        require(isinstance(name, str) and name, f"{label}: missing case_id")
        require(name not in indexed, f"{label}: duplicate case_id {name}")
        indexed[name] = case
    return indexed


def validate_timing(case: dict, samples: int, name: str) -> float:
    values = case.get("all_ms")
    require(isinstance(values, list) and len(values) == samples,
            f"{name}: benchmark sample count mismatch")
    ordered = sorted(measured(x, f"{name}.all_ms", positive=True) for x in values)
    require(case.get("iterations") == samples, f"{name}: iteration count mismatch")
    expected = {
        "median_ms": statistics.median(ordered),
        "p95_ms": ordered[max(0, math.ceil(samples * 0.95) - 1)],
        "min_ms": ordered[0],
        "max_ms": ordered[-1],
    }
    for field, value in expected.items():
        reported = measured(case.get(field), f"{name}.{field}", positive=True)
        require(abs(reported - value) <= 0.00011,
                f"{name}: inconsistent benchmark {field}")
    return (ordered[-1] - ordered[0]) / statistics.median(ordered)


def validate_resources(case: dict, samples: int, name: str) -> tuple[int, int]:
    observations = case.get("observations")
    require(isinstance(observations, list) and len(observations) == samples,
            f"{name}: resource sample count mismatch")
    walls: list[float] = []
    rss: list[int] = []
    cpus: list[float] = []
    for observation in observations:
        require(isinstance(observation, dict), f"{name}: invalid observation")
        walls.append(measured(observation.get("wall_ms"), f"{name}.wall", positive=True))
        count = observation.get("resource_samples")
        require(type(count) is int and count >= 0, f"{name}: invalid polling count")
        memory = observation.get("sampled_peak_rss_bytes")
        cpu = observation.get("last_sampled_cpu_ms")
        if memory is not None:
            require(type(memory) is int and memory >= 0 and count > 0,
                    f"{name}: invalid sampled RSS")
            rss.append(memory)
        if cpu is not None:
            cpus.append(measured(cpu, f"{name}.cpu"))
            require(count > 0, f"{name}: CPU recorded without sampling")
    expected_wall = statistics.median(walls)
    require(abs(measured(case.get("wall_median_ms"), f"{name}.wall_median") -
                expected_wall) <= 0.00011, f"{name}: inconsistent wall median")
    require(case.get("max_sampled_rss_bytes") == (max(rss) if rss else None),
            f"{name}: inconsistent sampled RSS maximum")
    reported_cpu = case.get("max_last_sampled_cpu_ms")
    if cpus:
        require(abs(measured(reported_cpu, f"{name}.max_cpu") - max(cpus)) <= 0.00011,
                f"{name}: inconsistent last-sampled CPU maximum")
    else:
        require(reported_cpu is None, f"{name}: CPU maximum without samples")
    return len(rss), len(cpus)


def build_evidence(benchmark: dict, resource: dict, expected_cases: int | None = None) -> dict:
    bench_env = benchmark["environment"]
    res_env = resource["environment"]
    require(bench_env["kind"] == "rel-cli-benchmark-v1", "wrong benchmark format")
    require(res_env["schema"] == "rel-resource-observations-v1", "wrong resource format")
    for left, right in (
        ("os", "os"), ("machine", "machine"), ("binary", "analyzer"),
        ("commit", "git_sha"), ("corpus_policy", "corpus_policy"),
    ):
        require(bench_env.get(left) == res_env.get(right),
                f"environment mismatch: {left}/{right}")
    require(bench_env.get("commit") is None or
            bool(re.fullmatch(r"[a-f0-9]{40}", bench_env["commit"])),
            "invalid non-null commit ID")
    for label, environment in (("benchmark", bench_env), ("resources", res_env)):
        context = environment.get("measurement_context")
        require(isinstance(context, dict), f"{label}: missing measurement context")
        require(context.get("schema") == "rel-measurement-context-v1",
                f"{label}: invalid measurement context schema")
        require(context.get("platform") == environment.get("os") and
                context.get("machine") == environment.get("machine"),
                f"{label}: hardware platform mismatch")
        digest = context.get("analyzer_binary_sha256")
        require(isinstance(digest, str) and re.fullmatch(r"[a-f0-9]{64}", digest) is not None,
                f"{label}: invalid analyzer binary SHA-256")
        require(environment.get("measurement_context_sha256") == fingerprint(context),
                f"{label}: invalid measurement context fingerprint")
    require(bench_env["measurement_context"] == res_env["measurement_context"],
            "measurement context mismatch across tools")
    require(bench_env.get("warmup") == res_env.get("warmup"),
            "warmup policy mismatch")
    bench_samples, resource_samples = bench_env["samples"], res_env["samples"]
    require(type(bench_samples) is int and bench_samples >= 3,
            "benchmark sample count below minimum")
    require(type(resource_samples) is int and resource_samples >= 2,
            "resource sample count below minimum")

    bench_cases = index_cases(benchmark["results"], "benchmark")
    res_cases = index_cases(resource["scenarios"], "resources")
    require(bench_cases.keys() == res_cases.keys(), "case inventory mismatch")
    if expected_cases is not None:
        require(len(bench_cases) == expected_cases,
                f"unexpected corpus size: {len(bench_cases)} (wanted {expected_cases})")
    paired = []
    for name in sorted(bench_cases):
        bcase, rcase = bench_cases[name], res_cases[name]
        for field in CASE_FIELDS:
            if field not in ("toolchain_version", "resource_source", "resource_sha256"):
                require(field in bcase and field in rcase,
                        f"{name}: missing required {field}")
            require(bcase.get(field) == rcase.get(field),
                    f"{name}: input/provenance mismatch on {field}")
        digest = bcase["sha256"]
        require(isinstance(digest, str) and re.fullmatch(r"[a-f0-9]{64}", digest) is not None,
                f"{name}: invalid binary sha256")
        require(type(bcase["size_bytes"]) is int and bcase["size_bytes"] > 0,
                f"{name}: invalid input size")
        spread = validate_timing(bcase, bench_samples, name)
        rss_count, cpu_count = validate_resources(rcase, resource_samples, name)
        paired.append({
            "case_id": name, "sha256": digest,
            "benchmark_relative_wall_spread": round(spread, 6),
            "rss_sampled_runs": rss_count,
            "cpu_sampled_runs": cpu_count,
            "resource_runs": resource_samples,
            "rss_observation_incomplete": rss_count < resource_samples,
            "cpu_observation_incomplete": cpu_count < resource_samples,
        })
    return {
        "schema": "rel-measurement-evidence-v1",
        "interpretation": "integrity and observation coverage only; no performance threshold",
        "environment": {
            "os": bench_env["os"], "machine": bench_env["machine"],
            "commit": bench_env.get("commit"),
            "measurement_context_sha256": bench_env["measurement_context_sha256"],
            "measurement_context": bench_env["measurement_context"],
            "benchmark_samples": bench_samples, "resource_samples": resource_samples,
        },
        "cases": paired,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark", required=True, type=Path)
    parser.add_argument("--resources", required=True, type=Path)
    parser.add_argument("--expected-cases", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not 1 <= args.expected_cases <= 1000:
        parser.error("--expected-cases must be between 1 and 1000")
    try:
        benchmark = json.loads(args.benchmark.read_text(encoding="utf-8"))
        resources = json.loads(args.resources.read_text(encoding="utf-8"))
        result = build_evidence(benchmark, resources, args.expected_cases)
        payload = json.dumps(result, indent=2, allow_nan=False) + "\n"
        with args.output.open("x", encoding="utf-8") as output:
            output.write(payload)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
