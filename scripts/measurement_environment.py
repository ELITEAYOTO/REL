#!/usr/bin/env python3
"""Stable-in-one-job measurement environment identity (not a hardware attestation).

The fingerprint pairs *observations made on the same CI job*. It is not a
cross-machine performance score, a runner specification or a security boundary.
No inspected PE is executed by this module.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
from pathlib import Path

import psutil


def fingerprint(context: dict) -> str:
    """Hash canonical JSON including explicit nulls for unknown properties."""
    payload = json.dumps(
        context, sort_keys=True, ensure_ascii=True,
        separators=(",", ":"), allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def compiler_version(command: str) -> str | None:
    try:
        result = subprocess.run(
            [command, "--version"], capture_output=True, text=True,
            check=False, timeout=8,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return (result.stdout.splitlines() or [None])[0]


def cpu_model() -> str | None:
    """Read a *reported* CPU model, without assuming virtual hardware identity."""
    if os.name == "nt":
        return os.environ.get("PROCESSOR_IDENTIFIER") or platform.processor() or None
    if platform.system() == "Linux":
        try:
            for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
                if line.lower().startswith("model name") and ":" in line:
                    return line.split(":", 1)[1].strip() or None
        except OSError:
            pass
    return platform.processor() or None


def binary_sha256(binary: Path) -> str:
    hasher = hashlib.sha256()
    with binary.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def collect_context(binary: Path) -> dict:
    """Collect low-volatility observations; avoid user identities and arbitrary env."""
    affinity_count = None
    if hasattr(os, "sched_getaffinity"):
        try:
            affinity_count = len(os.sched_getaffinity(0))
        except OSError:
            pass

    return {
        "schema": "rel-measurement-context-v1",
        "platform": platform.platform(),
        "machine": platform.machine(),
        "kernel_release": platform.release(),
        "cpu_model_reported": cpu_model(),
        "logical_cpu_count_reported": os.cpu_count(),
        "physical_cpu_count_reported": psutil.cpu_count(logical=False),
        "cpu_affinity_count": affinity_count,
        "host_ram_bytes_reported": psutil.virtual_memory().total,
        "rustc_version": compiler_version("rustc"),
        "cargo_version": compiler_version("cargo"),
        "python_version": platform.python_version(),
        "psutil_version": psutil.__version__,
        "analyzer_binary_sha256": binary_sha256(binary),
        "github_run_id": os.environ.get("GITHUB_RUN_ID"),
        "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "runner_os": os.environ.get("RUNNER_OS"),
        "runner_arch": os.environ.get("RUNNER_ARCH"),
        "runner_image_version": os.environ.get("ImageVersion"),
    }


def capture_context(binary: Path) -> tuple[dict, str]:
    context = collect_context(binary)
    return context, fingerprint(context)
