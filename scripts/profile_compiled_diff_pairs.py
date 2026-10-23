#!/usr/bin/env python3
"""Observe rel-diff resources on three independently checked, compiled PE pairs.

The existing Windows CI oracle first checks the controlled builds with pefile.
Only rel-inspect and rel-diff execute; PE inputs are statically read as bytes.
This measures a small source-derived corpus, not a representative PE population.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from _internal.measurement_environment import capture_context
from profile_manifest_diff import profile_once, summarize

ROOT = Path(__file__).resolve().parents[1]
PAIRS = (
    ("msvc-v1", "msvc-v4"),
    ("clang-v1", "clang-v4"),
    ("msvc-v3", "clang-v3"),
)
MAX_MANIFEST_BYTES = 16 * 1024 * 1024


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_manifest(manifest: dict, raw: bytes) -> None:
    """Reject stale or ambiguous CLI output before using it as a measurement."""
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be an object")
    if (manifest.get("schema_version"), manifest.get("format")) != ("1.0.0", "PE"):
        raise ValueError("expected PE manifest v1.0.0")
    if manifest.get("binary_sha256") != sha256(raw) or manifest.get("size_bytes") != len(raw):
        raise ValueError("PE raw-byte identity does not match rel-inspect")
    if manifest.get("warnings") != []:
        raise ValueError("compiler-built PE extraction was incomplete")
    if not all(isinstance(manifest.get(k), list) for k in ("imports", "exports", "sections")):
        raise ValueError("missing manifest collections")
    for category in ("imports", "exports"):
        strings = manifest[category]
        if not all(isinstance(item, str) for item in strings) or len(set(strings)) != len(strings):
            raise ValueError(f"invalid or repeated {category}")
    if not all(
        isinstance(item, dict) and isinstance(item.get("name"), str)
        for item in manifest["sections"]
    ):
        raise ValueError("invalid PE section names")


def diff_counts(left: dict, right: dict) -> tuple[int, int, int, int, int]:
    """Count the delta fields independently of the measured rel-diff report."""
    imports = len(set(right["imports"]) - set(left["imports"]))
    exports = len(set(right["exports"]) - set(left["exports"]))
    a_names = [section["name"] for section in left["sections"]]
    b_names = [section["name"] for section in right["sections"]]
    if len(set(a_names)) != len(a_names) or len(set(b_names)) != len(b_names):
        # rel-diff abstains entirely on ambiguous section names.
        return imports, exports, 0, 0, 0
    a = {section["name"]: section for section in left["sections"]}
    b = {section["name"]: section for section in right["sections"]}
    return (
        imports,
        exports,
        len(b.keys() - a.keys()),
        len(a.keys() - b.keys()),
        sum(a[name] != b[name] for name in a.keys() & b.keys()),
    )


def static_inspect(inspector: Path, source: Path) -> tuple[dict, bytes]:
    if source.is_symlink() or not source.is_file():
        raise ValueError(f"expected regular, non-symlink PE: {source.name}")
    raw = source.read_bytes()
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError(f"PE source size exceeds controlled cap: {source.name}")
    result = subprocess.run(
        [str(inspector), "analyze", str(source)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, timeout=30,
    )
    if result.returncode != 0 or len(result.stdout) > MAX_MANIFEST_BYTES:
        raise RuntimeError(f"static inspector failed: {source.name}: {result.stderr[:240]!r}")
    document = json.loads(result.stdout)
    validate_manifest(document, raw)
    return document, raw


def run(inspector: Path, diff: Path, corpus: Path, samples: int, warmup: int) -> dict:
    context, context_hash = capture_context(diff)
    inspector_hash = sha256(inspector.read_bytes())
    source_file = ROOT / "fixtures/probes/diff_version_probe.c"
    builder = ROOT / "scripts/build_windows_diff_pairs.cmd"
    result = {
        "schema_version": "rel-ex02-compiled-resource-evidence-v1-experimental",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "github_sha": os.environ.get("GITHUB_SHA"),
        "runner_platform": platform.platform(),
        "measurement_context": context,
        "measurement_context_sha256": context_hash,
        "inspector_sha256": inspector_hash,
        "probe_source_sha256": sha256(source_file.read_bytes()),
        "build_script_sha256": sha256(builder.read_bytes()),
        "samples": samples, "warmup": warmup,
        "method": "release rel-inspect static manifest + release rel-diff direct-child native CPU/RSS",
        "limitations": [
            "Three paired comparisons originate from four variants of one controlled C source.",
            "MSVC and Clang-cl share parts of the Windows SDK/linker environment.",
            "This is not a representative or redistribution-cleared external PE corpus.",
            "RSS and CPU are direct-child observations, not enforced bounds or process-tree isolation.",
            "Values from hosted runners are not comparable performance guarantees.",
        ],
        "pairs": [],
    }
    with tempfile.TemporaryDirectory(prefix="rel-ex02-compiled-profile-") as temp:
        work = Path(temp)
        manifests = {}
        source_hashes = {}
        # Only the five distinct build variants used by the selected pairs.
        selected = tuple(dict.fromkeys(name for pair in PAIRS for name in pair))
        for name in selected:
            source = corpus / f"{name}.exe"
            data, raw = static_inspect(inspector, source)
            manifests[name] = data
            source_hashes[name] = sha256(raw)
            (work / f"{name}.json").write_text(
                json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
        for left_id, right_id in PAIRS:
            left, right = manifests[left_id], manifests[right_id]
            expected = diff_counts(left, right)
            values = [
                profile_once(
                    diff, work / f"{left_id}.json", work / f"{right_id}.json",
                    (source_hashes[left_id], source_hashes[right_id]), expected,
                )
                for _ in range(warmup + samples)
            ][warmup:]
            if any(item["windows_peak_working_set_bytes"] is None
                   or item["windows_cpu_ms"] is None for item in values):
                raise AssertionError("missing direct-child native Windows CPU/RSS evidence")
            result["pairs"].append({
                "left": left_id, "right": right_id,
                "left_pe_sha256": source_hashes[left_id],
                "right_pe_sha256": source_hashes[right_id],
                "left_manifest_sha256": sha256((work / f"{left_id}.json").read_bytes()),
                "right_manifest_sha256": sha256((work / f"{right_id}.json").read_bytes()),
                "left_observations": {
                    key: len(left[key]) for key in ("imports", "exports", "sections")
                },
                "right_observations": {
                    key: len(right[key]) for key in ("imports", "exports", "sections")
                },
                "expected_delta_counts": expected,
                **summarize(values),
            })
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inspector", required=True, type=Path)
    parser.add_argument("--diff", required=True, type=Path)
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--samples", type=int, default=7)
    parser.add_argument("--warmup", type=int, default=1)
    args = parser.parse_args()
    if not 3 <= args.samples <= 100 or not 0 <= args.warmup <= 20:
        parser.error("samples must be [3,100] and warmup [0,20]")
    data = run(
        args.inspector.resolve(strict=True), args.diff.resolve(strict=True),
        args.corpus.resolve(strict=True), args.samples, args.warmup,
    )
    args.output.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"EX-02 compiler-pair resource evidence: PASS ({len(PAIRS)} pairs x {args.samples} samples)")


if __name__ == "__main__":
    main()
