#!/usr/bin/env python3
"""Controlled measurement scenarios; no licensed public binary corpus claim."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_NAMES = ("pe32-basic.exe", "pe64-basic.exe")
OVERLAY_SIZES = (1024 * 1024, 4 * 1024 * 1024)
REDISTRIBUTION_STATUS = "not-established"


@dataclass(frozen=True)
class CorpusCase:
    case_id: str
    path: Path
    kind: str
    source_fixture: str | None
    source_sha256: str | None
    provenance: str

    def report_fields(self) -> dict:
        return {
            "case_id": self.case_id,
            "kind": self.kind,
            "source_fixture": self.source_fixture,
            "source_sha256": self.source_sha256,
            "provenance": self.provenance,
            "redistribution_status": REDISTRIBUTION_STATUS,
        }


def load_verified_seeds(fixtures: Path) -> list[tuple[str, bytes, str]]:
    """Reject changes to the reference fixture bytes or declared sizes."""
    expected = json.loads((fixtures / "expected.json").read_text(encoding="utf-8"))
    seeds = []
    for name in FIXTURE_NAMES:
        truth = expected[name]
        data = (fixtures / name).read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if truth.get("synthetic") is not True:
            raise ValueError(f"{name}: expected synthetic fixture")
        if truth["sha256"] != digest or truth["size_bytes"] != len(data):
            raise ValueError(f"{name}: reference fixture hash/size mismatch")
        if len(data) > OVERLAY_SIZES[0]:
            raise ValueError(f"{name}: reference fixture exceeds overlay size")
        seeds.append((name, data, digest))
    return seeds


def prepare_cases(
    fixtures: Path, workdir: Path, binary: Path, *, include_windows_executable: bool
) -> list[CorpusCase]:
    """Create deterministic, provenance-labeled PE cases without running them."""
    cases: list[CorpusCase] = []
    for name, seed, digest in load_verified_seeds(fixtures):
        arch = name.split("-")[0]
        cases.append(CorpusCase(
            f"{arch}-reference", fixtures / name, "synthetic-fixture",
            name, digest, "tracked-rel-synthetic",
        ))
        for size in OVERLAY_SIZES:
            target = workdir / f"{arch}-overlay-{size}.exe"
            with target.open("xb") as output:
                output.write(seed)
                output.truncate(size)
            cases.append(CorpusCase(
                f"{arch}-overlay-{size}", target, "synthetic-overlay",
                name, digest, "derived-from-tracked-rel-synthetic",
            ))

    if include_windows_executable:
        if not binary.is_file():
            raise FileNotFoundError(binary)
        cases.append(CorpusCase(
            "rel-windows-self", binary, "native-windows-rel-executable",
            None, None, "locally-built-rel-cli",
        ))
    return cases
