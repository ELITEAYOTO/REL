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
    toolchain_version: str | None = None
    resource_source: str | None = None
    resource_sha256: str | None = None

    def report_fields(self) -> dict:
        result = {
            "case_id": self.case_id,
            "kind": self.kind,
            "source_fixture": self.source_fixture,
            "source_sha256": self.source_sha256,
            "provenance": self.provenance,
            "redistribution_status": REDISTRIBUTION_STATUS,
        }
        if self.toolchain_version is not None:
            result["toolchain_version"] = self.toolchain_version
        if self.resource_source is not None:
            result["resource_source"] = self.resource_source
            result["resource_sha256"] = self.resource_sha256
        return result


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



def append_structured_cases(
    cases: list[CorpusCase],
    msvc_probe: Path | None,
    clang_probe: Path | None,
    clang_version: str | None,
) -> None:
    """Append source-verified Windows structured cases after input validation."""
    if msvc_probe is None and clang_probe is None:
        return
    source = ROOT / "fixtures" / "probes" / "structured_probe.c"
    asset = ROOT / "fixtures" / "probes" / "structured_probe.rc"
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    asset_hash = hashlib.sha256(asset.read_bytes()).hexdigest()
    for compiler, probe, version in (
        ("msvc", msvc_probe, None),
        ("clang-cl", clang_probe, clang_version),
    ):
        if probe is None:
            continue
        cases.append(CorpusCase(
            case_id=f"{compiler}-x64-structured",
            path=probe,
            kind=f"ci-built-{compiler}-x64-structured-pe",
            source_fixture="fixtures/probes/structured_probe.c",
            source_sha256=source_hash,
            provenance=f"built-on-runner-{compiler}-x64-with-rc",
            toolchain_version=version,
            resource_source="fixtures/probes/structured_probe.rc",
            resource_sha256=asset_hash,
        ))


def prepare_cases(
    fixtures: Path, workdir: Path, binary: Path, *, include_windows_executable: bool,
    windows_msvc_probe: Path | None = None,
    windows_clang_probe: Path | None = None,
    windows_msvc_structured: Path | None = None,
    windows_clang_structured: Path | None = None,
) -> list[CorpusCase]:
    """Create deterministic, provenance-labeled PE cases without running them."""
    # Fail before producing any overlay if the optional compiler input is invalid.
    for name, probe in (
        ("MSVC", windows_msvc_probe),
        ("Clang-cl", windows_clang_probe),
        ("MSVC structured", windows_msvc_structured),
        ("Clang-cl structured", windows_clang_structured),
    ):
        if probe is not None:
            if not include_windows_executable:
                raise ValueError(f"{name} probe requires the Windows corpus mode")
            if not probe.is_file():
                raise FileNotFoundError(probe)

    clang_version = None
    if windows_clang_probe is not None or windows_clang_structured is not None:
        clang_path = windows_clang_probe or windows_clang_structured
        assert clang_path is not None
        version_file = clang_path.with_name("clang-cl-version.txt")
        version_lines = version_file.read_text(encoding="utf-8").splitlines()
        if not version_lines or not version_lines[0].startswith("clang version "):
            raise ValueError("missing or invalid Clang version provenance")
        clang_version = version_lines[0][:256]

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
    if windows_msvc_probe is not None:
        source = ROOT / "fixtures" / "probes" / "msvc_probe.c"
        source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
        cases.append(CorpusCase(
            "msvc-x64-local-build", windows_msvc_probe, "ci-built-msvc-x64-pe",
            "fixtures/probes/msvc_probe.c", source_sha, "built-on-runner-msvc-x64",
        ))
    if windows_clang_probe is not None:
        source = ROOT / "fixtures" / "probes" / "msvc_probe.c"
        cases.append(CorpusCase(
            "clang-cl-x64-local-build", windows_clang_probe,
            "ci-built-clang-cl-x64-pe", "fixtures/probes/msvc_probe.c",
            hashlib.sha256(source.read_bytes()).hexdigest(),
            "built-on-runner-clang-cl-x64", clang_version,
        ))
    append_structured_cases(
        cases, windows_msvc_structured, windows_clang_structured, clang_version
    )
    return cases
