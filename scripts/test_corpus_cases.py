#!/usr/bin/env python3
"""Cross-platform tests for hashes, deterministic overlays and honest provenance."""
from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from corpus_cases import (
    FIXTURE_NAMES, OVERLAY_SIZES, REDISTRIBUTION_STATUS, ROOT,
    load_verified_seeds, prepare_cases,
)


class CorpusCaseTests(unittest.TestCase):
    def test_tracked_fixture_hashes(self) -> None:
        seeds = load_verified_seeds(ROOT / "fixtures")
        self.assertEqual(tuple(n for n, _, _ in seeds), FIXTURE_NAMES)
        for name, data, digest in seeds:
            self.assertEqual(len(data), 2048)
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
            self.assertTrue(name.endswith(".exe"))

    def test_rejects_tampered_reference_seed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            copied = Path(tmp)
            fixtures = ROOT / "fixtures"
            (copied / "expected.json").write_bytes((fixtures / "expected.json").read_bytes())
            for name in FIXTURE_NAMES:
                (copied / name).write_bytes((fixtures / name).read_bytes())
            data = bytearray((copied / FIXTURE_NAMES[0]).read_bytes())
            data[-1] ^= 1
            (copied / FIXTURE_NAMES[0]).write_bytes(data)
            with self.assertRaisesRegex(ValueError, "hash/size mismatch"):
                load_verified_seeds(copied)

    def test_unique_cases_and_deterministic_overlay_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cases = prepare_cases(
                ROOT / "fixtures", Path(tmp), Path(tmp) / "unused",
                include_windows_executable=False,
            )
            self.assertEqual(len(cases), len(FIXTURE_NAMES) * (1 + len(OVERLAY_SIZES)))
            self.assertEqual(len({case.case_id for case in cases}), len(cases))
            for case in cases:
                self.assertEqual(case.report_fields()["redistribution_status"], REDISTRIBUTION_STATUS)
                seed = (ROOT / "fixtures" / case.source_fixture).read_bytes()
                with case.path.open("rb") as handle:
                    self.assertEqual(handle.read(len(seed)), seed)
                if case.kind == "synthetic-overlay":
                    size = int(case.case_id.split("-")[-1])
                    self.assertIn(size, OVERLAY_SIZES)
                    self.assertEqual(case.path.stat().st_size, size)
                    self.assertEqual(
                        case.path.read_bytes()[len(seed):], b"\x00" * (size - len(seed))
                    )
                else:
                    self.assertEqual(case.kind, "synthetic-fixture")

    def test_native_build_case_does_not_claim_redistribution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            native = folder / "rel-inspect.exe"
            native.write_bytes(b"simulated-local-build-metadata")
            cases = prepare_cases(
                ROOT / "fixtures", folder, native, include_windows_executable=True
            )
            result = cases[-1].report_fields()
            self.assertEqual(result["kind"], "native-windows-rel-executable")
            self.assertEqual(result["provenance"], "locally-built-rel-cli")
            self.assertEqual(result["redistribution_status"], "not-established")
            self.assertIsNone(result["source_fixture"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
