#!/usr/bin/env python3
"""Pure generation/provenance regressions for malformed-PE resource scenarios."""
from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from corpus_cases import ROOT, load_verified_seeds
from profile_malformed_resources import cases_from_verified_sources


class MalformedCorpusTests(unittest.TestCase):
    def test_case_set_is_deterministic_and_source_verified(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            cases = cases_from_verified_sources(ROOT / "fixtures", Path(folder))
            self.assertEqual(len(cases), 13)
            self.assertEqual(len(set(c.name for c in cases)), 13)
            seeds = {name: (bytes_, digest) for name, bytes_, digest
                     in load_verified_seeds(ROOT / "fixtures")}
            for case in cases:
                content = case.path.read_bytes()
                self.assertTrue(content)
                self.assertTrue(case.expected_error)
                if case.source in seeds:
                    self.assertEqual(case.source_sha256, seeds[case.source][1])
                    self.assertTrue(content.startswith(b"MZ"))
                else:
                    self.assertEqual(hashlib.sha256(content).hexdigest(),
                                     case.source_sha256)
            overlay = next(c for c in cases if c.name == "pe64-8m-overlay-bad-count")
            self.assertEqual(overlay.path.stat().st_size, 8 * 1024 * 1024)
            self.assertEqual(overlay.path.read_bytes()[-128:], bytes(128))

    def test_rejects_reference_seed_drift(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            source = Path(root)
            fixtures = ROOT / "fixtures"
            (source / "expected.json").write_bytes((fixtures / "expected.json").read_bytes())
            for name, _, _ in load_verified_seeds(fixtures):
                data = bytearray((fixtures / name).read_bytes())
                data[-1] ^= 0xff
                (source / name).write_bytes(data)
            with self.assertRaisesRegex(ValueError, "hash/size mismatch"):
                cases_from_verified_sources(source, source / "generated")


if __name__ == "__main__":
    unittest.main(verbosity=2)
