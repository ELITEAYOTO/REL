#!/usr/bin/env python3
"""Offline regression and provenance checks for generated import fuzz inputs."""
from __future__ import annotations

import hashlib
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from _internal.corpus_cases import ROOT, load_verified_seeds
from _internal.import_fuzz_fixture import (
    IMPORT_FUZZ_SHA256, derive_import_boundary, verified_import_fuzz_seeds,
)
from prepare_import_fuzz_seeds import populate


class ImportFuzzSeedTests(unittest.TestCase):
    def test_source_fingerprints_and_structural_mutations(self) -> None:
        seeds = verified_import_fuzz_seeds()
        self.assertEqual(len(seeds), 8)
        self.assertEqual(len({name for name, *_ in seeds}), 8)
        originals = {name: (data, sha)
                     for name, data, sha in load_verified_seeds(ROOT / "fixtures")}
        for name, data, src_sha, generated_sha in seeds:
            with self.subTest(name=name):
                is_64 = name.endswith("-pe64.exe")
                original, expected_sha = originals[
                    "pe64-basic.exe" if is_64 else "pe32-basic.exe"
                ]
                self.assertEqual(src_sha, expected_sha)
                self.assertEqual(hashlib.sha256(data).hexdigest(), generated_sha)
                self.assertEqual(len(data), len(original))
                self.assertEqual(data[:2], b"MZ")
                self.assertNotEqual(data, original)
                nt, = struct.unpack_from("<I", data, 0x3C)
                opt = nt + 24
                magic, = struct.unpack_from("<H", data, opt)
                self.assertEqual(magic, 0x20B if is_64 else 0x10B)
                directory_start = 112 if is_64 else 96
                self.assertEqual(
                    struct.unpack_from("<II", data, opt + directory_start),
                    (0, 0), "exports intentionally absent",
                )
                import_rva, = struct.unpack_from("<I", data, opt + directory_start + 8)
                self.assertEqual(import_rva, 0x2014)
                section_size, = struct.unpack_from("<H", data, nt + 4 + 16)
                rdata = opt + section_size + 40
                self.assertEqual(struct.unpack_from("<I", data, rdata + 16)[0], 16)
                self.assertEqual(data[0x414:0x420], original[0x400:0x40C])
                self.assertEqual(
                    struct.unpack_from("<I", data, 0x414 + 16)[0],
                    struct.unpack_from("<I", original, 0x400 + 16)[0],
                )
                self.assertEqual(
                    struct.unpack_from("<I", data, 0x414 + 12)[0] == 0,
                    "missing-name" in name,
                )
                self.assertEqual(
                    struct.unpack_from("<H", data, nt + 4 + 2)[0],
                    3 if "overlap" in name else 2,
                )

    def test_rejects_structural_source_drift(self) -> None:
        name, original, _ = load_verified_seeds(ROOT / "fixtures")[0]
        self.assertEqual(name, "pe32-basic.exe")
        modified = bytearray(original)
        modified[0x414] = 1
        with self.assertRaisesRegex(ValueError, "descriptor terminator"):
            derive_import_boundary(bytes(modified), is_64=False,
                                   overlap=False, malformed=False)

    def test_pinned_generated_sha_detects_algorithm_drift(self) -> None:
        name = "imp-overlap-missing-name-pe32.exe"
        with patch.dict(IMPORT_FUZZ_SHA256, {name: "0" * 64}):
            with self.assertRaisesRegex(ValueError, "source-derived SHA-256 mismatch"):
                verified_import_fuzz_seeds()

    def test_idempotence_and_fail_before_any_partial_generation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rel-import-fuzz-") as folder:
            dest = Path(folder)
            entries = populate(dest)
            self.assertEqual(len(entries), 8)
            self.assertEqual(entries, populate(dest))
            self.assertEqual(len(list(dest.iterdir())), 8)
            first = dest / entries[0][0]
            edited = bytearray(first.read_bytes())
            edited[-1] ^= 1
            first.write_bytes(edited)
            with self.assertRaisesRegex(ValueError, "pre-existing seed"):
                populate(dest)
            self.assertEqual(first.read_bytes(), edited)
            # A fresh directory with a conflicted later entry cannot receive
            # any other generated seeds before the mismatch is rejected.
            with tempfile.TemporaryDirectory(prefix="rel-import-conflict-") as second:
                empty = Path(second)
                last = entries[-1][0]
                (empty / last).write_bytes(b"tampered")
                with self.assertRaisesRegex(ValueError, "pre-existing seed"):
                    populate(empty)
                self.assertEqual([p.name for p in empty.iterdir()], [last])

    def test_fuzz_workflows_verify_before_generation_and_hashing(self) -> None:
        for workflow in ("fuzz.yml", "fuzz-long.yml"):
            with self.subTest(workflow=workflow):
                source = (ROOT / ".github" / "workflows" / workflow).read_text(
                    encoding="utf-8"
                )
                commands = (
                    "python scripts/test_corpus_cases.py",
                    "python scripts/test_import_fuzz_seeds.py",
                    "python scripts/prepare_import_fuzz_seeds.py --destination fuzz/corpus/pe_inspect",
                    "sha256sum fuzz/corpus/pe_inspect/*",
                    'fuzz build pe_inspect',
                    'fuzz run pe_inspect',
                )
                positions = []
                for command in commands:
                    if command.startswith("sha256sum"):
                        # The smoke workflow also fingerprints original seeds
                        # before deriving additions; final provenance is later.
                        self.assertGreaterEqual(source.count(command), 1)
                        positions.append(source.rindex(command))
                    else:
                        self.assertEqual(source.count(command), 1, f"{workflow}: {command}")
                        positions.append(source.index(command))
                self.assertEqual(positions, sorted(positions))
                self.assertIn("python scripts/test_tls_fuzz_seeds.py", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
