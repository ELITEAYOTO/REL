#!/usr/bin/env python3
"""Offline standard-library regression tests for generated TLS fuzz seeds."""
from __future__ import annotations

import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

from _internal.corpus_cases import ROOT, load_verified_seeds
from _internal.tls_fixture import RAW_TLS, TLS_SEED_SHA256, synthesize_tls, verified_tls_seeds
from prepare_tls_fuzz_seeds import populate


class TlsFuzzSeedTests(unittest.TestCase):
    def test_expected_hashes_and_callback_table(self) -> None:
        generated = verified_tls_seeds()
        self.assertEqual(len(generated), 2)
        for (name, data, source_sha, digest), (fixture, original, expected_source) in zip(
            generated, load_verified_seeds(ROOT / "fixtures")
        ):
            self.assertEqual(name, f"tls-{fixture}")
            self.assertEqual(source_sha, expected_source)
            self.assertEqual(len(data), len(original))
            self.assertNotEqual(data, original)
            self.assertEqual(digest, TLS_SEED_SHA256[fixture])
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
            is_64 = fixture == "pe64-basic.exe"
            base = 0x140000000 if is_64 else 0x400000
            width = 8 if is_64 else 4
            fmt = "<Q" if is_64 else "<I"
            self.assertEqual(struct.unpack_from(fmt, data, RAW_TLS + width * 3)[0], base + 0x2320)
            self.assertEqual(
                tuple(struct.unpack_from(fmt, data, 0x720 + i * width)[0] for i in range(3)),
                (base + 0x1000, base + 0x1010, 0),
            )

    def test_generation_is_idempotent_and_refuses_existing_drift(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rel-tls-fuzz-test-") as tmp:
            dest = Path(tmp)
            first = populate(dest)
            self.assertEqual(first, populate(dest))
            self.assertEqual(len(list(dest.iterdir())), 2)
            tampered = dest / first[0][0]
            modified = bytearray(tampered.read_bytes())
            modified[-1] ^= 0x7F
            tampered.write_bytes(modified)
            with self.assertRaisesRegex(ValueError, "pre-existing seed"):
                populate(dest)
            self.assertEqual(tampered.read_bytes(), bytes(modified))

    def test_nonempty_original_reserved_tls_region_is_rejected(self) -> None:
        name, original, _ = load_verified_seeds(ROOT / "fixtures")[0]
        self.assertEqual(name, "pe32-basic.exe")
        modified = bytearray(original)
        modified[RAW_TLS] = 1
        with self.assertRaises(AssertionError):
            synthesize_tls(bytes(modified), is_64=False)


if __name__ == "__main__":
    unittest.main()
