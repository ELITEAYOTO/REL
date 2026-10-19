#!/usr/bin/env python3
"""EX-01 verifier acquisition regressions; standalone Windows/Linux CI tests."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from verify_observation_evidence import (
    MAX_INPUT, MAX_REPORT, _read_after_preflight,
    decode_report, read_bounded_regular,
)

SCRIPT = Path(__file__).with_name("verify_observation_evidence.py")


class EvidenceInputTests(unittest.TestCase):
    def test_regular_exact_budget_and_bounded_growth(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "controlled.pe"
            payload = b"MZ" + b"x" * (MAX_INPUT - 2)
            path.write_bytes(payload)
            self.assertEqual(read_bounded_regular(path, MAX_INPUT), payload)
            with path.open("ab") as file:
                file.write(b"x")
            with self.assertRaisesRegex(ValueError, "byte limit"):
                read_bounded_regular(path, MAX_INPUT)

    def test_report_budget_and_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_bytes(b" " * (MAX_REPORT + 1))
            with self.assertRaisesRegex(ValueError, "byte limit"):
                read_bounded_regular(path, MAX_REPORT)

        self.assertEqual(decode_report(b'{"item":{"proof":1}}'), {"item": {"proof": 1}})
        for invalid in (
            b'{"item":1,"item":2}',
            b'{"item":{"proof":1,"proof":2}}',
        ):
            with self.subTest(payload=invalid), self.assertRaisesRegex(
                ValueError, "duplicate JSON object key"
            ):
                decode_report(invalid)
        for invalid in (b'{"item":NaN}', b'{"item":Infinity}'):
            with self.subTest(payload=invalid), self.assertRaisesRegex(
                ValueError, "non-JSON numeric constant"
            ):
                decode_report(invalid)

    def test_preflight_to_open_regular_file_replacement_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, substitute = root / "input.exe", root / "replacement.exe"
            target.write_bytes(b"MZ original")
            substitute.write_bytes(b"MZ replaced")
            previous = target.lstat()
            os.replace(substitute, target)
            with self.assertRaisesRegex(ValueError, "identity changed"):
                _read_after_preflight(target, previous, MAX_INPUT)

    def test_leaf_symlinks_are_refused_for_both_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "file.json"
            source.write_bytes(b'{"report":1}')
            link = root / "alias.json"
            try:
                link.symlink_to(source)
            except OSError as error:
                if os.getenv("GITHUB_ACTIONS"):
                    self.fail(f"hosted CI must exercise real file symlink: {error}")
                self.skipTest(f"local symlink privilege unavailable: {error}")
            with self.assertRaisesRegex(ValueError, "regular file"):
                read_bounded_regular(link, MAX_REPORT)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "Unix FIFO test")
    def test_fifo_source_and_report_cannot_block(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.exe"
            report = root / "report.json"
            source.write_bytes(b"MZ")
            report.write_bytes(b"{}")
            for index in (0, 1):
                fifo = root / f"blocked-{index}"
                os.mkfifo(fifo)
                args = [sys.executable, str(SCRIPT), "--input", str(
                    fifo if index == 0 else source
                ), "--report", str(fifo if index == 1 else report)]
                completed = subprocess.run(
                    args, capture_output=True, text=True,
                    check=False, timeout=5,
                )
                with self.subTest(index=index):
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertIn("regular file", completed.stderr)


if __name__ == "__main__":
    unittest.main()
