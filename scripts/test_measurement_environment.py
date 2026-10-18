#!/usr/bin/env python3
"""Reproducible, privacy-bounded context fingerprint tests."""
from __future__ import annotations

import copy
import hashlib
import tempfile
import unittest
from pathlib import Path

from measurement_environment import (
    binary_sha256, capture_context, collect_context, fingerprint,
)


class EnvironmentTests(unittest.TestCase):
    def test_order_independent_context_digest(self) -> None:
        a = {"schema": "v1", "cpu": "virtual", "ram": 123}
        b = {"ram": 123, "cpu": "virtual", "schema": "v1"}
        self.assertEqual(fingerprint(a), fingerprint(b))

    def test_changed_runner_attempt_changes_digest(self) -> None:
        original = {"github_run_id": "123", "github_run_attempt": "1"}
        another = {**original, "github_run_attempt": "2"}
        self.assertNotEqual(fingerprint(original), fingerprint(another))

    def test_changed_cpu_or_binary_changes_digest(self) -> None:
        original = {"cpu_model_reported": "Example CPU", "analyzer_binary_sha256": "a" * 64}
        for key, value in (
            ("cpu_model_reported", "Different CPU"),
            ("analyzer_binary_sha256", "b" * 64),
        ):
            changed = copy.deepcopy(original)
            changed[key] = value
            self.assertNotEqual(fingerprint(original), fingerprint(changed))

    def test_no_machine_username_or_sensitive_arbitrary_environment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "rel-test"
            binary.write_bytes(b"controlled-executable-hash-only")
            context, digest = capture_context(binary)
            self.assertEqual(context["analyzer_binary_sha256"], hashlib.sha256(binary.read_bytes()).hexdigest())
            self.assertEqual(digest, fingerprint(context))
            self.assertEqual(context["schema"], "rel-measurement-context-v1")
            self.assertGreater(context["host_ram_bytes_reported"], 0)
            self.assertNotIn("username", context)
            self.assertNotIn("hostname", context)
            self.assertNotIn("environment", context)

    def test_digest_includes_unknown_null_fields(self) -> None:
        self.assertNotEqual(fingerprint({"cpu_model_reported": None}), fingerprint({}))

    def test_hash_streams_binary_without_loading_whole_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture"
            path.write_bytes(b"x" * (1024 * 1024 + 5))
            self.assertEqual(binary_sha256(path), hashlib.sha256(path.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main(verbosity=2)
