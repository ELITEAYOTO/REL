#!/usr/bin/env python3
"""CI guard: verify committed GitHub-owned actions use reviewed immutable SHAs."""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ("ci.yml", "fuzz.yml", "fuzz-long.yml")
EXPECTED = {
    "actions/checkout": "d23441a48e516b6c34aea4fa41551a30e30af803",
    "actions/setup-python": "ece7cb06caefa5fff74198d8649806c4678c61a1",
    "actions/upload-artifact": "b7c566a772e6b6bfb58ed0dc250532a479d7789f",
}
USE = re.compile(r"^\s*(?:-\s*)?uses:\s+(\S+)")


def verify_workflow(content: str, name: str) -> dict[str, int]:
    found: dict[str, int] = {}
    for line_number, source in enumerate(content.splitlines(), 1):
        line = source.split("#", 1)[0].rstrip()
        match = USE.match(line)
        if not match or not match.group(1).startswith("actions/"):
            continue
        action_and_pin = match.group(1)
        action, separator, pin = action_and_pin.partition("@")
        if not separator or action not in EXPECTED or pin != EXPECTED[action]:
            raise ValueError(
                f"{name}:{line_number}: unreviewed/unpinned GitHub action "
                f"{action_and_pin}"
            )
        found[action] = found.get(action, 0) + 1
    if not found or "actions/checkout" not in found:
        raise ValueError(f"{name}: missing first-party checkout action")
    return found


class PinTests(unittest.TestCase):
    def test_accepts_complete_sha_and_multiple_steps(self) -> None:
        workflow = ("    - uses: actions/checkout@" + EXPECTED["actions/checkout"] +
                    " # v6\n    - uses: actions/upload-artifact@" +
                    EXPECTED["actions/upload-artifact"] + " # v6\n")
        self.assertEqual(verify_workflow(workflow, "test")["actions/checkout"], 1)

    def test_rejects_mutable_or_truncated_refs(self) -> None:
        for ref in ("v6", EXPECTED["actions/checkout"][:12], ""):
            with self.subTest(ref=ref):
                with self.assertRaisesRegex(ValueError, "unreviewed/unpinned"):
                    verify_workflow(" - uses: actions/checkout@" + ref, "test")

    def test_rejects_unknown_github_action(self) -> None:
        with self.assertRaisesRegex(ValueError, "unreviewed/unpinned"):
            verify_workflow(" - uses: actions/checkout@" + EXPECTED["actions/checkout"] +
                            "\n - uses: actions/cache@v4", "test")

    def test_rejects_missing_checkout(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing first-party checkout"):
            verify_workflow(" - uses: actions/upload-artifact@" +
                            EXPECTED["actions/upload-artifact"], "test")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(PinTests)
        if not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful():
            raise SystemExit(1)
        return
    for filename in WORKFLOWS:
        found = verify_workflow(
            (ROOT / ".github" / "workflows" / filename).read_text(
                encoding="utf-8"
            ), filename
        )
        print(f"PASS {filename}: " + ", ".join(
            f"{name}={count}" for name, count in sorted(found.items())
        ))


if __name__ == "__main__":
    main()
