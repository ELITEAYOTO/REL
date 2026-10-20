#!/usr/bin/env python3
"""Negative-path regressions for local Markdown link gate."""
from __future__ import annotations

import unittest

from check_repo_hygiene import link_destinations, validate_document

TRACKED = {"README.md", "docs/guide.md", "docs/other.md", "assets/logo.png"}


class MarkdownLinkTests(unittest.TestCase):
    def test_resolves_relative_files_folders_and_fragments(self) -> None:
        markdown = (
            "[file](other.md#heading) [root](../README.md) "
            "[folder](../assets/) [image](../assets/logo.png)\n"
            "[fragment](#local) [external](https://example.org/path)\n"
        )
        self.assertEqual(validate_document("docs/guide.md", markdown, TRACKED), [])

    def test_missing_reference_reports_source_and_line(self) -> None:
        failures = validate_document(
            "docs/guide.md", "First line\n[bad](MISSING.md)", TRACKED
        )
        self.assertEqual(
            failures, ["docs/guide.md:2: missing local link: MISSING.md"]
        )

    def test_rejects_parent_traversal_and_case_drift(self) -> None:
        failures = validate_document(
            "docs/guide.md", "[escape](../../outside) [case](Other.md)",
            TRACKED,
        )
        self.assertEqual(len(failures), 2)
        self.assertIn("escapes repository", failures[0])
        self.assertIn("missing local link: Other.md", failures[1])

    def test_ignores_code_fences_and_inline_code(self) -> None:
        markdown = (
            "```markdown\n[not real](missing.md)\n```\n"
            "`[example](also-missing.md)` [valid](other.md)\n"
            "~~~\n[ignored](absent.md)\n~~~\n"
        )
        self.assertEqual(validate_document("docs/guide.md", markdown, TRACKED), [])

    def test_reference_links_and_percent_encoding(self) -> None:
        tracked = TRACKED | {"docs/a b.md"}
        markdown = (
            "[read this][ref]\n[ref]: a%20b.md\n"
            "[other]: ../README.md \"title\"\n"
        )
        self.assertEqual(validate_document("docs/guide.md", markdown, tracked), [])
        self.assertEqual(len(list(link_destinations(markdown))), 2)

    def test_root_absolute_is_not_treated_as_relative(self) -> None:
        failures = validate_document("README.md", "[link](/docs/guide.md)", TRACKED)
        self.assertIn("absolute local link", failures[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
