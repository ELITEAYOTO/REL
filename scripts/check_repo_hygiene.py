#!/usr/bin/env python3
"""Check tracked Markdown links against the real Git index, without network IO.

This deliberately checks local file/directory existence, NOT external URLs or
fragment targets. Historical docs are preserved; the gate detects path drift.
"""
from __future__ import annotations

import posixpath
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
INLINE_LINK = re.compile(r"!?\[[^\]\n]*\]\(\s*(<[^>]+>|[^\s)]+)")
REFERENCE_LINK = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*(<[^>]+>|\S+)")
FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})")
CODE_SPAN = re.compile(r"`+[^\n`]*`+")


def link_destinations(markdown: str):
    """Yield (line, destination); ignore fenced code and inline code spans."""
    fence_char, fence_length = None, 0
    for line_number, line in enumerate(markdown.splitlines(), 1):
        match = FENCE.match(line)
        if match:
            marker = match.group(1)
            if fence_char is None:
                fence_char, fence_length = marker[0], len(marker)
            elif marker[0] == fence_char and len(marker) >= fence_length:
                fence_char, fence_length = None, 0
            continue
        if fence_char is not None:
            continue
        visible = CODE_SPAN.sub("", line)
        for found in INLINE_LINK.finditer(visible):
            yield line_number, found.group(1).strip("<>")
        reference = REFERENCE_LINK.match(visible)
        if reference:
            yield line_number, reference.group(1).strip("<>")


def tracked_paths(root: Path) -> set[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached"],
        cwd=root, capture_output=True, check=True,
    )
    return {
        name.decode("utf-8") for name in result.stdout.split(b"\0") if name
    }


def validate_document(
    source: str, markdown: str, tracked: set[str],
) -> list[str]:
    """Report broken relative references, preserving case and source lines."""
    folders = {""}
    for name in tracked:
        folder = posixpath.dirname(name)
        while folder and folder not in folders:
            folders.add(folder)
            folder = posixpath.dirname(folder)
    failures = []
    for line, destination in link_destinations(markdown):
        if not destination or destination.startswith("#"):
            continue
        if destination.startswith("//"):
            continue  # Protocol-relative external URL.
        if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", destination):
            continue  # External scheme, e.g. https: or mailto:.
        relative = unquote(urlsplit(destination).path)
        if not relative:
            continue
        if relative.startswith("/"):
            failures.append(f"{source}:{line}: absolute local link {destination}")
            continue
        resolved = posixpath.normpath(
            posixpath.join(posixpath.dirname(source), relative)
        )
        if resolved.startswith("../") or resolved == "..":
            failures.append(f"{source}:{line}: link escapes repository: {destination}")
        elif resolved not in tracked and resolved not in folders:
            failures.append(f"{source}:{line}: missing local link: {destination}")
    return failures


def main() -> int:
    tracked = tracked_paths(ROOT)
    failures = []
    for source in sorted(name for name in tracked if name.endswith(".md")):
        markdown = (ROOT / source).read_text(encoding="utf-8")
        failures.extend(validate_document(source, markdown, tracked))
    for error in failures:
        print(error, file=sys.stderr)
    if failures:
        print(f"FAIL: {len(failures)} broken local Markdown links", file=sys.stderr)
        return 1
    print("PASS: tracked Markdown local path references resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main())
