#!/usr/bin/env python3
"""Populate an existing fuzz corpus with 8 source-verified temporary PE inputs."""
from __future__ import annotations

import argparse
from pathlib import Path

from _internal.import_fuzz_fixture import verified_import_fuzz_seeds


def populate(directory: Path) -> list[tuple[str, str, str]]:
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError("destination must be an existing real directory")
    seeds = verified_import_fuzz_seeds()
    # Detect all conflicts before writing the first byte. Never overwrite
    # tracked, altered, or symlinked corpus entries.
    for name, data, _source_sha, _derived_sha in seeds:
        target = directory / name
        if target.is_symlink() or (target.exists() and
                                  (not target.is_file() or target.read_bytes() != data)):
            raise ValueError(f"{name}: pre-existing seed does not match expected bytes")
    for name, data, _source_sha, _derived_sha in seeds:
        target = directory / name
        if not target.exists():
            with target.open("xb") as handle:
                handle.write(data)
    return [(name, src, derived) for name, _data, src, derived in seeds]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", type=Path, required=True)
    arguments = parser.parse_args()
    for name, source_sha, generated_sha in populate(arguments.destination):
        print(f"IMPORT FUZZ SEED {name} source_sha256={source_sha} derived_sha256={generated_sha}")


if __name__ == "__main__":
    main()
