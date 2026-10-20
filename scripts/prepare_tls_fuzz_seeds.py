#!/usr/bin/env python3
"""Generate two verified, ignored TLS fuzz seeds; do not commit the PE bytes."""
from __future__ import annotations

import argparse
from pathlib import Path

from _internal.tls_fixture import verified_tls_seeds


def populate(directory: Path) -> list[tuple[str, str, str]]:
    """Reject tampered existing entries before writing any new seed."""
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError("destination must be an existing real directory")
    seeds = verified_tls_seeds()
    for name, contents, _source_sha, _generated_sha in seeds:
        destination = directory / name
        if destination.is_symlink() or (
            destination.exists() and destination.read_bytes() != contents
        ):
            raise ValueError(f"{name}: pre-existing seed does not match expected bytes")
    for name, contents, _source_sha, _generated_sha in seeds:
        destination = directory / name
        if not destination.exists():
            with destination.open("xb") as handle:
                handle.write(contents)
    return [(name, source_sha, generated_sha)
            for name, _data, source_sha, generated_sha in seeds]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", type=Path, required=True)
    arguments = parser.parse_args()
    for name, source_sha, generated_sha in populate(arguments.destination):
        print(f"TLS FUZZ SEED {name} source_sha256={source_sha} derived_sha256={generated_sha}")


if __name__ == "__main__":
    main()
