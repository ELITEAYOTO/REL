"""Deterministic PE import-boundary fuzz inputs derived from verified REL fixtures.

These are temporary static parser inputs, not executed PE samples or a licensed
redistributable corpus. Keep the exact data transformations independently
covered by Rust fixture_pe regressions (#171, #172).
"""
from __future__ import annotations

import hashlib
import struct

from .corpus_cases import ROOT, load_verified_seeds


def require(ok: bool, detail: str) -> None:
    if not ok:
        raise ValueError(f"import fuzz fixture drift: {detail}")


def derive_import_boundary(source: bytes, *, is_64: bool, overlap: bool,
                           malformed: bool) -> bytes:
    """Build a padding or overlapping-section import descriptor in memory."""
    data = bytearray(source)
    nt, = struct.unpack_from("<I", data, 0x3C)
    require(len(data) == 2048 and nt == 0x80, "source length/NT offset")
    require(data[:2] == b"MZ" and data[nt:nt + 4] == b"PE\x00\x00",
            "source signatures")
    coff, opt = nt + 4, nt + 24
    magic, = struct.unpack_from("<H", data, opt)
    require(magic == (0x20B if is_64 else 0x10B), "optional header magic")
    header_size, section_count = struct.unpack_from("<HH", data, coff + 16)[0], None
    section_count, = struct.unpack_from("<H", data, coff + 2)
    require(section_count == 2, "source section count")
    rdata, = (opt + header_size + 40,)
    alias = rdata + 40
    require(alias + 40 <= 0x200, "third section header space")
    va, raw_size, raw = struct.unpack_from("<III", data, rdata + 12)
    require((va, raw_size, raw) == (0x2000, 0x400, 0x400),
            "reference .rdata section mapping")
    require(data[0x414:0x428] == bytes(20), "descriptor terminator not empty")
    require(data[0x600:0x620] == bytes(32), "alternate raw range not empty")
    orig = bytes(data[0x400:0x414])
    name, thunk = struct.unpack_from("<II", orig, 12)
    require(name != 0 and thunk != 0, "reference import fields")

    directory_start = 112 if is_64 else 96
    # Disable unrelated exports, repoint imports into aligned padding.
    data[opt + directory_start:opt + directory_start + 8] = bytes(8)
    struct.pack_into("<I", data, opt + directory_start + 8, 0x2014)
    struct.pack_into("<I", data, rdata + 16, 16)
    data[0x414:0x428] = orig

    if overlap:
        # The earlier section is still Goblin's first aligned RVA mapping;
        # a later section's strict raw RVA mapping points at zero bytes.
        struct.pack_into("<H", data, coff + 2, 3)
        data[alias:alias + 40] = bytes(40)
        data[alias:alias + 8] = b".alias\x00\x00"
        struct.pack_into("<IIII", data, alias + 8, 32, 0x2014, 32, 0x600)
    if malformed:
        struct.pack_into("<I", data, 0x414 + 12, 0)  # Name=0
    return bytes(data)


def verified_import_fuzz_seeds() -> list[tuple[str, bytes, str, str]]:
    """Return (seed name, bytes, pinned source digest, derived digest)."""
    result = []
    for source_name, source, source_digest in load_verified_seeds(ROOT / "fixtures"):
        is_64 = {"pe32-basic.exe": False, "pe64-basic.exe": True}[source_name]
        arch = "pe64" if is_64 else "pe32"
        for overlap in (False, True):
            for malformed in (False, True):
                kind = "overlap" if overlap else "padding"
                state = "missing-name" if malformed else "valid"
                name = f"imp-{kind}-{state}-{arch}.exe"
                value = derive_import_boundary(
                    source, is_64=is_64, overlap=overlap, malformed=malformed
                )
                result.append((name, value, source_digest, hashlib.sha256(value).hexdigest()))
    require(len(result) == 8 and len({entry[0] for entry in result}) == 8,
            "derived seed identities")
    return result
