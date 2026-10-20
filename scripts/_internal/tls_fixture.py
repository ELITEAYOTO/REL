"""Temporary source-defined PE32/PE32+ TLS callback seeds for static fuzzing.

Uses only the checked-in SHA-verified synthetic fixtures; no binary file is
committed, loaded or executed. Regeneration is byte-for-byte deterministic.
"""
from __future__ import annotations

import hashlib
import struct

from .corpus_cases import ROOT, load_verified_seeds

RAW_TLS = 0x600  # .rdata RVA 0x2200, raw offset 0x400
RAW_DATA = 0x700  # .rdata RVA 0x2300
RAW_INDEX = 0x710
RAW_CALLBACKS = 0x720
TLS_RVA = 0x2200


def synthesize_tls(source: bytes, *, is_64: bool) -> tuple[bytes, int, int]:
    """Place a valid two-callback, zero-terminated TLS table in unused .rdata."""
    data = bytearray(source)
    assert len(data) == 2048 and data[RAW_TLS:0x740] == bytes(0x140)
    assert data[:2] == b"MZ"
    nt, = struct.unpack_from("<I", data, 0x3C)
    assert nt == 0x80 and data[nt:nt + 4] == b"PE\x00\x00"
    optional = nt + 24
    magic, = struct.unpack_from("<H", data, optional)
    assert magic == (0x20B if is_64 else 0x10B)

    width = 8 if is_64 else 4
    fmt = "<Q" if is_64 else "<I"
    base, = struct.unpack_from(fmt, data, optional + (24 if is_64 else 28))
    assert base == (0x140000000 if is_64 else 0x400000)
    directory_start = 112 if is_64 else 96
    count, = struct.unpack_from("<I", data, optional + directory_start - 4)
    assert count >= 10
    tls_slot = optional + directory_start + 9 * 8
    assert struct.unpack_from("<II", data, tls_slot) == (0, 0)

    struct.pack_into("<II", data, tls_slot, TLS_RVA, 40 if is_64 else 24)
    for index, rva in enumerate((0x2300, 0x2304, 0x2310, 0x2320)):
        struct.pack_into(fmt, data, RAW_TLS + index * width, base + rva)
    data[RAW_DATA:RAW_DATA + 4] = b"\x12\x34\x56\x78"
    for index, rva in enumerate((0x1000, 0x1010, 0)):
        struct.pack_into(fmt, data, RAW_CALLBACKS + index * width, base + rva if rva else 0)

    return bytes(data), base, width


TLS_SEED_SHA256 = {
    "pe32-basic.exe": "7d3c836083d26d48619115f5025f85072878eff0405b98170eebdbca7836df64",
    "pe64-basic.exe": "37f6d6582030a951f2c63c48108947f00ea68242961939f6d31452a80b5d2629",
}


def verified_tls_seeds() -> list[tuple[str, bytes, str, str]]:
    """Return (generated name, PE bytes, source SHA, generated SHA).

    Validate all source and derived hashes before the caller writes any seed.
    """
    seeds = []
    for name, source, source_digest in load_verified_seeds(ROOT / "fixtures"):
        is_64 = {"pe32-basic.exe": False, "pe64-basic.exe": True}[name]
        generated, _image_base, _width = synthesize_tls(source, is_64=is_64)
        digest = hashlib.sha256(generated).hexdigest()
        if digest != TLS_SEED_SHA256[name]:
            raise ValueError(f"{name}: generated TLS fixture hash mismatch")
        seeds.append((f"tls-{name}", generated, source_digest, digest))
    return seeds
