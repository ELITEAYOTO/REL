#!/usr/bin/env python3
"""Read-only Linux cgroup-v2 capability observations, NOT an isolation check.

Never writes to cgroupfs, migrates a process, enables controllers, or
assumes that a writable-looking mount is a delegated hierarchy.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Callable

_OCTAL_ESCAPE = re.compile(r"\\([0-7]{3})")


def decode_mount_field(text: str) -> str:
    """Decode octal escapes mandated by /proc/self/mountinfo."""
    return _OCTAL_ESCAPE.sub(lambda m: chr(int(m.group(1), 8)), text)


def cgroup2_mounts(mountinfo: str) -> list[tuple[str, frozenset[str]]]:
    """Return cgroup2 (mountpoint, per-mount option set) observations."""
    found = []
    for line in mountinfo.splitlines():
        before, separator, after = line.partition(" - ")
        if not separator or len(before.split()) < 6:
            continue
        details = after.split()
        if not details or details[0] != "cgroup2":
            continue
        columns = before.split()
        found.append((
            decode_mount_field(columns[4]),
            frozenset(columns[5].split(",")),
        ))
    return found


def has_unified_membership(cgroup_file: str) -> bool:
    """Recognize an actual 0::/ hierarchy membership record."""
    return any(
        line.startswith("0::/") for line in cgroup_file.splitlines()
    )


def inspect(
    platform: str,
    mountinfo: str,
    membership: str,
    read_text: Callable[[Path], str],
) -> dict[str, object]:
    """Classify preconditions without taking any action on a cgroup.

    A positive result means *candidate for future active delegation tests*,
    never operational/verified isolation.
    """
    report: dict[str, object] = {
        "active_delegation_verified": False,
        "enforcement_tested": False,
        "mode": "read_only",
    }
    if not platform.startswith("linux"):
        return {**report, "status": "unsupported_platform"}
    mounts = cgroup2_mounts(mountinfo)
    if not mounts:
        return {**report, "status": "no_cgroup2_mount"}
    mountpoint, options = next(
        (m for m in mounts if m[0] == "/sys/fs/cgroup"), mounts[0]
    )
    report["mountpoint"] = mountpoint
    report["mount_is_read_only"] = "ro" in options
    report["unified_membership_visible"] = has_unified_membership(membership)
    try:
        root = Path(mountpoint)
        available = set((read_text(root / "cgroup.controllers")).split())
        enabled = set((read_text(root / "cgroup.subtree_control")).split())
    except (OSError, UnicodeError):
        report["status"] = "controller_observation_unavailable"
        return report

    report["available_controllers"] = sorted(available)
    report["enabled_for_children"] = sorted(enabled)
    if report["mount_is_read_only"]:
        report["status"] = "read_only_mount"
    elif not report["unified_membership_visible"]:
        report["status"] = "membership_unresolved"
    elif not {"cpu", "memory"} <= available:
        report["status"] = "required_controllers_not_available"
    else:
        report["status"] = "candidate_unverified"
    return report


def main() -> int:
    if not sys.platform.startswith("linux"):
        print(json.dumps(inspect(sys.platform, "", "", lambda _: ""), sort_keys=True))
        return 0
    try:
        mounts = Path("/proc/self/mountinfo").read_text(encoding="utf-8")
        membership = Path("/proc/self/cgroup").read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        print(json.dumps({
            "mode": "read_only",
            "status": "proc_metadata_unavailable",
            "active_delegation_verified": False,
            "enforcement_tested": False,
        }, sort_keys=True))
        return 0
    result = inspect(
        sys.platform,
        mounts,
        membership,
        lambda p: p.read_text(encoding="utf-8"),
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
