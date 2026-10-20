#!/usr/bin/env python3
"""Read-only Linux cgroup-v2 capability observations, NOT an isolation check.

Never writes to cgroupfs, migrates a process, enables controllers, or
assumes that a writable-looking mount is a delegated hierarchy.
"""
from __future__ import annotations

import argparse
import json
import re
import secrets
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



def own_nonroot_group(mountinfo: str, membership: str) -> Path | None:
    """Find ONLY the current process's non-root cgroup in the canonical mount.

    Refuse namespace roots, ambiguous/mismatched mount roots and dot segments.
    Never write to a parent or another process's group by guessing.
    """
    paths = [line[3:] for line in membership.splitlines() if line.startswith("0::/")]
    if len(paths) != 1 or paths[0] == "/":
        return None
    members = paths[0].strip("/").split("/")
    if any(part in ("", ".", "..") for part in members):
        return None
    for line in mountinfo.splitlines():
        before, sep, after = line.partition(" - ")
        columns = before.split()
        if not sep or len(columns) < 6 or not after.startswith("cgroup2 "):
            continue
        if decode_mount_field(columns[4]) != "/sys/fs/cgroup":
            continue
        root = decode_mount_field(columns[3])
        if not root.startswith("/"):
            return None
        roots = root.strip("/").split("/") if root != "/" else []
        if any(part in ("", ".", "..") for part in roots):
            return None
        if members[:len(roots)] != roots:
            return None
        relative = members[len(roots):]
        if not relative:
            return None  # Never create under a namespace or system root.
        return Path("/sys/fs/cgroup").joinpath(*relative)
    return None


def check_empty_child(
    parent: Path,
    create: Callable[[Path], None],
    remove: Callable[[Path], None],
    read_text: Callable[[Path], str],
    suffix: str,
) -> dict[str, object]:
    """Only mkdir/read-empty/rmdir a freshly named OWN child, never migrate PIDs.

    A cleanup failure is fatal: leaving a group behind is not a passing
    result, even if the capability probe is nonessential to the build.
    """
    if not re.fullmatch(r"[0-9a-f]{24}", suffix):
        raise ValueError("unsafe disposable cgroup suffix")
    child = parent / ("rel-empty-" + suffix)
    try:
        create(child)  # Exclusively creates a new, unpredictable child path.
    except OSError as error:
        return {"empty_child_probe": "create_denied", "errno": error.errno}
    try:
        try:
            members = read_text(child / "cgroup.procs")
        except (OSError, UnicodeError):
            result = {"empty_child_probe": "membership_unreadable"}
        else:
            result = {
                "empty_child_probe": (
                    "unexpected_process_present" if members.strip()
                    else "created_empty_and_removed"
                ),
            }
    finally:
        try:
            remove(child)
        except OSError as error:
            raise RuntimeError(
                "own disposable cgroup cleanup FAILED; intervention required: "
                + str(child)
            ) from error
    return result


def optional_empty_child_probe(
    report: dict[str, object], mountinfo: str, membership: str,
) -> dict[str, object]:
    """Opt-in, minimal active permission test; no controller or PID writes."""
    report = {**report, "mode": "empty_child_probe",
              "empty_child_creation_verified": False}
    if report.get("status") != "candidate_unverified":
        return {**report, "empty_child_probe": "skipped_preconditions"}
    if not {"cpu", "memory"} <= set(report.get("enabled_for_children", [])):
        return {**report, "empty_child_probe": "controllers_not_enabled"}
    parent = own_nonroot_group(mountinfo, membership)
    if parent is None:
        return {**report, "empty_child_probe": "unsafe_or_root_membership"}
    try:
        # A mount or cgroup path that resolves through a symlink is refused.
        if parent.resolve(strict=True) != parent:
            return {**report, "empty_child_probe": "noncanonical_path"}
    except OSError:
        return {**report, "empty_child_probe": "parent_not_accessible"}
    result = check_empty_child(
        parent,
        lambda path: path.mkdir(mode=0o700),
        lambda path: path.rmdir(),
        lambda path: path.read_text(encoding="utf-8"),
        secrets.token_hex(12),
    )
    report.update(result)
    report["empty_child_creation_verified"] = (
        result["empty_child_probe"] == "created_empty_and_removed"
    )
    # This does NOT verify cgroup.procs migration or memory/cpu enforcement.
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check-empty-child", action="store_true",
        help="Opt-in Linux mkdir/read/rmdir of ONE owned empty child only",
    )
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        report = inspect(sys.platform, "", "", lambda _: "")
        if args.check_empty_child:
            report = optional_empty_child_probe(report, "", "")
        print(json.dumps(report, sort_keys=True))
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
    if args.check_empty_child:
        result = optional_empty_child_probe(result, mounts, membership)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
