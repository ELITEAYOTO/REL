#!/usr/bin/env python3
"""Deterministic, non-mutating cgroup v2 probe regressions on both OSes."""
from __future__ import annotations

import unittest
from pathlib import Path

from probe_linux_cgroup_v2 import (
    cgroup2_mounts, decode_mount_field, has_unified_membership, inspect,
)


def mountinfo(*, writable: bool, mountpoint: str = "/sys/fs/cgroup") -> str:
    options = "rw,nosuid,nodev" if writable else "ro,nosuid,nodev"
    return (
        "31 22 0:27 / " + mountpoint + " " + options +
        " - cgroup2 cgroup " + ("rw" if writable else "ro") + "\n"
    )


def fake_reader(
    available: str = "cpu memory io",
    enabled: str = "cpu memory",
):
    def read(path: Path) -> str:
        if path.name == "cgroup.controllers":
            return available
        if path.name == "cgroup.subtree_control":
            return enabled
        raise AssertionError(f"unexpected read: {path}")
    return read


class CgroupV2ProbeTests(unittest.TestCase):
    def test_decode_octals_and_ignore_v1_mount(self) -> None:
        data = (
            "11 3 0:22 / /system\\040with\\040space rw - cgroup2 cgroup rw\n"
            "12 3 0:23 / /sys/fs/legacy ro - cgroup cgroup rw\n"
        )
        self.assertEqual(decode_mount_field("a\\040b"), "a b")
        self.assertEqual(
            cgroup2_mounts(data), [("/system with space", frozenset({"rw"}))]
        )

    def test_unified_membership_must_be_zero_hierarchy(self) -> None:
        self.assertTrue(has_unified_membership("0::/runner.slice\n"))
        self.assertFalse(has_unified_membership("2:cpu:/runner.slice\n"))
        self.assertFalse(has_unified_membership("0::not-an-absolute-path\n"))

    def test_read_only_mount_blocks_candidate(self) -> None:
        result = inspect(
            "linux", mountinfo(writable=False), "0::/ci\n", fake_reader()
        )
        self.assertEqual(result["status"], "read_only_mount")
        self.assertEqual(result["enabled_for_children"], ["cpu", "memory"])
        self.assertFalse(result["active_delegation_verified"])
        self.assertFalse(result["enforcement_tested"])

    def test_read_write_mount_is_only_unverified_candidate(self) -> None:
        result = inspect(
            "linux", mountinfo(writable=True), "0::/ci\n", fake_reader()
        )
        self.assertEqual(result["status"], "candidate_unverified")
        self.assertFalse(result["active_delegation_verified"])
        self.assertFalse(result["enforcement_tested"])

    def test_missing_controller_and_membership(self) -> None:
        self.assertEqual(
            inspect("linux", mountinfo(writable=True), "0::/ci\n",
                    fake_reader(available="memory"))["status"],
            "required_controllers_not_available",
        )
        self.assertEqual(
            inspect("linux", mountinfo(writable=True), "1:cpu:/ci\n",
                    fake_reader())["status"],
            "membership_unresolved",
        )

    def test_missing_mount_and_windows(self) -> None:
        self.assertEqual(
            inspect("linux", "invalid\n", "0::/\n", fake_reader())["status"],
            "no_cgroup2_mount",
        )
        self.assertEqual(
            inspect("win32", "", "", fake_reader())["status"],
            "unsupported_platform",
        )

    def test_unreadable_controller_files_are_not_a_positive(self) -> None:
        def inaccessible(_: Path) -> str:
            raise PermissionError("controlled denial")
        result = inspect(
            "linux", mountinfo(writable=True), "0::/ci\n", inaccessible
        )
        self.assertEqual(result["status"], "controller_observation_unavailable")
        self.assertFalse(result["active_delegation_verified"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
