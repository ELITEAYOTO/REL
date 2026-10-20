#!/usr/bin/env python3
"""Deterministic, non-mutating cgroup v2 probe regressions on both OSes."""
from __future__ import annotations

import unittest
from pathlib import Path

from probe_linux_cgroup_v2 import (
    cgroup2_mounts, decode_mount_field, has_unified_membership, inspect,
    own_nonroot_group, check_empty_child, optional_empty_child_probe,
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

    def test_current_group_resolution_refuses_root_and_wrong_mount(self) -> None:
        self.assertIsNone(own_nonroot_group(mountinfo(writable=True), "0::/\n"))
        self.assertIsNone(own_nonroot_group(
            mountinfo(writable=True), "0::/else/../ci\n"
        ))
        self.assertIsNone(own_nonroot_group(
            mountinfo(writable=True, mountpoint="/not-cgroup"), "0::/ci\n"
        ))
        self.assertEqual(
            own_nonroot_group(mountinfo(writable=True), "0::/ci/worker\n"),
            Path("/sys/fs/cgroup/ci/worker"),
        )

    def test_mount_root_prefix_mapping_is_exact(self) -> None:
        data = "31 22 0:27 /slice /sys/fs/cgroup rw - cgroup2 cgroup rw\n"
        self.assertEqual(
            own_nonroot_group(data, "0::/slice/runner/ci\n"),
            Path("/sys/fs/cgroup/runner/ci"),
        )
        self.assertIsNone(own_nonroot_group(data, "0::/unrelated/ci\n"))
        self.assertIsNone(own_nonroot_group(data, "0::/slice\n"))

    def test_empty_child_success_only_after_cleanup(self) -> None:
        calls: list[tuple[str, Path]] = []
        def create(p: Path) -> None:
            calls.append(("create", p))
        def remove(p: Path) -> None:
            calls.append(("remove", p))
        def read(p: Path) -> str:
            calls.append(("read", p))
            return ""
        out = check_empty_child(
            Path("/example/ci"), create, remove, read, "a" * 24,
        )
        self.assertEqual(out, {"empty_child_probe": "created_empty_and_removed"})
        self.assertEqual([kind for kind, _ in calls], ["create", "read", "remove"])
        self.assertEqual(calls[0][1], calls[-1][1])
        self.assertEqual(calls[1][1].name, "cgroup.procs")

    def test_permission_denial_does_not_remove_uncreated_group(self) -> None:
        def deny(_: Path) -> None:
            raise PermissionError(13, "denied")
        def unexpected(_: Path) -> None:
            raise AssertionError("not allowed")
        self.assertEqual(
            check_empty_child(Path("/example/ci"), deny, unexpected,
                              unexpected, "b" * 24),
            {"empty_child_probe": "create_denied", "errno": 13},
        )

    def test_cleanup_failure_is_fatal_not_success(self) -> None:
        def cleanup_denied(_: Path) -> None:
            raise PermissionError(13, "denied")
        with self.assertRaisesRegex(RuntimeError, "cleanup FAILED"):
            check_empty_child(
                Path("/example/ci"), lambda _: None, cleanup_denied,
                lambda _: "", "c" * 24,
            )

    def test_nonempty_or_unreadable_group_is_not_verified(self) -> None:
        cleaned: list[Path] = []
        def cleanup(p: Path) -> None:
            cleaned.append(p)
        for reader, expected in (
            (lambda _: "12345\n", "unexpected_process_present"),
            (lambda _: (_ for _ in ()).throw(PermissionError(13)),
             "membership_unreadable"),
        ):
            with self.subTest(expected=expected):
                result = check_empty_child(
                    Path("/example/ci"), lambda _: None, cleanup,
                    reader, "d" * 24,
                )
                self.assertEqual(result["empty_child_probe"], expected)
        self.assertEqual(len(cleaned), 2)

    def test_unsafe_suffix_cannot_create_anything(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsafe"):
            check_empty_child(
                Path("/example"), lambda _: self.fail("write"), lambda _: None,
                lambda _: "", "../escape",
            )

    def test_active_mode_remains_unverified_on_nonlinux(self) -> None:
        result = optional_empty_child_probe(
            inspect("win32", "", "", fake_reader()), "", ""
        )
        self.assertEqual(result["empty_child_probe"], "skipped_preconditions")
        self.assertFalse(result["active_delegation_verified"])
        self.assertFalse(result["empty_child_creation_verified"])
        self.assertFalse(result["enforcement_tested"])

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
