#!/usr/bin/env python3
"""Cross-platform direct-child watchdog regressions and real REL CLI smoke."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import psutil

from run_bounded_inspection import (
    LimitExceeded, WorkerFailed, sampled_linux_tree_rss, supervise,
)

ROOT = Path(__file__).resolve().parents[1]
BINARY: Path | None = None
# A Windows venv executable can be a redirector whose child runs Python.
# Resource/Job Object tests need the interpreter itself as the direct child.
# CLI integration below deliberately keeps sys.executable and its environment.
CONTROLLED_PYTHON = getattr(sys, "_base_executable", sys.executable)


def python_child(source: str, **kwargs: object) -> bytes:
    return supervise(
        [CONTROLLED_PYTHON, "-c", source],
        wall_seconds=5,
        max_sampled_rss_bytes=256 * 1024 * 1024,
        **kwargs,
    )


class WatchdogTests(unittest.TestCase):
    def test_controlled_interpreter_runs_in_the_created_process(self) -> None:
        # A redirector could otherwise make RSS/job tests observe the launcher
        # while allocations and descendant creation happen in another process.
        child = subprocess.Popen(
            [CONTROLLED_PYTHON, "-c", "import os; print(os.getpid())"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            stdout, stderr = child.communicate(timeout=10)
            self.assertEqual(child.returncode, 0, stderr.decode(errors="replace"))
            self.assertEqual(int(stdout.strip()), child.pid)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)

    def test_returns_byte_exact_stdout_only_after_success(self) -> None:
        result = python_child("import sys;sys.stdout.buffer.write(b'abc\\x00xyz')")
        self.assertEqual(result, b"abc\x00xyz")

    def test_child_failure_does_not_publish_partial_stdout(self) -> None:
        with self.assertRaisesRegex(WorkerFailed, "status 7"):
            python_child(
                "import sys;sys.stdout.write('partial');"
                "sys.stderr.write('deliberate failure');sys.exit(7)"
            )

    def test_terminates_hung_direct_child(self) -> None:
        started = time.monotonic()
        with self.assertRaises(LimitExceeded) as raised:
            supervise(
                [CONTROLLED_PYTHON, "-c", "import time;time.sleep(10)"],
                wall_seconds=0.2,
                max_sampled_rss_bytes=256 * 1024 * 1024,
            )
        self.assertEqual(raised.exception.kind, "wall")
        self.assertLess(time.monotonic() - started, 5)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux groups only")
    def test_linux_wall_timeout_terminates_descendant_in_same_group(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rel-linux-group-") as folder:
            ready = Path(folder) / "ready"
            escaped = Path(folder) / "escaped"
            descendant = (
                "import pathlib,time;"
                "time.sleep(2.3);"
                f"pathlib.Path({str(escaped)!r}).write_text('survived')"
            )
            parent = (
                "import pathlib,subprocess,sys,time;"
                f"subprocess.Popen([sys.executable,'-c',{descendant!r}]);"
                f"pathlib.Path({str(ready)!r}).write_text('spawned');"
                "time.sleep(10)"
            )
            with self.assertRaises(LimitExceeded) as raised:
                supervise(
                    [CONTROLLED_PYTHON, "-c", parent],
                    wall_seconds=1.0,
                    max_sampled_rss_bytes=256 * 1024 * 1024,
                )
            self.assertEqual(raised.exception.kind, "wall")
            self.assertTrue(ready.exists(), "descendant was never spawned")
            time.sleep(2.4)
            self.assertFalse(escaped.exists(), "descendant survived wall timeout")

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux groups only")
    def test_linux_success_cleans_up_remaining_group_descendant(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rel-linux-group-") as folder:
            escaped = Path(folder) / "escaped"
            descendant = (
                "import pathlib,time;"
                "time.sleep(1.1);"
                f"pathlib.Path({str(escaped)!r}).write_text('survived')"
            )
            parent = (
                "import subprocess,sys,time;"
                f"subprocess.Popen([sys.executable,'-c',{descendant!r}]);"
                "time.sleep(0.15);print('parent succeeded')"
            )
            output = supervise(
                [CONTROLLED_PYTHON, "-c", parent],
                wall_seconds=5,
                max_sampled_rss_bytes=256 * 1024 * 1024,
            )
            self.assertEqual(output.strip(), b"parent succeeded")
            time.sleep(1.3)
            self.assertFalse(escaped.exists(), "descendant survived parent exit")

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux RSS-tree only")
    def test_linux_opt_in_tree_rss_rejects_memory_hungry_descendant(self) -> None:
        # Reproduce the direct-child-only gap first: the parent stays small,
        # while its controlled child holds >= 96 MiB resident.
        with tempfile.TemporaryDirectory(prefix="rel-tree-rss-") as folder:
            ready = Path(folder) / "allocated"
            descendant = (
                "import pathlib,time;"
                "payload=bytearray(b'x'*(96*1024*1024));"
                f"pathlib.Path({str(ready)!r}).write_text('ready');"
                "time.sleep(10)"
            )
            parent = (
                "import pathlib,subprocess,sys,time\n"
                f"subprocess.Popen([sys.executable,'-c',{descendant!r}])\n"
                f"ready=pathlib.Path({str(ready)!r})\n"
                "end=time.monotonic()+4\n"
                "while not ready.exists() and time.monotonic()<end:\n"
                "    time.sleep(0.01)\n"
                "if not ready.exists():\n"
                "    sys.exit(71)\n"
                "time.sleep(0.4)\n"
                "print('parent completed')\n"
            )
            command = [CONTROLLED_PYTHON, "-c", parent]
            direct_only = supervise(
                command, wall_seconds=6,
                max_sampled_rss_bytes=48 * 1024 * 1024,
            )
            self.assertEqual(direct_only.strip(), b"parent completed")
            ready.unlink()
            with self.assertRaises(LimitExceeded) as raised:
                supervise(
                    command, wall_seconds=6,
                    max_sampled_rss_bytes=256 * 1024 * 1024,
                    max_sampled_tree_rss_bytes=48 * 1024 * 1024,
                )
            self.assertEqual(raised.exception.kind, "rss")
            self.assertIn("descendant-tree", str(raised.exception))

    def test_tree_rss_enumeration_denial_is_controlled_failure(self) -> None:
        parent = Mock()
        for error in (psutil.AccessDenied(pid=123), psutil.NoSuchProcess(123)):
            with self.subTest(exception=type(error).__name__):
                parent.children.side_effect = error
                with self.assertRaisesRegex(
                    WorkerFailed, "unable to enumerate analyzer descendants"
                ):
                    sampled_linux_tree_rss(parent, 1024)
                parent.children.assert_called_with(recursive=True)

    def test_tree_rss_refuses_unreadable_descendant(self) -> None:
        parent = Mock()
        descendant = Mock()
        descendant.memory_info.side_effect = psutil.AccessDenied(pid=234)
        parent.children.return_value = [descendant]
        with self.assertRaisesRegex(WorkerFailed, "unable to sample descendant RSS"):
            sampled_linux_tree_rss(parent, 1024)

    def test_tree_rss_skips_vanished_descendant_but_counts_live_one(self) -> None:
        parent = Mock()
        vanished = Mock()
        vanished.memory_info.side_effect = psutil.NoSuchProcess(345)
        live = Mock()
        live.memory_info.return_value.rss = 4096
        parent.children.return_value = [vanished, live]
        self.assertEqual(sampled_linux_tree_rss(parent, 1024), 5120)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux tree RSS only")
    def test_linux_tree_probe_denial_stops_worker_without_publishing_output(self) -> None:
        # The real child is alive and has emitted bytes to its private spool.
        # Force an inaccessible tree query; this must be a controlled error,
        # not a traceback or a partial manifest on public stdout.
        with patch(
            "run_bounded_inspection.psutil.Popen.children",
            side_effect=psutil.AccessDenied(pid=456),
        ):
            with self.assertRaisesRegex(
                WorkerFailed, "unable to enumerate analyzer descendants"
            ):
                supervise(
                    [
                        CONTROLLED_PYTHON, "-c",
                        "import time;print('partial',flush=True);time.sleep(10)",
                    ],
                    wall_seconds=5,
                    max_sampled_rss_bytes=256 * 1024 * 1024,
                    max_sampled_tree_rss_bytes=128 * 1024 * 1024,
                )

    def test_sampled_tree_budget_rejected_on_unsupported_platform(self) -> None:
        if sys.platform.startswith("linux"):
            with self.assertRaisesRegex(ValueError, "positive"):
                python_child("print('not launched')", max_sampled_tree_rss_bytes=0)
        else:
            with self.assertRaisesRegex(ValueError, "requires Linux"):
                python_child("print('not launched')", max_sampled_tree_rss_bytes=1024)

    @unittest.skipIf(sys.platform.startswith("linux"), "Linux supports this flag")
    def test_nonlinux_cli_rejects_sampled_tree_flag(self) -> None:
        result = subprocess.run(
            [
                sys.executable, str(ROOT / "scripts/run_bounded_inspection.py"),
                "--binary", str(BINARY), "--input", str(ROOT / "fixtures/pe64-basic.exe"),
                "--max-sampled-tree-rss-mib", "128",
            ],
            capture_output=True, check=False, timeout=10,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"supported only on Linux", result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_stops_observed_rss_above_budget(self) -> None:
        with self.assertRaises(LimitExceeded) as raised:
            supervise(
                [
                    CONTROLLED_PYTHON, "-c",
                    "import time;x=bytearray(80*1024*1024);time.sleep(2)",
                ],
                wall_seconds=5,
                max_sampled_rss_bytes=32 * 1024 * 1024,
            )
        self.assertEqual(raised.exception.kind, "rss")

    def test_rejects_overlarge_stdout_before_publication(self) -> None:
        with self.assertRaisesRegex(WorkerFailed, "stdout exceeded"):
            python_child("import sys;sys.stdout.write('123456789')", max_stdout_bytes=8)

    def test_stops_running_child_after_stdout_spool_limit(self) -> None:
        started = time.monotonic()
        with self.assertRaisesRegex(WorkerFailed, "stdout exceeded"):
            python_child(
                "import os,time;os.write(1,b'0123456789');time.sleep(10)",
                max_stdout_bytes=8,
            )
        self.assertLess(time.monotonic() - started, 3)

    def test_stops_running_child_after_stderr_spool_limit(self) -> None:
        started = time.monotonic()
        with self.assertRaisesRegex(WorkerFailed, "stderr exceeded"):
            python_child(
                "import os,time;os.write(2,b'0123456789');time.sleep(10)",
                max_stderr_bytes=8,
            )
        self.assertLess(time.monotonic() - started, 3)

    def test_rejects_successful_child_with_overbudget_stderr(self) -> None:
        with self.assertRaisesRegex(WorkerFailed, "stderr exceeded"):
            python_child(
                "import sys;sys.stderr.write('0123456789')",
                max_stderr_bytes=8,
            )

    def test_rejects_invalid_limits_before_launch(self) -> None:
        with self.assertRaises(ValueError):
            python_child("print('never launched')", poll_seconds=0)
        with self.assertRaises(ValueError):
            python_child("print('never launched')", max_stderr_bytes=0)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux RLIMIT_FSIZE only")
    def test_linux_kernel_file_size_ceiling_is_installed_before_exec(self) -> None:
        import resource

        # The wrapper must respect a pre-existing smaller hard ceiling.
        _, inherited_hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        budget = max(4096, 1024) + 1
        if inherited_hard != resource.RLIM_INFINITY:
            budget = min(budget, inherited_hard)
        output = python_child(
            "import resource;print(resource.getrlimit(resource.RLIMIT_FSIZE))",
            max_stdout_bytes=4096,
            max_stderr_bytes=1024,
        )
        self.assertEqual(output.strip(), f"({budget}, {budget})".encode())

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux RLIMIT_FSIZE only")
    def test_linux_kernel_stops_fast_large_file_write_between_polls(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rel-fsize-") as directory:
            output_file = Path(directory) / "oversized.bin"
            script = (
                "import errno,signal,sys\n"
                "signal.signal(signal.SIGXFSZ, signal.SIG_IGN)\n"
                f"with open({str(output_file)!r}, 'wb', buffering=0) as handle:\n"
                "    try:\n"
                "        while True:\n"
                "            handle.write(b'x' * 65536)\n"
                "    except OSError as error:\n"
                "        if error.errno != errno.EFBIG:\n"
                "            raise\n"
                "        sys.stderr.write('kernel EFBIG')\n"
                "        sys.exit(79)\n"
            )
            with self.assertRaisesRegex(WorkerFailed, "status 79: kernel EFBIG"):
                python_child(
                    script, max_stdout_bytes=4096, max_stderr_bytes=1024,
                    poll_seconds=1,
                )
            self.assertGreater(output_file.stat().st_size, 0)
            self.assertLessEqual(output_file.stat().st_size, 4097)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux RLIMIT_AS only")
    def test_linux_kernel_address_space_limit_is_installed_before_exec(self) -> None:
        limit = 128 * 1024 * 1024
        output = supervise(
            [
                CONTROLLED_PYTHON, "-c",
                "import resource;print(resource.getrlimit(resource.RLIMIT_AS))",
            ],
            wall_seconds=5,
            max_sampled_rss_bytes=256 * 1024 * 1024,
            max_address_space_bytes=limit,
        )
        self.assertEqual(output.strip(), f"({limit}, {limit})".encode())

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux RLIMIT_AS only")
    def test_linux_kernel_denies_allocation_above_address_space_limit(self) -> None:
        script = (
            "import sys\n"
            "try:\n"
            "    value = bytearray(256 * 1024 * 1024)\n"
            "except MemoryError:\n"
            "    sys.exit(73)\n"
            "sys.exit(0)\n"
        )
        with self.assertRaisesRegex(WorkerFailed, "status 73"):
            supervise(
                [CONTROLLED_PYTHON, "-c", script],
                wall_seconds=5,
                max_sampled_rss_bytes=512 * 1024 * 1024,
                max_address_space_bytes=128 * 1024 * 1024,
            )

    def test_rejects_native_cap_when_unsupported(self) -> None:
        if sys.platform.startswith("linux"):
            with self.assertRaisesRegex(ValueError, "positive"):
                python_child("print('not launched')", max_address_space_bytes=0)
        else:
            with self.assertRaisesRegex(ValueError, "requires Linux"):
                python_child("print('not launched')", max_address_space_bytes=1024)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux RLIMIT_AS only")
    def test_linux_cli_rejects_too_small_address_space_cap(self) -> None:
        result = subprocess.run(
            [
                sys.executable, str(ROOT / "scripts" / "run_bounded_inspection.py"),
                "--binary", str(BINARY), "--input", str(ROOT / "fixtures/pe64-basic.exe"),
                "--max-address-space-mib", "16",
            ],
            capture_output=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"between 128 and 8192", result.stderr)
        self.assertEqual(result.stdout, b"")

    @unittest.skipIf(sys.platform.startswith("linux"), "Linux supports this flag")
    def test_nonlinux_cli_rejects_address_space_cap(self) -> None:
        result = subprocess.run(
            [
                sys.executable, str(ROOT / "scripts" / "run_bounded_inspection.py"),
                "--binary", str(BINARY), "--input", str(ROOT / "fixtures/pe64-basic.exe"),
                "--max-address-space-mib", "512",
            ],
            capture_output=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"supported only on Linux", result.stderr)
        self.assertEqual(result.stdout, b"")

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux RLIMIT_CPU only")
    def test_linux_cpu_budget_installed_before_exec_with_address_limit(self) -> None:
        output = supervise(
            [
                CONTROLLED_PYTHON, "-c",
                "import resource;"
                "print(resource.getrlimit(resource.RLIMIT_CPU));"
                "print(resource.getrlimit(resource.RLIMIT_AS))",
            ],
            wall_seconds=8,
            max_sampled_rss_bytes=256 * 1024 * 1024,
            max_address_space_bytes=512 * 1024 * 1024,
            max_cpu_seconds=3,
        )
        self.assertEqual(output.splitlines(), [
            b"(3, 4)",
            f"({512 * 1024 * 1024}, {512 * 1024 * 1024})".encode(),
        ])

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux RLIMIT_CPU only")
    def test_linux_kernel_interrupts_busy_child_at_cpu_limit(self) -> None:
        with self.assertRaisesRegex(
            WorkerFailed, f"status {-signal.SIGXCPU}"
        ):
            supervise(
                [CONTROLLED_PYTHON, "-c", "while True: pass"],
                wall_seconds=15,
                max_sampled_rss_bytes=256 * 1024 * 1024,
                max_cpu_seconds=1,
            )

    def test_rejects_native_cpu_budget_on_unsupported_platform(self) -> None:
        if sys.platform.startswith("linux"):
            with self.assertRaisesRegex(ValueError, "between 1 and 300"):
                python_child("print('not launched')", max_cpu_seconds=0)
        else:
            with self.assertRaisesRegex(ValueError, "RLIMIT_CPU option requires Linux"):
                python_child("print('not launched')", max_cpu_seconds=1)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux RLIMIT_CPU only")
    def test_linux_cli_rejects_invalid_cpu_seconds(self) -> None:
        result = subprocess.run(
            [
                sys.executable, str(ROOT / "scripts" / "run_bounded_inspection.py"),
                "--binary", str(BINARY), "--input", str(ROOT / "fixtures/pe64-basic.exe"),
                "--max-cpu-seconds", "0",
            ],
            capture_output=True, check=False, timeout=10,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"between 1 and 300", result.stderr)
        self.assertEqual(result.stdout, b"")

    @unittest.skipIf(sys.platform.startswith("linux"), "Linux supports RLIMIT_CPU")
    def test_nonlinux_cli_rejects_cpu_seconds(self) -> None:
        result = subprocess.run(
            [
                sys.executable, str(ROOT / "scripts" / "run_bounded_inspection.py"),
                "--binary", str(BINARY), "--input", str(ROOT / "fixtures/pe64-basic.exe"),
                "--max-cpu-seconds", "3",
            ],
            capture_output=True, check=False, timeout=10,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"supported only on Linux", result.stderr)
        self.assertEqual(result.stdout, b"")

    @unittest.skipUnless(os.name == "nt", "Windows Job Objects only")
    def test_windows_job_runs_assigned_child(self) -> None:
        result = supervise(
            [CONTROLLED_PYTHON, "-c", "print('assigned before run')"],
            wall_seconds=5,
            max_sampled_rss_bytes=512 * 1024 * 1024,
            max_job_memory_bytes=256 * 1024 * 1024,
        )
        self.assertEqual(result.strip(), b"assigned before run")

    @unittest.skipUnless(os.name == "nt", "Windows Job Objects only")
    def test_windows_job_rejects_oversized_memory_commit(self) -> None:
        script = (
            "import sys\n"
            "try:\n"
            "    data = bytearray(512 * 1024 * 1024)\n"
            "except MemoryError:\n"
            "    sys.exit(73)\n"
            "sys.exit(0)\n"
        )
        # A successful 512 MiB allocation under a 128 MiB job budget
        # would violate the native job-commit policy.
        with self.assertRaises(WorkerFailed):
            supervise(
                [CONTROLLED_PYTHON, "-c", script],
                wall_seconds=5,
                max_sampled_rss_bytes=1024 * 1024 * 1024,
                max_job_memory_bytes=128 * 1024 * 1024,
            )

    @unittest.skipUnless(os.name == "nt", "Windows Job Objects only")
    def test_windows_job_closing_terminates_descendant(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rel-job-test-") as folder:
            ready = Path(folder) / "ready"
            escaped = Path(folder) / "escaped"
            descendant = (
                "import time,pathlib;"
                "time.sleep(4);"
                f"pathlib.Path({str(escaped)!r}).write_text('survived')"
            )
            parent = (
                "import pathlib,subprocess,sys,time;"
                f"subprocess.Popen([sys.executable,'-c',{descendant!r}]);"
                f"pathlib.Path({str(ready)!r}).write_text('spawned');"
                "time.sleep(20)"
            )
            with self.assertRaises(LimitExceeded) as limit:
                supervise(
                    [CONTROLLED_PYTHON, "-c", parent],
                    wall_seconds=2.0,
                    max_sampled_rss_bytes=512 * 1024 * 1024,
                    max_job_memory_bytes=256 * 1024 * 1024,
                )
            self.assertEqual(limit.exception.kind, "wall")
            self.assertTrue(ready.exists(), "test descendant was never spawned")
            time.sleep(4.2)
            self.assertFalse(
                escaped.exists(), "descendant survived kill-on-close"
            )

    @unittest.skipUnless(os.name == "nt", "Windows Job Objects only")
    def test_windows_job_cpu_only_runs_assigned_child(self) -> None:
        # CPU-only mode must still assign before resuming the analyzer.
        result = python_child(
            "print('native CPU-only job')", max_job_cpu_seconds=10
        )
        self.assertEqual(result.strip(), b"native CPU-only job")

    @unittest.skipUnless(os.name == "nt", "Windows Job Objects only")
    def test_windows_job_cpu_limit_terminates_busy_child(self) -> None:
        # Set a generous wall limit: a native per-job user-CPU limit
        # should stop this busy direct child first (not a wall timeout).
        with self.assertRaises(WorkerFailed) as raised:
            supervise(
                [CONTROLLED_PYTHON, "-c", "while True: pass"],
                wall_seconds=20,
                max_sampled_rss_bytes=512 * 1024 * 1024,
                max_job_cpu_seconds=1,
            )
        self.assertIn("analyzer exited with status", str(raised.exception))

    @unittest.skipUnless(os.name == "nt", "Windows Job Objects only")
    def test_windows_job_cpu_and_memory_limits_can_be_combined(self) -> None:
        result = python_child(
            "print('both limits')",
            max_job_memory_bytes=256 * 1024 * 1024,
            max_job_cpu_seconds=10,
        )
        self.assertEqual(result.strip(), b"both limits")

    def test_rejects_invalid_job_cpu_budget_before_launch(self) -> None:
        if os.name == "nt":
            with self.assertRaisesRegex(ValueError, "between 1 and 300"):
                python_child("print('not launched')", max_job_cpu_seconds=0)
        else:
            with self.assertRaisesRegex(ValueError, "requires Windows"):
                python_child("print('not launched')", max_job_cpu_seconds=1)

    @unittest.skipUnless(os.name != "nt", "Windows supports this flag")
    def test_nonwindows_cli_rejects_job_cpu_option_before_launch(self) -> None:
        result = subprocess.run(
            [
                sys.executable, str(ROOT / "scripts" / "run_bounded_inspection.py"),
                "--binary", str(BINARY), "--input", str(ROOT / "fixtures/pe64-basic.exe"),
                "--max-job-cpu-seconds", "10",
            ],
            capture_output=True, check=False, timeout=10,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"supported only on Windows", result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_rejects_native_job_cap_on_unsupported_platform(self) -> None:
        if os.name != "nt":
            with self.assertRaisesRegex(ValueError, "requires Windows"):
                python_child("print('never started')", max_job_memory_bytes=1024)
        else:
            with self.assertRaisesRegex(ValueError, "positive"):
                python_child("print('never started')", max_job_memory_bytes=0)

    @unittest.skipUnless(os.name != "nt", "Windows supports this flag")
    def test_nonwindows_cli_rejects_job_option_before_launch(self) -> None:
        result = subprocess.run(
            [
                sys.executable, str(ROOT / "scripts" / "run_bounded_inspection.py"),
                "--binary", str(BINARY), "--input", str(ROOT / "fixtures/pe64-basic.exe"),
                "--max-job-memory-mib", "512",
            ],
            capture_output=True, check=False, timeout=10,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"supported only on Windows", result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_real_rel_cli_manifest_preserved(self) -> None:
        self.assertIsNotNone(BINARY)
        fixture = ROOT / "fixtures" / "pe64-basic.exe"
        command = [
            sys.executable, str(ROOT / "scripts" / "run_bounded_inspection.py"),
            "--binary", str(BINARY), "--input", str(fixture),
            "--wall-seconds", "30", "--max-sampled-rss-mib", "512",
        ]
        if sys.platform.startswith("linux"):
            command.extend([
                "--max-address-space-mib", "2048",
                "--max-cpu-seconds", "10",
                "--max-sampled-tree-rss-mib", "512",
            ])
        if os.name == "nt":
            command.extend([
                "--max-job-memory-mib", "512",
                "--max-job-cpu-seconds", "10",
            ])
        done = subprocess.run(
            command,
            capture_output=True,
            check=False,
            timeout=45,
        )
        self.assertEqual(done.returncode, 0, done.stderr.decode(errors="replace"))
        document = json.loads(done.stdout)
        self.assertEqual(document["schema_version"], "1.0.0")
        self.assertEqual(document["size_bytes"], fixture.stat().st_size)
        self.assertEqual(
            document["binary_sha256"], hashlib.sha256(fixture.read_bytes()).hexdigest()
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    BINARY = parser.parse_args().binary.resolve(strict=True)
    unittest.main(argv=[sys.argv[0]], verbosity=2)
