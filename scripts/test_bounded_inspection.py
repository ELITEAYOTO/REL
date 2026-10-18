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

from run_bounded_inspection import LimitExceeded, WorkerFailed, supervise

ROOT = Path(__file__).resolve().parents[1]
BINARY: Path | None = None


def python_child(source: str, **kwargs: object) -> bytes:
    return supervise(
        [sys.executable, "-c", source],
        wall_seconds=5,
        max_sampled_rss_bytes=256 * 1024 * 1024,
        **kwargs,
    )


class WatchdogTests(unittest.TestCase):
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
                [sys.executable, "-c", "import time;time.sleep(10)"],
                wall_seconds=0.2,
                max_sampled_rss_bytes=256 * 1024 * 1024,
            )
        self.assertEqual(raised.exception.kind, "wall")
        self.assertLess(time.monotonic() - started, 5)

    def test_stops_observed_rss_above_budget(self) -> None:
        with self.assertRaises(LimitExceeded) as raised:
            supervise(
                [
                    sys.executable, "-c",
                    "import time;x=bytearray(80*1024*1024);time.sleep(2)",
                ],
                wall_seconds=5,
                max_sampled_rss_bytes=32 * 1024 * 1024,
            )
        self.assertEqual(raised.exception.kind, "rss")

    def test_rejects_overlarge_stdout_before_publication(self) -> None:
        with self.assertRaisesRegex(WorkerFailed, "stdout exceeded"):
            python_child("import sys;sys.stdout.write('123456789')", max_stdout_bytes=8)

    def test_rejects_invalid_limits_before_launch(self) -> None:
        with self.assertRaises(ValueError):
            python_child("print('never launched')", poll_seconds=0)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux RLIMIT_AS only")
    def test_linux_kernel_address_space_limit_is_installed_before_exec(self) -> None:
        limit = 128 * 1024 * 1024
        output = supervise(
            [
                sys.executable, "-c",
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
                [sys.executable, "-c", script],
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
                sys.executable, "-c",
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
                [sys.executable, "-c", "while True: pass"],
                wall_seconds=15,
                max_sampled_rss_bytes=256 * 1024 * 1024,
                max_cpu_seconds=1,
            )

    def test_rejects_native_cpu_budget_on_unsupported_platform(self) -> None:
        if sys.platform.startswith("linux"):
            with self.assertRaisesRegex(ValueError, "between 1 and 300"):
                python_child("print('not launched')", max_cpu_seconds=0)
        else:
            with self.assertRaisesRegex(ValueError, "require Linux"):
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
            [sys.executable, "-c", "print('assigned before run')"],
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
                [sys.executable, "-c", script],
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
                    [sys.executable, "-c", parent],
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
            command.extend(["--max-address-space-mib", "2048", "--max-cpu-seconds", "10"])
        if os.name == "nt":
            command.extend(["--max-job-memory-mib", "512"])
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
