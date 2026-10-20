"""Native retained-handle accounting; only controlled Python children execute."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

import psutil
from unittest.mock import patch

if sys.platform == "win32":
    from _internal import windows_process_usage as usage


@unittest.skipUnless(sys.platform == "win32", "native Windows accounting only")
class WindowsUsageTests(unittest.TestCase):
    def test_final_usage_after_exit_and_original_handle_close(self):
        for status in (0, 7):
            with self.subTest(status=status):
                # Use the base interpreter: Windows venv launchers may create
                # a separate child outside this intentionally direct-process scope.
                # Touch 16 MiB then release before exit; final current RSS would
                # miss this allocation. No timing or CPU-speed threshold.
                code = ("import time; data=bytearray(16*1024*1024); "
                        "data[::4096]=b'x'*4096; del data; "
                        "end=time.process_time()+0.05; "
                        "exec('while time.process_time()<end: pass'); "
                        f"raise SystemExit({status})")
                child = psutil.Popen([getattr(sys, "_base_executable", sys.executable), "-c", code])
                owned = usage.WindowsProcessUsage(child)
                try:
                    self.assertEqual(child.wait(timeout=10), status)
                    child._handle.Close()
                    peak, cpu = owned.final()
                    self.assertGreaterEqual(peak, 16 * 1024 * 1024)
                    self.assertGreater(cpu, 0)
                    self.assertEqual(owned.final(), (peak, cpu))
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.wait()
                    owned.close()
                owned.close()  # Idempotent, never double-close a reused handle.
                with self.assertRaisesRegex(OSError, "closed"):
                    owned.final()

    def test_real_analyzer_without_psutil_samples(self):
        from profile_resources import profile_once
        root = Path(__file__).resolve().parent.parent
        binary = root / "target/release/rel-inspect.exe"
        if not binary.is_file():
            self.skipTest("Release analyzer not built locally; required by CI build step")
        with patch.object(psutil.Popen, "memory_info", side_effect=psutil.AccessDenied()):
            result = profile_once(binary, root / "fixtures/pe32-basic.exe")
        self.assertEqual(result["resource_samples"], 0)
        self.assertIsNone(result["sampled_peak_rss_bytes"])
        self.assertIsNone(result["last_sampled_cpu_ms"])
        self.assertGreater(result["windows_peak_working_set_bytes"], 0)
        self.assertGreaterEqual(result["windows_cpu_ms"], 0)
        self.assertIsNone(result["kernel_peak_rss_bytes"])

    def test_immediate_exit_retains_measurements(self):
        for _ in range(3):
            child = psutil.Popen([getattr(sys, "_base_executable", sys.executable), "-c", "pass"])
            owned = usage.WindowsProcessUsage(child)
            try:
                child.wait(timeout=10)
                peak, cpu = owned.final()
                self.assertGreater(peak, 0)
                self.assertGreaterEqual(cpu, 0)
            finally:
                owned.close()

    def test_running_child_is_not_final_accounting(self):
        child = psutil.Popen([getattr(sys, "_base_executable", sys.executable), "-c", "import time; time.sleep(30)"])
        owned = usage.WindowsProcessUsage(child)
        try:
            with self.assertRaisesRegex(OSError, "still running"):
                owned.final()
        finally:
            child.kill()
            child.wait()
            owned.close()

    def test_invalid_creation_handle_fails_closed(self):
        class Invalid:
            _handle = 0
        with self.assertRaisesRegex(OSError, "DuplicateHandle"):
            usage.WindowsProcessUsage(Invalid())
        with self.assertRaisesRegex(OSError, "unavailable"):
            usage.WindowsProcessUsage(object())

    def test_api_failures_never_become_zero_measurements(self):
        child = psutil.Popen([getattr(sys, "_base_executable", sys.executable), "-c", "pass"])
        owned = usage.WindowsProcessUsage(child)
        try:
            child.wait(timeout=10)
            for function, message in (("MEMORY", "K32GetProcessMemoryInfo"),
                                      ("TIMES", "GetProcessTimes")):
                with self.subTest(function=function), patch.object(usage, function, return_value=0):
                    with self.assertRaisesRegex(OSError, message):
                        owned.final()
            with patch.object(usage, "WAIT", return_value=0xFFFFFFFF):
                with self.assertRaisesRegex(OSError, "WaitForSingleObject"):
                    owned.final()
        finally:
            owned.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)

