#!/usr/bin/env python3
"""Opt-in REL CLI watchdog; this runs the analyzer, never the inspected PE.

It kills the direct child after a wall-time breach and checks sampled RSS.
On Linux, optional RLIMIT_AS and RLIMIT_CPU constrain virtual address space
and per-process CPU time before exec. These are not resident-memory or
process-tree limits, nor a sandbox.
"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Sequence

import psutil

DEFAULT_WALL_SECONDS = 30.0
DEFAULT_SAMPLED_RSS_MIB = 512
POLL_SECONDS = 0.01
MAX_STDOUT_BYTES = 16 * 1024 * 1024 + 1
MAX_STDERR_BYTES = 1024 * 1024


class LimitExceeded(RuntimeError):
    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


class WorkerFailed(RuntimeError):
    """Child failure or unavailable observation."""


def reject_oversized_spools(stdout, stderr, max_stdout: int, max_stderr: int) -> None:
    """Sample spool lengths; this cannot enforce a hard kernel disk quota."""
    if os.fstat(stdout.fileno()).st_size > max_stdout:
        raise WorkerFailed("analyzer stdout exceeded bounded JSON size")
    if os.fstat(stderr.fileno()).st_size > max_stderr:
        raise WorkerFailed("analyzer stderr exceeded diagnostic spool budget")


def stop_linux_process_group(child: psutil.Popen) -> None:
    """Kill the child's dedicated Linux process group, including ordinary forks.

    Descendants that deliberately create another session can escape; this is
    cleanup of an owned group, not a process-tree security boundary.
    """
    if not sys.platform.startswith("linux"):
        return
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def supervise(
    command: Sequence[str],
    *,
    wall_seconds: float,
    max_sampled_rss_bytes: int,
    max_address_space_bytes: int | None = None,
    max_cpu_seconds: int | None = None,
    max_job_memory_bytes: int | None = None,
    poll_seconds: float = POLL_SECONDS,
    max_stdout_bytes: int = MAX_STDOUT_BYTES,
    max_stderr_bytes: int = MAX_STDERR_BYTES,
) -> bytes:
    """Return complete stdout only after a successful direct-child exit."""
    if not command or not 0 < wall_seconds <= 600 or not 0 < poll_seconds <= 1:
        raise ValueError("invalid command or watchdog timing")
    if max_sampled_rss_bytes <= 0 or max_stdout_bytes <= 0 or max_stderr_bytes <= 0:
        raise ValueError("limits must be positive")

    if max_job_memory_bytes is not None:
        if max_job_memory_bytes <= 0:
            raise ValueError("job memory budget must be positive")
        if os.name != "nt":
            raise ValueError("Windows Job Object budget requires Windows")

    # A dedicated session makes ordinary descendants terminate with the analyzer
    # even if they outlive their parent. No process-group isolation on Windows.
    child_options = {"start_new_session": True} if sys.platform.startswith("linux") else {}
    if max_address_space_bytes is not None or max_cpu_seconds is not None:
        if not sys.platform.startswith("linux"):
            if max_address_space_bytes is not None:
                raise ValueError("RLIMIT_AS option requires Linux")
            raise ValueError("RLIMIT_CPU option requires Linux")
        if max_address_space_bytes is not None and max_address_space_bytes <= 0:
            raise ValueError("address-space limit must be positive")
        if max_cpu_seconds is not None and not 1 <= max_cpu_seconds <= 300:
            raise ValueError("CPU-time limit must be between 1 and 300 seconds")
        import resource

        # Set both kernel limits on the direct child BEFORE exec. preexec_fn
        # is used only in this intentionally single-threaded CLI wrapper.
        def apply_linux_limits() -> None:
            if max_address_space_bytes is not None:
                resource.setrlimit(
                    resource.RLIMIT_AS,
                    (max_address_space_bytes, max_address_space_bytes),
                )
            if max_cpu_seconds is not None:
                # SIGXCPU is delivered at the soft boundary; the hard
                # boundary stops a child that catches/ignores SIGXCPU.
                resource.setrlimit(
                    resource.RLIMIT_CPU, (max_cpu_seconds, max_cpu_seconds + 1)
                )

        child_options["preexec_fn"] = apply_linux_limits

    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        child = None
        job = None
        try:
            child_kwargs = dict(
                stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                **child_options,
            )
            if max_job_memory_bytes is not None:
                from windows_job import WindowsJob

                job = WindowsJob(max_job_memory_bytes)
                child = job.start(command, **child_kwargs)
            else:
                child = psutil.Popen(list(command), **child_kwargs)
            started = time.monotonic()
            while child.poll() is None:
                # Reject a continuously writing child before it reaches the
                # wall deadline. A poll can still miss a transient disk spike.
                reject_oversized_spools(
                    stdout, stderr, max_stdout_bytes, max_stderr_bytes
                )
                elapsed = time.monotonic() - started
                if elapsed >= wall_seconds:
                    raise LimitExceeded("wall", f"wall time exceeded {wall_seconds:g}s")
                try:
                    rss = child.memory_info().rss
                except psutil.NoSuchProcess:
                    continue
                except psutil.AccessDenied as error:
                    raise WorkerFailed("unable to monitor child RSS") from error
                if rss > max_sampled_rss_bytes:
                    raise LimitExceeded(
                        "rss", f"sampled child RSS exceeded {max_sampled_rss_bytes} bytes"
                    )
                time.sleep(min(poll_seconds, max(0.0, wall_seconds - elapsed)))

            status = child.wait()
            stop_linux_process_group(child)
            reject_oversized_spools(
                stdout, stderr, max_stdout_bytes, max_stderr_bytes
            )
            if status:
                stderr.seek(0)
                detail = stderr.read(512).decode("utf-8", errors="replace").strip()
                raise WorkerFailed(f"analyzer exited with status {status}: {detail}")
            stdout.seek(0)
            result = stdout.read(max_stdout_bytes + 1)
            if len(result) > max_stdout_bytes:
                raise WorkerFailed("analyzer stdout exceeded bounded JSON size")
            return result
        except BaseException:
            # Closing the Job Object terminates associated descendants too.
            if job is not None:
                job.close()
            if child is not None:
                stop_linux_process_group(child)
                if child.poll() is None:
                    try:
                        child.kill()
                    except psutil.NoSuchProcess:
                        pass
                child.wait(timeout=5)
            raise
        finally:
            if job is not None:
                job.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--wall-seconds", type=float, default=DEFAULT_WALL_SECONDS)
    parser.add_argument("--max-sampled-rss-mib", type=int, default=DEFAULT_SAMPLED_RSS_MIB)
    parser.add_argument(
        "--max-address-space-mib", type=int,
        help="Linux only: optional RLIMIT_AS virtual address-space cap (MiB)",
    )
    parser.add_argument(
        "--max-job-memory-mib", type=int,
        help="Windows only: aggregate Job Object memory commit cap (MiB)",
    )
    parser.add_argument(
        "--max-cpu-seconds", type=int,
        help="Linux only: optional per-process kernel RLIMIT_CPU budget (seconds)",
    )
    args = parser.parse_args(argv)
    if not 0 < args.wall_seconds <= 600:
        parser.error("--wall-seconds must be > 0 and <= 600")
    if not 16 <= args.max_sampled_rss_mib <= 4096:
        parser.error("--max-sampled-rss-mib must be between 16 and 4096")
    if args.max_address_space_mib is not None:
        if not sys.platform.startswith("linux"):
            parser.error("--max-address-space-mib is supported only on Linux")
        if not 128 <= args.max_address_space_mib <= 8192:
            parser.error("--max-address-space-mib must be between 128 and 8192")

    if args.max_cpu_seconds is not None:
        if not sys.platform.startswith("linux"):
            parser.error("--max-cpu-seconds is supported only on Linux")
        if not 1 <= args.max_cpu_seconds <= 300:
            parser.error("--max-cpu-seconds must be between 1 and 300")
    if args.max_job_memory_mib is not None:
        if os.name != "nt":
            parser.error("--max-job-memory-mib is supported only on Windows")
        if not 128 <= args.max_job_memory_mib <= 8192:
            parser.error("--max-job-memory-mib must be between 128 and 8192")

    try:
        # The PE is data passed to REL, never executed as a program.
        result = supervise(
            [str(args.binary.resolve(strict=True)), "analyze", str(args.input)],
            wall_seconds=args.wall_seconds,
            max_sampled_rss_bytes=args.max_sampled_rss_mib * 1024 * 1024,
            max_address_space_bytes=(
                args.max_address_space_mib * 1024 * 1024
                if args.max_address_space_mib is not None else None
            ),
            max_job_memory_bytes=(
                args.max_job_memory_mib * 1024 * 1024
                if args.max_job_memory_mib is not None else None
            ),
            max_cpu_seconds=args.max_cpu_seconds,
        )
    except LimitExceeded as error:
        print(f"rel-watchdog: {error}", file=sys.stderr)
        return 124 if error.kind == "wall" else 125
    except (WorkerFailed, OSError, subprocess.SubprocessError) as error:
        print(f"rel-watchdog: {error}", file=sys.stderr)
        return 1

    sys.stdout.buffer.write(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
