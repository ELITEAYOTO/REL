"""Windows Job Object lifecycle for the opt-in REL Python watchdog.

An analyzer is created suspended, assigned to a limited Job Object, verified
as a member, then resumed. No inspected PE binary is ever executed by REL.
This code runs only on Windows and does NOT create a security sandbox.
"""
from __future__ import annotations

import ctypes
import subprocess
from ctypes import wintypes
from typing import Sequence

import psutil

CREATE_SUSPENDED = 0x00000004
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
PROCESS_SET_QUOTA = 0x0100
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
THREAD_SUSPEND_RESUME = 0x0002
FAILED_RESUME_THREAD = 0xFFFFFFFF


class BasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class IoCounters(ctypes.Structure):
    _fields_ = [
        (name, ctypes.c_ulonglong)
        for name in (
            "ReadOperationCount", "WriteOperationCount",
            "OtherOperationCount", "ReadTransferCount",
            "WriteTransferCount", "OtherTransferCount",
        )
    ]


class ExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", BasicLimitInformation),
        ("IoInfo", IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


def windows_error(function: str) -> OSError:
    return OSError(f"{function}: {ctypes.WinError(ctypes.get_last_error())}")


def kernel32_function(name: str, result: object, argtypes: list[object]):
    function = getattr(ctypes.WinDLL("kernel32", use_last_error=True), name)
    function.restype = result
    function.argtypes = argtypes
    return function


CREATE_JOB = kernel32_function(
    "CreateJobObjectW", wintypes.HANDLE, [wintypes.LPVOID, wintypes.LPCWSTR]
)
SET_JOB = kernel32_function(
    "SetInformationJobObject", wintypes.BOOL,
    [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD],
)
ASSIGN_JOB = kernel32_function(
    "AssignProcessToJobObject", wintypes.BOOL, [wintypes.HANDLE, wintypes.HANDLE]
)
OPEN_PROCESS = kernel32_function(
    "OpenProcess", wintypes.HANDLE, [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
)
OPEN_THREAD = kernel32_function(
    "OpenThread", wintypes.HANDLE, [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
)
RESUME_THREAD = kernel32_function(
    "ResumeThread", wintypes.DWORD, [wintypes.HANDLE]
)
IS_IN_JOB = kernel32_function(
    "IsProcessInJob", wintypes.BOOL,
    [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
)
CLOSE = kernel32_function("CloseHandle", wintypes.BOOL, [wintypes.HANDLE])


class WindowsJob:
    """Owned kill-on-close Job Object with aggregate job-commit budget.

    No breakaway flags are enabled. Creation is suspended to apply the job
    before any target code executes; unassignable jobs fail closed.
    """

    def __init__(self, max_job_memory_bytes: int) -> None:
        if max_job_memory_bytes <= 0:
            raise ValueError("job memory budget must be positive")
        self._handle = CREATE_JOB(None, None)
        if not self._handle:
            raise windows_error("CreateJobObjectW")
        try:
            limits = ExtendedLimitInformation()
            limits.BasicLimitInformation.LimitFlags = (
                JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            )
            limits.JobMemoryLimit = max_job_memory_bytes
            if not SET_JOB(
                self._handle,
                JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
                ctypes.byref(limits),
                ctypes.sizeof(limits),
            ):
                raise windows_error("SetInformationJobObject")
        except BaseException:
            self.close()
            raise

    def start(self, command: Sequence[str], **kwargs: object) -> psutil.Popen:
        """Create suspended, assign+verify, then resume exactly one main thread."""
        child = psutil.Popen(
            list(command), creationflags=CREATE_SUSPENDED, **kwargs
        )
        try:
            process = OPEN_PROCESS(
                PROCESS_SET_QUOTA | PROCESS_TERMINATE |
                PROCESS_QUERY_LIMITED_INFORMATION, False, child.pid
            )
            if not process:
                raise windows_error("OpenProcess")
            try:
                if not ASSIGN_JOB(self._handle, process):
                    raise windows_error("AssignProcessToJobObject")
                member = wintypes.BOOL()
                if not IS_IN_JOB(process, self._handle, ctypes.byref(member)):
                    raise windows_error("IsProcessInJob")
                if not member.value:
                    raise OSError("child is not in the expected Job Object")
            finally:
                CLOSE(process)

            threads = child.threads()
            if len(threads) != 1:
                raise OSError("suspended new process must have one main thread")
            thread = OPEN_THREAD(THREAD_SUSPEND_RESUME, False, threads[0].id)
            if not thread:
                raise windows_error("OpenThread")
            try:
                if RESUME_THREAD(thread) != 1:
                    raise windows_error("ResumeThread")
            finally:
                CLOSE(thread)
            return child
        except BaseException:
            self.close()
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            raise

    def close(self) -> None:
        if self._handle:
            handle, self._handle = self._handle, None
            CLOSE(handle)
