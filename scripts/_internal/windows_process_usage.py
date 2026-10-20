"""Final direct-child Windows accounting via an owned creation-handle duplicate.

CPython's subprocess.Popen retains its CreateProcess handle in _handle. Duplicate
that handle, never reopen a PID (which could disappear or be reused). No process
is started here. Only the trusted analyzer/test interpreter is launched by callers.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes


def bind(name, result, arguments):
    function = getattr(ctypes.WinDLL("kernel32", use_last_error=True), name)
    function.restype, function.argtypes = result, arguments
    return function


class MemoryCounters(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
        (name, ctypes.c_size_t) for name in (
            "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
            "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
            "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage",
        )
    ]


CURRENT = bind("GetCurrentProcess", wintypes.HANDLE, [])
DUPLICATE = bind("DuplicateHandle", wintypes.BOOL, [
    wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
    ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, wintypes.BOOL, wintypes.DWORD,
])
CLOSE = bind("CloseHandle", wintypes.BOOL, [wintypes.HANDLE])
WAIT = bind("WaitForSingleObject", wintypes.DWORD, [wintypes.HANDLE, wintypes.DWORD])
MEMORY = bind("K32GetProcessMemoryInfo", wintypes.BOOL, [
    wintypes.HANDLE, ctypes.POINTER(MemoryCounters), wintypes.DWORD,
])
TIMES = bind("GetProcessTimes", wintypes.BOOL, [
    wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4),
])
METHOD = "windows-retained-handle-PeakWorkingSetSize-GetProcessTimes"


def fail(function):
    return OSError(f"{function}: {ctypes.WinError(ctypes.get_last_error())}")


def ticks(value):
    return (value.dwHighDateTime << 32) | value.dwLowDateTime


class WindowsProcessUsage:
    """Own a non-inheritable handle; errors abort profiling, never invent zeros."""

    def __init__(self, process):
        self._handle = None
        handle = wintypes.HANDLE()
        # Isolated CPython Windows implementation dependency, exercised in CI.
        source = getattr(process, "_handle", None)
        if source is None:
            raise OSError("Popen creation handle unavailable")
        if not DUPLICATE(CURRENT(), int(source), CURRENT(), ctypes.byref(handle),
                         0, False, 2):  # DUPLICATE_SAME_ACCESS
            raise fail("DuplicateHandle")
        self._handle = handle.value

    def final(self):
        if self._handle is None:
            raise OSError("process usage handle is closed")
        state = WAIT(self._handle, 0)
        if state == 258:  # WAIT_TIMEOUT: final accounting requires termination.
            raise OSError("process is still running")
        if state != 0:  # WAIT_OBJECT_0
            raise fail("WaitForSingleObject")
        memory = MemoryCounters()
        memory.cb = ctypes.sizeof(memory)
        if not MEMORY(self._handle, ctypes.byref(memory), memory.cb):
            raise fail("K32GetProcessMemoryInfo")
        creation, exit_time, kernel, user = (wintypes.FILETIME() for _ in range(4))
        if not TIMES(self._handle, ctypes.byref(creation), ctypes.byref(exit_time),
                     ctypes.byref(kernel), ctypes.byref(user)):
            raise fail("GetProcessTimes")
        if memory.PeakWorkingSetSize <= 0:
            raise OSError("Windows returned no peak working set")
        return int(memory.PeakWorkingSetSize), round((ticks(kernel) + ticks(user)) / 10000, 4)

    def close(self):
        if self._handle is not None:
            if not CLOSE(self._handle):
                raise fail("CloseHandle")
            self._handle = None
