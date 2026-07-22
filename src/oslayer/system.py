import os
import sys
from typing import Optional


def available_memory_info() -> Optional[dict]:
    """Return dict with total_gb, free_gb, free_pct via OS-native call.
    Zero subprocesses spawned. Returns None if unavailable.
    """
    if sys.platform == "win32":
        return _windows_memory_info()
    return _linux_memory_info()


def _windows_memory_info() -> Optional[dict]:
    try:
        import ctypes

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
            total_bytes = stat.ullTotalPhys
            free_bytes = stat.ullAvailPhys
            total_gb = round(total_bytes / (1024**3), 1)
            free_gb = round(free_bytes / (1024**3), 1)
            free_pct = round((free_bytes / total_bytes) * 100, 1) if total_bytes else 0.0
            return {"total_gb": total_gb, "free_gb": free_gb, "free_pct": free_pct}
    except Exception:
        pass
    return None


def _linux_memory_info() -> Optional[dict]:
    try:
        with open("/proc/meminfo", "r") as f:
            lines = f.readlines()

        mem_total = mem_available = 0
        for line in lines:
            if line.startswith("MemTotal:"):
                mem_total = int(line.split()[1]) * 1024
            elif line.startswith("MemAvailable:"):
                mem_available = int(line.split()[1]) * 1024

        if mem_total > 0:
            total_gb = round(mem_total / (1024**3), 1)
            free_gb = round(mem_available / (1024**3), 1)
            free_pct = round((mem_available / mem_total) * 100, 1)
            return {"total_gb": total_gb, "free_gb": free_gb, "free_pct": free_pct}
    except Exception:
        pass
    return None


def uptime_seconds() -> Optional[float]:
    """Return seconds since boot. None if unavailable."""
    if sys.platform == "win32":
        return _windows_uptime()
    return _linux_uptime()


def _windows_uptime() -> Optional[float]:
    try:
        import ctypes
        uptime_ms = ctypes.windll.kernel32.GetTickCount64()
        return uptime_ms / 1000.0
    except Exception:
        pass
    return None


def _linux_uptime() -> Optional[float]:
    try:
        with open("/proc/uptime", "r") as f:
            return float(f.read().split()[0])
    except Exception:
        pass
    return None


LOW_MEMORY_THRESHOLD_PCT = 25.0


def memory_pressure_hint() -> str:
    """Return hint string if memory is low, empty string otherwise."""
    info = available_memory_info()
    if info and info["free_pct"] < LOW_MEMORY_THRESHOLD_PCT:
        return (
            f" (system memory is low: {info['free_pct']:.0f}% free - this may be resource "
            f"contention from multiple parallel sessions rather than a hung command; "
            f"consider closing unused Claude Desktop windows, or retrying with a longer timeout)"
        )
    return ""