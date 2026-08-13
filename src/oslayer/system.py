import time

import psutil


def available_memory_info() -> dict | None:
    """Return dict with total_gb, free_gb, free_pct via psutil (cross-platform).
    Returns None if unavailable.
    """
    try:
        mem = psutil.virtual_memory()
        total_bytes = mem.total
        free_bytes = mem.available
        total_gb = round(total_bytes / (1024**3), 1)
        free_gb = round(free_bytes / (1024**3), 1)
        free_pct = round((free_bytes / total_bytes) * 100, 1) if total_bytes else 0.0
        return {"total_gb": total_gb, "free_gb": free_gb, "free_pct": free_pct}
    except Exception:
        return None


def uptime_seconds() -> float | None:
    """Return seconds since boot. None if unavailable."""
    try:
        return time.time() - psutil.boot_time()
    except Exception:
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
