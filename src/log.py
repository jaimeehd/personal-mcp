import logging
import logging.handlers
import time
import json
import ctypes
from contextlib import contextmanager
from pathlib import Path
from typing import Optional, Any

_logger: Optional[logging.Logger] = None


class _MEMORYSTATUSEX(ctypes.Structure):
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


def available_memory_pct() -> Optional[float]:
    """% of physical RAM currently free, via GlobalMemoryStatusEx (Windows API
    call, no subprocess spawned - safe to call from inside a timeout handler
    without risking adding to the exact kind of subprocess pressure this is
    meant to diagnose). Returns None if the call fails for any reason (e.g.
    non-Windows) - callers must treat that as "unknown", not "0% free".

    2026-07-20: added after a session reported sh_exec timeouts that turned
    out to be ~10-12 parallel Claude Desktop processes competing for RAM on an
    8GB machine, not a hang - see CHANGELOG. Surfacing this number at the
    moment of a timeout/slow-op turns "is this a bug or my machine" from a
    multi-turn investigation into something visible in the error itself.
    """
    try:
        stat = _MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
            return 100.0 - float(stat.dwMemoryLoad)
    except Exception:
        pass
    return None


# Below this = likely resource contention, not a genuine hang; worth saying so.
LOW_MEMORY_THRESHOLD_PCT = 25.0


def memory_pressure_hint() -> str:
    """Empty string when memory looks fine or can't be read; otherwise a short,
    appendable clause explaining a slow/timed-out operation may not be a bug.
    """
    pct = available_memory_pct()
    if pct is not None and pct < LOW_MEMORY_THRESHOLD_PCT:
        return (f" (system memory is low: {pct:.0f}% free - this may be resource "
                f"contention from multiple parallel sessions rather than a hung "
                f"command; consider closing unused Claude Desktop windows, or "
                f"retrying with a longer timeout)")
    return ""

# Lista de claves que siempre deben ser enmascaradas
SENSITIVE_KEYS = {"password", "token", "secret", "key", "api_key", "auth", "cookie", "bearer"}

def scrub_sensitive_data(data: Any) -> Any:
    """Limpia recursivamente datos sensibles de diccionarios o listas."""
    if isinstance(data, dict):
        return {k: ("***" if k.lower() in SENSITIVE_KEYS else scrub_sensitive_data(v))
                for k, v in data.items()}
    elif isinstance(data, list):
        return [scrub_sensitive_data(item) for item in data]
    return data

def sanitize_log_value(value: str) -> str:
    """Escape control characters before interpolating a raw string into a log line.

    Call sites that log a tool argument directly via %s (not via json.dumps, which
    already escapes \\n/\\r as part of JSON string encoding) must sanitize it first —
    otherwise a crafted argument containing a literal newline can forge fake log
    entries (e.g. a fake "[INFO] User authenticated as admin" line) in server.log.
    """
    return value.replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\r")

def configure(data_dir: str, level: str = "INFO",
              max_bytes: int = 10 * 1024 * 1024,
              backup_count: int = 3) -> None:
    global _logger
    # A shared server.log can be opened by more than one personal-mcp server
    # process at once (e.g. several parallel Claude sessions). RotatingFileHandler
    # is documented upstream as unsafe across processes: if one process's
    # doRollover() renames the file while another still has it open for writing,
    # the rename raises PermissionError on Windows. By default that error is
    # printed to stderr on every subsequent emit() while the size condition
    # persists - and on a stdio-transport MCP server, an unread stderr pipe can
    # fill and block the writer, freezing the whole process, not just logging.
    # Losing a log line to a rotation race is an acceptable, cosmetic cost;
    # a hung server is not. This does not fix the underlying rollover race
    # itself, only how a failure there can cascade (hypothesis, see CHANGELOG
    # 1.4.21 - not conclusively reproduced, but low-risk to apply regardless).
    logging.raiseExceptions = False
    log_path = Path(data_dir) / "server.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("personal-mcp")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()
    handler = logging.handlers.RotatingFileHandler(
        str(log_path), maxBytes=max_bytes, backupCount=backup_count,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s.%(msecs)03d [%(levelname)-5s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(handler)
    _logger = logger


def get_logger(name: str = "") -> logging.Logger:
    global _logger
    if _logger is None:
        _logger = logging.getLogger("personal-mcp")
        _logger.addHandler(logging.NullHandler())
    if name:
        return _logger.getChild(name)
    return _logger


@contextmanager
def timed(operation: str, warn_ms: int = 10_000, **extra):
    logger = get_logger()
    start = time.time()
    try:
        yield
        elapsed = (time.time() - start) * 1000
        extra_str = " ".join(f"{k}={v}" for k, v in extra.items()) if extra else ""
        msg = f"{operation} {extra_str}".strip()
        if elapsed >= warn_ms:
            logger.warning("SLOW %s took %.0fms%s", msg, elapsed, memory_pressure_hint())
        else:
            logger.debug("%s took %.0fms", msg, elapsed)
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        extra_str = " ".join(f"{k}={v}" for k, v in extra.items()) if extra else ""
        msg = f"{operation} {extra_str}".strip()
        logger.error("FAIL %s after %.0fms: %s", msg, elapsed, str(e))
        raise
