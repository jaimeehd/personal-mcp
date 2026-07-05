import logging
import logging.handlers
import time
import json
from contextlib import contextmanager
from pathlib import Path
from typing import Optional, Any

_logger: Optional[logging.Logger] = None

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
            logger.warning("SLOW %s took %.0fms", msg, elapsed)
        else:
            logger.debug("%s took %.0fms", msg, elapsed)
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        extra_str = " ".join(f"{k}={v}" for k, v in extra.items()) if extra else ""
        msg = f"{operation} {extra_str}".strip()
        logger.error("FAIL %s after %.0fms: %s", msg, elapsed, str(e))
        raise
