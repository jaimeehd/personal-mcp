import logging
import logging.handlers
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from src.oslayer.system import memory_pressure_hint
from src.secretscanner import scan_text

_logger: logging.Logger | None = None


# Below this = likely resource contention, not a genuine hang; worth saying so.
LOW_MEMORY_THRESHOLD_PCT = 25.0


# Lista de claves que siempre deben ser enmascaradas
SENSITIVE_KEYS = {"password", "token", "secret", "key", "api_key", "auth", "cookie", "bearer"}

# Mismo tope que audit.py::_AUDIT_SCAN_CHAR_CAP -- acota el costo del escaneo
# de contenido en un valor de string grande, sin garantizar cobertura mas
# alla de esa ventana.
_LOG_SCAN_CHAR_CAP = 100_000

def scrub_sensitive_data(data: Any) -> Any:
    """Limpia recursivamente datos sensibles de diccionarios o listas.

    2026-08-11 fix (encontrado revisando server.py, no en la auditoria
    original): esta funcion solo redactaba por NOMBRE DE CLAVE -- el mismo
    bug que se corrigio en audit.py::AuditEntry._sanitize() (1.4.58), pero en
    una funcion DISTINTA que alimenta un destino DISTINTO (server.log, via
    AuditedFastMCP.call_tool en server.py; audit.py alimenta audit.json).
    Arreglar solo audit.py dejo este gemelo con la misma debilidad: un
    secreto en un argumento sin nombre sospechoso (ej. fs_edit(new_string=
    "API_KEY=...")) se seguia persistiendo en texto plano en server.log.
    Ahora tambien escanea el VALOR de cada string con scan_text() (no solo
    la clave), con el mismo tope de tamano y la misma redaccion de valor
    completo (no in-place por posicion) que audit.py -- ver el docstring de
    _sanitize() ahi para el razonamiento completo de por que valor completo
    y no una redaccion posicional mas fina.

    No se unifico con AuditEntry._sanitize() en un helper compartido: son
    dos funciones que expresan el mismo principio de seguridad para dos
    consumidores distintos (log de texto vs. entrada de audit estructurada),
    y log.py es un modulo mas base que audit.py -- importar audit.py aca
    invertiria esa relacion de dependencia sin necesidad real.
    """
    if isinstance(data, dict):
        result = {}
        for k, v in data.items():
            if k.lower() in SENSITIVE_KEYS:
                result[k] = "***"
            elif isinstance(v, str) and v:
                findings = scan_text(v[:_LOG_SCAN_CHAR_CAP])
                if findings:
                    types = ", ".join(sorted({f.secret_type for f in findings}))
                    result[k] = f"[REDACTED: {len(findings)} potential secret(s) - {types}]"
                else:
                    result[k] = v
            else:
                result[k] = scrub_sensitive_data(v)
        return result
    elif isinstance(data, list):
        return [scrub_sensitive_data(item) for item in data]
    return data

def sanitize_log_value(value: str) -> str:
    """Escape control characters before interpolating a raw string into a log line.

    Call sites that log a tool argument directly via %s (not via json.dumps, which
    already escapes \n/\r as part of JSON string encoding) must sanitize it first —
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