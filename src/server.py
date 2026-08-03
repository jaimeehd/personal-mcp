import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import json
import os
import time

from mcp.server.fastmcp import FastMCP

from src.audit import AuditLog
from src.config import AppConfig
from src.layers.layer1_filesystem import register_filesystem_tools
from src.layers.layer2_shell import ShellManager, SpawnManager, register_shell_tools
from src.layers.layer3_ssh import SSHManager, register_ssh_tools
from src.layers.layer4_personal import register_personal_tools
from src.layers.layer5_health import register_health_tools
from src.layers.layer6_permissions import register_permission_tools
from src.log import configure as configure_logging
from src.log import get_logger, memory_pressure_hint
from src.permissions import PermissionManager
from src.security import SecurityValidator
from src.shell_resolver import resolve_shell


class AuditedFastMCP(FastMCP):
    """FastMCP que registra cada invocacion de herramienta en el audit log.

    NOTA (H1, 2026-07-02): reasignar el atributo `app.call_tool = wrapper`
    no funciona con esta version de FastMCP. `FastMCP._setup_handlers()`
    registra `self.call_tool` en el servidor MCP de bajo nivel dentro de
    `__init__`, mediante un closure que captura el objeto funcion en el
    momento del decorado. Reasignar `app.call_tool` despues no tiene efecto
    sobre ese closure ya registrado, y por eso ninguna invocacion real de
    un cliente MCP llegaba a auditarse (verificado: audit.json nunca se
    creaba pese a haber actividad real).

    Sobrescribir `call_tool` como metodo de instancia si funciona, porque
    Python resuelve `self.call_tool` por el MRO de la clase en el momento
    en que `_setup_handlers()` se ejecuta (dentro de `super().__init__()`),
    y en ese momento `self` ya es una instancia de `AuditedFastMCP`.
    """

    def __init__(self, *args, audit_log: AuditLog, logger, **kwargs):
        self._audit_log = audit_log
        self._audit_logger = logger
        super().__init__(*args, **kwargs)

    # Resultados que son fallas SEMANTICAS aunque no lancen excepcion.
    # fs_approve/fs_deny reportan fallas como strings planos ("Ticket not
    # found", "Invalid or missing confirmation code"): registrarlos como "OK"
    # fue exactamente lo que oculto el incidente de tickets perdidos por
    # reinicio (v1.4.41). Solo se inspeccionan las tools de permisos - otras
    # tools devuelven "Error: path does not exist" como resultado normal.
    _SEMANTIC_FAILURE_TOOLS = ("fs_approve", "fs_deny")
    _SEMANTIC_FAILURE_PREFIXES = (
        "Ticket not found",
        "Ticket expired",
        "Ticket already",
        "Invalid or missing confirmation code",
        "Invalid level",
        "Permanent grants are disabled",
    )

    def _result_text(self, result: object) -> str | None:
        """Extrae el texto plano del retorno de `super().call_tool()`.

        En esta version de FastMCP (3.4.x), `convert_result` devuelve para
        tools con anotacion `-> str` un tuple `(content_blocks, dict)` (el
        dict con la salida estructurada `{"result": ...}`). Otras formas
        posibles: un str plano, una lista de ContentBlock o un objeto con
        `.text`. Se recorre de forma defensiva para no perder nunca una
        falla semantica por un cambio en el contenedor del resultado.
        """
        if isinstance(result, str):
            return result
        if isinstance(result, tuple):
            for item in result:
                text = self._result_text(item)
                if text is not None:
                    return text
            return None
        if isinstance(result, list):
            parts = []
            for item in result:
                text = self._result_text(item)
                if text is not None:
                    parts.append(text)
            return "\n".join(parts) if parts else None
        text = getattr(result, "text", None)
        return text if isinstance(text, str) else None

    def _is_semantic_failure(self, name: str, result: object) -> bool:
        if name not in self._SEMANTIC_FAILURE_TOOLS:
            return False
        text = self._result_text(result)
        if text is None:
            return False
        return text.startswith(self._SEMANTIC_FAILURE_PREFIXES)

    async def call_tool(self, name: str, arguments: dict):
        from src.log import scrub_sensitive_data
        sanitized_args = scrub_sensitive_data(arguments)
        log_args = {k: v for k, v in sanitized_args.items() if k != "content"}

        self._audit_logger.info("CALL %s %s", name, json.dumps(log_args))
        start = time.time()
        try:
            result = await super().call_tool(name, arguments)
            elapsed = (time.time() - start) * 1000
            semantic_failed = self._is_semantic_failure(name, result)
            if elapsed > 30_000:
                self._audit_logger.warning("SLOW %s %.0fms%s", name, elapsed, memory_pressure_hint())
            elif semantic_failed:
                failure_text = self._result_text(result)
                self._audit_logger.warning("FAILED %s %.0fms %s", name, elapsed, failure_text)
            else:
                self._audit_logger.info("OK   %s %.0fms", name, elapsed)
            self._audit_log.record(name, arguments, not semantic_failed, elapsed)
            return result
        except Exception as e:
            elapsed = (time.time() - start) * 1000
            self._audit_logger.error("FAIL %s %.0fms %s", name, elapsed, str(e))
            self._audit_log.record(name, arguments, False, elapsed, str(e))
            raise


def create_app() -> FastMCP:
    config = AppConfig.load()
    config.data_dir = str(Path.home() / ".personal-mcp" / "data")

    configure_logging(config.data_dir, config.log.level, config.log.max_bytes, config.log.backup_count)
    logger = get_logger()
    logger.info("Server starting  data_dir=%s pid=%d", config.data_dir, os.getpid())

    security = SecurityValidator(config)
    perm_manager = PermissionManager(config)
    security.perm_manager = perm_manager
    audit_log = AuditLog.load(
        max_entries=config.audit_max_entries,
        persist_path=Path(config.data_dir) / "audit.json"
    )

    app = AuditedFastMCP("personal-mcp", audit_log=audit_log, logger=logger)

    register_filesystem_tools(app, security)
    shell_info = resolve_shell(config.shell.default_shell, config.shell.shell_map)
    shell_manager = ShellManager(security, config.shell.session_timeout_seconds, shell_info, config.shell.shell_map)
    spawn_manager = SpawnManager(security)
    register_shell_tools(app, security, shell_manager, spawn_manager)
    ssh_manager = SSHManager(config)
    register_ssh_tools(app, config, ssh_manager)
    register_personal_tools(app, config, security)
    register_health_tools(app, config, audit_log)
    register_permission_tools(app, security, perm_manager)

    return app


app = create_app()


def main():
    print("personal-mcp starting (stdio mode)")
    app.run(transport="stdio")


if __name__ == "__main__":
    main()
