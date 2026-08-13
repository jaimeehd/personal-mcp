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
    #
    # Las tools destructivas (write/delete/execute) devuelven un JSON
    # {"status": "permission_required", ...} cuando validate_tool_path las
    # bloquea. Sin excepcion de por medio, el audit log las registraria como
    # "OK" — ocultando que la operacion fue detenida por el sistema de
    # tickets. Tambien se incluyen las de shell porque validate_shell_execution
    # devuelve el mismo JSON cuando un interprete requiere aprobacion.
    _SEMANTIC_FAILURE_TOOLS = (
        "fs_approve",
        "fs_deny",
        "fs_write",
        "fs_edit",
        "fs_delete",
        "fs_delete_directory",
        "fs_delete_batch",
        "fs_move",
        "fs_create_directory",
        "fs_snapshot",
        "fs_compress",
        "fs_extract",
        "fs_batch",
        "sh_exec",
        "sh_script",
        "sh_session_send",
        "sh_spawn",
    )
    _SEMANTIC_FAILURE_PREFIXES = (
        "Ticket not found",
        "Ticket expired",
        "Ticket already",
        "Invalid or missing confirmation code",
        "Invalid level",
        "Permanent grants are disabled",
    )
    # Substring que indica una operacion bloqueada por el sistema de tickets.
    # json.dumps de request_permission() y validate_shell_execution() siempre
    # incluyen '"status": "permission_required"' — se busca como substring
    # (no como prefix) porque el JSON puede abrir con o sin espacios.
    _SEMANTIC_FAILURE_MARKER = "permission_required"

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
        if text.startswith(self._SEMANTIC_FAILURE_PREFIXES):
            return True
        # Operacion bloqueada por el sistema de tickets: la tool devolvio el
        # JSON de request_permission()/validate_shell_execution() sin lanzar
        # excepcion. Detectado por substring para ser robusto a formato JSON.
        return self._SEMANTIC_FAILURE_MARKER in text

    def _is_permission_blocked(self, name: str, result: object) -> bool:
        """True cuando una tool destructiva fue bloqueada por el sistema de
        tickets (devolvio JSON permission_required). Distinto de FAILED:
        aqui la operacion se detuvo antes de ejecutarse, no fue un error."""
        if name not in self._SEMANTIC_FAILURE_TOOLS:
            return False
        # fs_approve/fs_deny nunca devuelven permission_required, pero el
        # chequeo de prefijos las captura por _is_semantic_failure de todas
        # formas — este metodo es especificamente para tools destructivas.
        if name in ("fs_approve", "fs_deny"):
            return False
        text = self._result_text(result)
        if text is None:
            return False
        return self._SEMANTIC_FAILURE_MARKER in text

    def _is_access_denied(self, result: object) -> bool:
        """True cuando una tool devolvio un rechazo de config duro
        ("Access denied: ..."), p.ej. un match de paths_deny en fs_read o una
        ruta relativa/~/ en un comando shell. Aplica a CUALQUIER tool, no solo
        _SEMANTIC_FAILURE_TOOLS: una lectura denegada tambien es una operacion
        fallida y no debe registrarse como OK (auditoría 2026-08-11)."""
        text = self._result_text(result)
        return bool(text) and text.lstrip().lower().startswith("access denied")

    async def call_tool(self, name: str, arguments: dict):
        from src.log import scrub_sensitive_data
        sanitized_args = scrub_sensitive_data(arguments)
        log_args = {k: v for k, v in sanitized_args.items() if k != "content"}

        self._audit_logger.info("CALL %s %s", name, json.dumps(log_args))
        start = time.time()
        try:
            result = await super().call_tool(name, arguments)
            elapsed = (time.time() - start) * 1000
            if elapsed > 30_000:
                self._audit_logger.warning("SLOW %s %.0fms%s", name, elapsed, memory_pressure_hint())
            elif self._is_permission_blocked(name, result):
                self._audit_logger.warning("BLOCKED %s %.0fms ticket required", name, elapsed)
                self._audit_log.record(name, arguments, False, elapsed, "permission_required")
            elif self._is_access_denied(result):
                failure_text = self._result_text(result)
                self._audit_logger.warning("DENIED %s %.0fms %s", name, elapsed, failure_text)
                self._audit_log.record(name, arguments, False, elapsed, failure_text)
            elif self._is_semantic_failure(name, result):
                failure_text = self._result_text(result)
                self._audit_logger.warning("FAILED %s %.0fms %s", name, elapsed, failure_text)
                self._audit_log.record(name, arguments, False, elapsed, failure_text)
            else:
                self._audit_logger.info("OK   %s %.0fms", name, elapsed)
                self._audit_log.record(name, arguments, True, elapsed)
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
    perm_manager.security = security
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
