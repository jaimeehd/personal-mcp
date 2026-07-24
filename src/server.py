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
from src.layers.layer2_shell import ShellManager, register_shell_tools
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
    audit_log = AuditLog.load(
        max_entries=config.audit_max_entries,
        persist_path=Path(config.data_dir) / "audit.json"
    )

    app = AuditedFastMCP("personal-mcp", audit_log=audit_log, logger=logger)

    register_filesystem_tools(app, security)
    shell_info = resolve_shell(config.shell.default_shell, config.shell.shell_map)
    shell_manager = ShellManager(security, config.shell.session_timeout_seconds, shell_info, config.shell.shell_map)
    register_shell_tools(app, security, shell_manager)
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
