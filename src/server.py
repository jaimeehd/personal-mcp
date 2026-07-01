import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import asyncio
import time
import json
from collections import deque
from functools import wraps

from mcp.server.fastmcp import FastMCP

from src.config import AppConfig
from src.security import SecurityValidator
from src.audit import AuditLog
from src.permissions import PermissionManager
from src.layers.layer1_filesystem import register_filesystem_tools
from src.layers.layer2_shell import ShellManager, register_shell_tools
from src.layers.layer3_ssh import SSHManager, register_ssh_tools
from src.shell_resolver import resolve_shell
from src.layers.layer4_personal import register_personal_tools
from src.layers.layer5_health import register_health_tools
from src.layers.layer6_permissions import register_permission_tools


class RateLimitError(Exception):
    pass


def create_app() -> FastMCP:
    config = AppConfig.load()
    config.data_dir = str(Path.home() / ".personal-mcp" / "data")

    security = SecurityValidator(config)
    perm_manager = PermissionManager(config)
    security.perm_manager = perm_manager
    audit_log = AuditLog.load(
        max_entries=config.audit_max_entries,
        persist_path=Path(config.data_dir) / "audit.json"
    )

    app = FastMCP("personal-mcp")

    _rate_limiter: deque = deque()

    original_call_tool = app.call_tool

    @wraps(original_call_tool)
    async def wrapped_call_tool(name: str, arguments: dict, *args, **kwargs):
        now = time.time()
        cutoff = now - 60
        while _rate_limiter and _rate_limiter[0] < cutoff:
            _rate_limiter.popleft()
        limit = config.security.rate_limit_commands_per_minute
        if len(_rate_limiter) >= limit:
            raise RateLimitError(f"Rate limit exceeded: {limit} commands per minute")
        _rate_limiter.append(now)

        start = time.time()
        try:
            result = await original_call_tool(name, arguments, *args, **kwargs)
            audit_log.record(name, arguments, True, (time.time() - start) * 1000)
            return result
        except Exception as e:
            audit_log.record(name, arguments, False, (time.time() - start) * 1000, str(e))
            raise

    app.call_tool = wrapped_call_tool

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
