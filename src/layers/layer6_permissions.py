import json
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

from src.permissions import GrantLevel, PermissionManager
from src.security import SecurityValidator


def register_permission_tools(mcp: FastMCP, security: SecurityValidator,
                              perm_manager: PermissionManager) -> None:

    @mcp.tool()
    async def fs_approve(ticket_id: str, confirm_code: str, level: str = "single") -> str:
        try:
            gl = GrantLevel(level)
        except ValueError:
            return f"Invalid level '{level}'. Use: single, session"
        if gl == GrantLevel.PERMANENT:
            return ("Permanent grants are disabled from tool calls. "
                    "Edit ~/.personal-mcp/config.json directly to add paths.")
        ok, msg = perm_manager.approve(ticket_id, gl, confirm_code)
        return msg

    @mcp.tool()
    async def fs_deny(ticket_id: str) -> str:
        ok, msg = perm_manager.deny(ticket_id)
        return msg

    @mcp.tool()
    async def fs_request_allow(path: str, level: str = "session") -> str:
        try:
            gl = GrantLevel(level)
        except ValueError:
            return f"Invalid level '{level}'. Use: single, session"
        if gl == GrantLevel.PERMANENT:
            return ("Permanent grants are disabled from tool calls. "
                    "Edit ~/.personal-mcp/config.json directly to add paths.")
        ticket = perm_manager.request(path, operation="*", level=gl)
        return (f"Ticket {ticket.id} created for '{path}' (pending). "
                f"A confirmation code was shown on your screen — it is NOT visible "
                f"to this agent. Use fs_approve(ticket_id='{ticket.id}', "
                f"confirm_code='<code from the popup>', level='{gl.value}') to confirm.")

    @mcp.tool()
    async def security_pending() -> str:
        pending = perm_manager.pending()
        if not pending:
            return "No pending permission requests"
        return json.dumps(pending, indent=2, ensure_ascii=False)

    @mcp.tool()
    async def security_revoke(resource: str) -> str:
        ok = perm_manager.revoke(resource)
        if ok:
            return f"Revoked grants for: {resource}"
        return f"No active grants found for: {resource}"

    @mcp.tool()
    async def security_stats() -> str:
        return json.dumps(perm_manager.stats(), indent=2, ensure_ascii=False)