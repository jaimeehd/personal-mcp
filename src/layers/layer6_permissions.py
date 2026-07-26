import json

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from src.permissions import GrantLevel, PermissionManager
from src.security import SecurityValidator


def register_permission_tools(mcp: FastMCP, security: SecurityValidator,
                              perm_manager: PermissionManager) -> None:

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False))
    async def fs_approve(ticket_id: str, confirm_code: str, level: str = "single") -> str:
        try:
            gl = GrantLevel(level)
        except ValueError:
            return f"Invalid level '{level}'. Use: single, session"
        if gl == GrantLevel.PERMANENT:
            return ("Permanent grants are disabled from tool calls. "
                    "Edit ~/.personal-mcp/config.json directly to add paths.")
        _ok, msg = perm_manager.approve(ticket_id, gl, confirm_code)
        return msg

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True))
    async def fs_deny(ticket_id: str) -> str:
        _ok, msg = perm_manager.deny(ticket_id)
        return msg

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False))
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

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True))
    async def security_pending() -> str:
        pending = perm_manager.pending()
        if not pending:
            return "No pending permission requests"
        return json.dumps(pending, indent=2, ensure_ascii=False)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True))
    async def security_revoke(resource: str, operation: str | None = None) -> str:
        """Revoke grants for a resource.

        If operation is specified (e.g. "write", "delete", "execute"), only that
        operation's grant is revoked. If omitted, ALL grants for the resource are
        revoked. Prefer passing operation when possible to avoid silently dropping
        unrelated grants on the same path.
        """
        ok = perm_manager.revoke(resource, operation)
        if ok:
            op_str = f" [{operation}]" if operation else ""
            return f"Revoked grants{op_str} for: {resource}"
        return f"No active grants found for: {resource}"

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True))
    async def security_stats() -> str:
        return json.dumps(perm_manager.stats(), indent=2, ensure_ascii=False)