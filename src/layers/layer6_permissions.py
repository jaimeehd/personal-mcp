import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from src.permissions import GrantLevel, PermissionManager
from src.security import PathNotAllowedError, SecurityValidator


def _single_grant_directory_error(path: str) -> str | None:
    """Reject a 'single' grant request on a directory before a ticket is even
    created (2026-08-08 fix, found via external audit).

    check_granted()'s single-grant lookup is an exact-path match -- unlike
    session grants, it never walks up parent directories. Requesting a
    single-level grant on a folder therefore could never satisfy a later
    check on a file inside it: the ticket got created, could be approved,
    and would still never actually grant anything usable. Standalone function
    (same pattern as _validate_command_paths/_check_spawn_permission in
    layer2_shell.py) so this is unit-testable without the FastMCP tool
    registration machinery.

    Returns an error message if path is a directory, None otherwise.
    """
    try:
        is_dir = Path(path).is_dir()
    except OSError:
        is_dir = False
    if not is_dir:
        return None
    return (f"'{path}' is a directory. A 'single' grant only matches an exact "
            f"path (no parent-directory walk, unlike 'session'), so it could "
            f"never satisfy a check on a file inside this folder. Use "
            f"level='session' instead.")


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
        # M-C1 (auditoría 2026-08-11): a ticket can only ever grant access to a path
        # already inside paths_allow/data_dir (resolve_and_validate checks membership
        # first), so requesting one for an outside/denied path was silently useless.
        # Validate up front and say so, instead of minting an inert ticket.
        try:
            security.resolve_and_validate(path)
        except PathNotAllowedError as e:
            return f"Access denied: {e}"
        if gl == GrantLevel.SINGLE:
            dir_error = _single_grant_directory_error(path)
            if dir_error:
                return dir_error
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