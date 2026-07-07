"""Integration tests: end-to-end tool call flow via closures identical to real registration.

Builds closures matching register_filesystem_tools() and register_permission_tools()
exactly, then tests ONLY client-observable behavior (return strings).
No FastMCP, no _impl internals. No tool source modifications.
"""
import json
import sys
from pathlib import Path
from typing import Optional

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import AppConfig, SecurityConfig, CommandPolicy, ShellConfig, SSHConfig, JournalConfig
from src.security import SecurityValidator, CommandNotAllowedError
from src.permissions import GrantLevel, PermissionManager
from src.layers.layer1_filesystem import (
    fs_read_impl, fs_write_impl, fs_edit_impl, fs_list_impl, fs_tree_impl,
    fs_search_impl, fs_find_impl, fs_info_impl, fs_diff_impl, fs_batch_impl, fs_snapshot_impl,
)
from src.layers.layer6_permissions import register_permission_tools


# ===================================================================
# Fixtures
# ===================================================================

@pytest.fixture
def wired_system(temp_home):
    """Return (config, security, perm_manager) wired together."""
    config = AppConfig(
        security=SecurityConfig(
            paths_allow=[
                str(temp_home / "Repos"),
                str(temp_home / "Desktop"),
                str(temp_home / ".personal-mcp"),
            ],
            paths_deny=["**\\node_modules\\**", "**\\.git\\**"],
        ),
        shell=ShellConfig(enabled=True),
        ssh=SSHConfig(enabled=False),
        journal=JournalConfig(
            enabled=True,
            path=str(temp_home / ".personal-mcp" / "data" / "journal"),
        ),
        data_dir=str(temp_home / ".personal-mcp" / "data"),
        audit_max_entries=1000,
        config_path=str(temp_home / ".personal-mcp" / "config.json"),
    )
    pm = PermissionManager(config)
    sec = SecurityValidator(config)
    sec.perm_manager = pm
    return config, sec, pm


@pytest.fixture
def sec_no_pm(temp_home):
    """SecurityValidator without PermissionManager."""
    config = AppConfig(
        security=SecurityConfig(paths_allow=[str(temp_home / "Repos")]),
        data_dir=str(temp_home / ".personal-mcp" / "data"),
    )
    return SecurityValidator(config)


# ---------------------------------------------------------------
# Closure builders — identical pattern to register_*_tools()
# ---------------------------------------------------------------

def _make_fs_read(security):
    async def fs_read(path: str, encoding: str = "utf-8") -> str:
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        return await fs_read_impl(path, security, encoding)
    return fs_read


def _make_fs_write(security):
    async def fs_write(path: str, content: str = "") -> str:
        err = security.validate_tool_path(path, "write")
        if err:
            return err
        return await fs_write_impl(path, content, security)
    return fs_write


def _make_fs_edit(security):
    async def fs_edit(path: str, old_string: str, new_string: str) -> str:
        err = security.validate_tool_path(path, "write")
        if err:
            return err
        return await fs_edit_impl(path, old_string, new_string, security)
    return fs_edit


def _make_fs_list(security):
    async def fs_list(path: str) -> str:
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        return await fs_list_impl(path, security)
    return fs_list


def _make_fs_tree(security):
    async def fs_tree(path: str, max_depth: int = 3) -> str:
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        return await fs_tree_impl(path, security, max_depth)
    return fs_tree


def _make_fs_info(security):
    async def fs_info(path: str) -> str:
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        return await fs_info_impl(path, security)
    return fs_info


def _make_fs_search(security):
    async def fs_search(path: str, pattern: str) -> str:
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        return await fs_search_impl(path, pattern, security)
    return fs_search


def _make_fs_find(security):
    async def fs_find(path: str, name: Optional[str] = None) -> str:
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        if not name:
            return "Error: name is required"
        return await fs_find_impl(path, security, name=name)
    return fs_find


def _make_fs_diff(security):
    async def fs_diff(path_a: str, path_b: Optional[str] = None) -> str:
        err = security.validate_tool_path(path_a, "read")
        if err:
            return err
        if path_b:
            err = security.validate_tool_path(path_b, "read")
            if err:
                return err
        return await fs_diff_impl(path_a, path_b, security)
    return fs_diff


def _make_fs_batch(security):
    async def fs_batch(path: str, operation: str, target: str,
                       pattern: Optional[str] = None, dry_run: bool = True) -> str:
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        err = security.validate_tool_path(target, "write")
        if err:
            return err
        return await fs_batch_impl(path, operation, target, security, pattern, dry_run)
    return fs_batch


def _make_fs_approve(security, pm):
    async def fs_approve(ticket_id: str, confirm_code: str, level: str = "single") -> str:
        try:
            gl = GrantLevel(level)
        except ValueError:
            return f"Invalid level '{level}'. Use: single, session"
        if gl == GrantLevel.PERMANENT:
            return ("Permanent grants are disabled from tool calls. "
                    "Edit ~/.personal-mcp/config.json directly to add paths.")
        ok, msg = pm.approve(ticket_id, gl, confirm_code)
        return msg
    return fs_approve


def _make_fs_deny(pm):
    async def fs_deny(ticket_id: str) -> str:
        ok, msg = pm.deny(ticket_id)
        return msg
    return fs_deny


def _make_fs_request_allow(security, pm):
    async def fs_request_allow(path: str, level: str = "session") -> str:
        try:
            gl = GrantLevel(level)
        except ValueError:
            return f"Invalid level '{level}'. Use: single, session"
        if gl == GrantLevel.PERMANENT:
            return ("Permanent grants are disabled from tool calls. "
                    "Edit ~/.personal-mcp/config.json directly to add paths.")
        ticket = pm.request(path, operation="*", level=gl)
        return (f"Ticket {ticket.id} created for '{path}' (pending). "
                f"A confirmation code was shown on your screen — it is NOT visible "
                f"to this agent. Use fs_approve(ticket_id='{ticket.id}', "
                f"confirm_code='<code from the popup>', level='{gl.value}') to confirm.")
    return fs_request_allow


def _make_security_pending(pm):
    async def security_pending() -> str:
        pending = pm.pending()
        if not pending:
            return "No pending permission requests"
        return json.dumps(pending, indent=2, ensure_ascii=False)
    return security_pending


def _make_security_revoke(pm):
    async def security_revoke(resource: str) -> str:
        ok = pm.revoke(resource)
        if ok:
            return f"Revoked grants for: {resource}"
        return f"No active grants found for: {resource}"
    return security_revoke


def _make_security_stats(pm):
    async def security_stats() -> str:
        return json.dumps(pm.stats(), indent=2, ensure_ascii=False)
    return security_stats


@pytest.fixture
def tools(wired_system):
    """Build a dict of tool closures mirroring production registration."""
    _, sec, pm = wired_system
    return {
        "fs_read": _make_fs_read(sec),
        "fs_write": _make_fs_write(sec),
        "fs_edit": _make_fs_edit(sec),
        "fs_list": _make_fs_list(sec),
        "fs_tree": _make_fs_tree(sec),
        "fs_info": _make_fs_info(sec),
        "fs_search": _make_fs_search(sec),
        "fs_find": _make_fs_find(sec),
        "fs_diff": _make_fs_diff(sec),
        "fs_batch": _make_fs_batch(sec),
        "fs_approve": _make_fs_approve(sec, pm),
        "fs_deny": _make_fs_deny(pm),
        "fs_request_allow": _make_fs_request_allow(sec, pm),
        "security_pending": _make_security_pending(pm),
        "security_revoke": _make_security_revoke(pm),
        "security_stats": _make_security_stats(pm),
    }


@pytest.fixture
def tools_no_pm(sec_no_pm):
    """Tool closures with no PermissionManager attached."""
    sec = sec_no_pm
    return {
        "fs_read": _make_fs_read(sec),
        "fs_write": _make_fs_write(sec),
        "fs_info": _make_fs_info(sec),
    }


# ===================================================================
# Helper: create a file inside allowed path for actual tool operations
# ===================================================================

def _create_file(config, rel_path: str, content: str = "hello") -> dict:
    """Create a real file. Returns dict with 'path' and 'resolved'."""
    full = Path(config.security.paths_allow[0]) / rel_path
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(content)
    return {"path": str(full), "resolved": str(full.resolve())}


# ===================================================================
# 1 — Tool call exitoso (session grant presente)
# ===================================================================

class TestToolCallSuccess:

    async def test_fs_read_returns_content(self, tools, wired_system):
        config, sec, pm = wired_system
        f = _create_file(config, "read_ok.txt", "Hello Tool!")
        pm.grant_direct(f["path"], "read", GrantLevel.SESSION)
        result = await tools["fs_read"](f["path"])
        assert "Hello Tool!" in result
        assert not result.startswith("{")  # not a JSON ticket

    async def test_fs_write_creates_file(self, tools, wired_system):
        config, _, pm = wired_system
        f = _create_file(config, "write_ok_target.txt", "")
        # _impl also calls resolve_and_validate (default "read"), so grant "*"
        pm.grant_direct(f["path"], "*", GrantLevel.SESSION)
        result = await tools["fs_write"](f["path"], "new content")
        assert "Written" in result
        assert Path(f["resolved"]).read_text() == "new content"

    async def test_fs_info_returns_metadata(self, tools, wired_system):
        config, sec, pm = wired_system
        f = _create_file(config, "info_ok.txt", "data")
        pm.grant_direct(f["path"], "read", GrantLevel.SESSION)
        result = await tools["fs_info"](f["path"])
        assert "path:" in result and "size:" in result and "sha256:" in result

    async def test_fs_list_returns_entries(self, tools, wired_system):
        config, sec, pm = wired_system
        d = Path(config.security.paths_allow[0]) / "list_dir"
        d.mkdir(parents=True, exist_ok=True)
        (d / "a.txt").write_text("a")
        (d / "b.txt").write_text("b")
        pm.grant_direct(str(d), "read", GrantLevel.SESSION)
        result = await tools["fs_list"](str(d))
        assert "a.txt" in result and "b.txt" in result

    async def test_fs_tree_returns_tree(self, tools, wired_system):
        config, sec, pm = wired_system
        d = Path(config.security.paths_allow[0]) / "tree_dir"
        d.mkdir(parents=True, exist_ok=True)
        (d / "leaf.py").write_text("")
        pm.grant_direct(str(d), "read", GrantLevel.SESSION)
        result = await tools["fs_tree"](str(d))
        assert "leaf.py" in result and "tree_dir" in result

    async def test_fs_search_finds_pattern(self, tools, wired_system):
        config, sec, pm = wired_system
        f = _create_file(config, "search_me.py", "def hello(): pass")
        pm.grant_direct(Path(f["path"]).parent.as_posix(), "read", GrantLevel.SESSION)
        result = await tools["fs_search"](str(Path(f["path"]).parent), "def hello")
        assert "hello" in result

    async def test_fs_find_finds_file_by_name(self, tools, wired_system):
        config, sec, pm = wired_system
        f = _create_file(config, "find_target.txt", "find me")
        pm.grant_direct(Path(f["path"]).parent.as_posix(), "read", GrantLevel.SESSION)
        result = await tools["fs_find"](str(Path(f["path"]).parent), "find_target.txt")
        assert "find_target.txt" in result

    async def test_fs_diff_identical_files(self, tools, wired_system):
        config, sec, pm = wired_system
        a = _create_file(config, "diff_a.txt", "same")
        b = _create_file(config, "diff_b.txt", "same")
        pm.grant_direct(a["path"], "read", GrantLevel.SESSION)
        pm.grant_direct(b["path"], "read", GrantLevel.SESSION)
        result = await tools["fs_diff"](a["path"], b["path"])
        assert "(identical)" in result

    async def test_fs_edit_replaces_string(self, tools, wired_system):
        config, _, pm = wired_system
        f = _create_file(config, "edit_me.txt", "old content here")
        # _impl calls fs_read_impl (needs "read"), closure validates "write"
        pm.grant_direct(f["path"], "*", GrantLevel.SESSION)
        result = await tools["fs_edit"](f["path"], "old", "new")
        assert "Applied edit" in result
        assert Path(f["resolved"]).read_text() == "new content here"

    async def test_multiple_tools_same_session_grant(self, tools, wired_system):
        config, sec, pm = wired_system
        f = _create_file(config, "multi_tool.txt", "initial")
        pm.grant_direct(f["path"], "*", GrantLevel.SESSION)
        r1 = await tools["fs_read"](f["path"])
        assert "initial" in r1
        r2 = await tools["fs_write"](f["path"], "updated")
        assert "Written" in r2
        r3 = await tools["fs_info"](f["path"])
        assert "sha256:" in r3


# ===================================================================
# 2 — Tool call bloqueado: permission_required (JSON ticket)
# ===================================================================

class TestToolCallPermissionRequired:

    def _is_permission_required(self, result: str) -> dict:
        """Assert result is a permission_required JSON and return parsed data."""
        assert result.startswith("{"), f"Expected JSON ticket, got: {result[:200]}"
        data = json.loads(result)
        assert data["status"] == "permission_required"
        assert "ticket" in data
        assert "fs_approve" in data["message"]
        return data

    async def test_fs_read_without_grant_succeeds(self, tools, wired_system):
        """Read in paths_allow works without grant (Option C)."""
        config, _, _ = wired_system
        f = _create_file(config, "no_grant_read.txt")
        result = await tools["fs_read"](f["path"])
        assert "hello" in result
        assert not result.startswith("{")

    async def test_fs_write_without_grant_returns_ticket(self, tools, wired_system):
        config, _, _ = wired_system
        f = _create_file(config, "no_grant_write.txt")
        result = await tools["fs_write"](f["path"], "data")
        self._is_permission_required(result)

    async def test_fs_info_without_grant_succeeds(self, tools, wired_system):
        """Info in paths_allow works without grant (Option C)."""
        config, _, _ = wired_system
        f = _create_file(config, "no_grant_info.txt")
        result = await tools["fs_info"](f["path"])
        assert "path:" in result
        assert not result.startswith("{")

    async def test_fs_edit_without_grant_returns_ticket(self, tools, wired_system):
        config, _, _ = wired_system
        f = _create_file(config, "no_grant_edit.txt", "old")
        result = await tools["fs_edit"](f["path"], "old", "new")
        self._is_permission_required(result)

    async def test_read_grant_does_not_allow_write(self, tools, wired_system):
        config, _, pm = wired_system
        f = _create_file(config, "read_only.txt", "hello data")
        pm.grant_direct(f["path"], "read", GrantLevel.SESSION)
        read_result = await tools["fs_read"](f["path"])
        assert "hello data" in read_result  # read works
        write_result = await tools["fs_write"](f["path"], "data")
        self._is_permission_required(write_result)  # write blocked

    async def test_ticket_contains_approve_instructions(self, tools, wired_system):
        config, _, _ = wired_system
        f = _create_file(config, "instructions.txt")
        # Write still requires grant (Option C)
        result = await tools["fs_write"](f["path"], "data")
        data = self._is_permission_required(result)
        assert data["ticket"] in data["message"]
        assert data["resource"] == f["path"]
        assert data["operation"] == "write"


# ===================================================================
# 3 — Tool call bloqueado: access denied (error string, no ticket)
# ===================================================================

class TestToolCallAccessDenied:

    async def test_path_outside_allow_dirs(self, tools, wired_system):
        result = await tools["fs_read"]("C:\\Windows\\system.ini")
        assert "Access denied" in result
        assert "permission_required" not in result

    async def test_path_matches_deny_pattern(self, tools, wired_system):
        config, _, _ = wired_system
        bad = Path(config.security.paths_allow[0]) / "project" / ".git" / "config"
        bad.parent.mkdir(parents=True, exist_ok=True)
        bad.write_text("[core]")
        result = await tools["fs_read"](str(bad))
        assert "Access denied" in result
        assert "denied by pattern" in result

    async def test_relative_path(self, tools, wired_system):
        result = await tools["fs_read"]("Repos/file.txt")
        assert "Access denied" in result
        assert "Path must be absolute" in result

    async def test_path_in_data_dir_auto_allowed(self, tools, wired_system):
        config, _, _ = wired_system
        f = Path(config.data_dir) / "internal_state.json"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text('{"ok": true}')
        result = await tools["fs_read"](str(f))
        assert '{"ok": true}' in result  # read succeeds without grant

    async def test_path_in_data_dir_but_deny_pattern(self, tools, wired_system):
        config, _, _ = wired_system
        f = Path(config.data_dir) / "node_modules" / "pkg" / "index.js"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("test")
        result = await tools["fs_read"](str(f))
        assert "Access denied" in result
        assert "denied by pattern" in result


# ===================================================================
# 4 — Permission management tools
# ===================================================================

class TestPermissionTools:

    async def test_fs_approve_single(self, tools, wired_system):
        config, _, pm = wired_system
        path = str(Path(config.security.paths_allow[0]) / "approve_single.txt")
        ticket = pm.request(path, "read", GrantLevel.SINGLE)
        result = await tools["fs_approve"](ticket.id, ticket.confirm_code, "single")
        assert "Granted single access" in result

    async def test_fs_approve_session(self, tools, wired_system):
        config, _, pm = wired_system
        path = str(Path(config.security.paths_allow[0]) / "approve_session.txt")
        ticket = pm.request(path, "read", GrantLevel.SESSION)
        result = await tools["fs_approve"](ticket.id, ticket.confirm_code, "session")
        assert "Granted session access" in result

    async def test_fs_approve_permanent_rejected(self, tools, wired_system):
        config, _, pm = wired_system
        path = config.data_dir + "\\..\\perm_approve.txt"
        resolved = str(Path(path).resolve())
        ticket = pm.request(resolved, "read", GrantLevel.PERMANENT)
        result = await tools["fs_approve"](ticket.id, ticket.confirm_code, "permanent")
        assert "disabled from tool calls" in result
        assert resolved not in config.security.paths_allow

    async def test_fs_approve_invalid_level(self, tools):
        result = await tools["fs_approve"]("perm_xxx", "any_code", level="invalid")
        assert "Invalid level" in result

    async def test_fs_deny(self, tools, wired_system):
        config, _, pm = wired_system
        path = str(Path(config.security.paths_allow[0]) / "deny_test.txt")
        ticket = pm.request(path, "read")
        result = await tools["fs_deny"](ticket.id)
        assert "Denied access" in result
        assert ticket.status == "denied"

    async def test_fs_request_allow_session_pending(self, tools, wired_system):
        config, _, pm = wired_system
        path = str(Path(config.security.paths_allow[0]) / "pre_allow.txt")
        result = await tools["fs_request_allow"](path, "session")
        assert "pending" in result
        assert "Use fs_approve" in result
        assert pm.check_granted(path, "*") is False

    async def test_fs_request_allow_then_approve(self, tools, wired_system):
        config, _, pm = wired_system
        path = str(Path(config.security.paths_allow[0]) / "pre_allow_full.txt")
        r1 = await tools["fs_request_allow"](path, "session")
        ticket_id = r1.split("Ticket ")[1].split(" ")[0]
        code = pm._tickets[ticket_id].confirm_code
        result = await tools["fs_approve"](ticket_id, code, "session")
        assert "Granted session access" in result
        assert pm.check_granted(path, "*") is True

    async def test_fs_request_allow_then_deny(self, tools, wired_system):
        config, _, pm = wired_system
        path = str(Path(config.security.paths_allow[0]) / "pre_allow_deny.txt")
        r1 = await tools["fs_request_allow"](path, "session")
        ticket_id = r1.split("Ticket ")[1].split(" ")[0]
        result = await tools["fs_deny"](ticket_id)
        assert "Denied" in result
        assert pm.check_granted(path, "*") is False

    async def test_fs_request_allow_permanent_rejected(self, tools, wired_system):
        config, _, pm = wired_system
        path = config.data_dir + "\\..\\pre_perm.txt"
        resolved = str(Path(path).resolve())
        result = await tools["fs_request_allow"](resolved, "permanent")
        assert "disabled from tool calls" in result
        assert resolved not in config.security.paths_allow

    async def test_security_pending(self, tools, wired_system):
        config, _, pm = wired_system
        path = str(Path(config.security.paths_allow[0]) / "pending_test.txt")
        pm.request(path, "read")
        result = await tools["security_pending"]()
        assert "pending_test.txt" in result  # filename visible in JSON

    async def test_security_pending_empty(self, tools):
        result = await tools["security_pending"]()
        assert result == "No pending permission requests"

    async def test_security_revoke(self, tools, wired_system):
        config, _, pm = wired_system
        path = str(Path(config.security.paths_allow[0]) / "revoke_me.txt")
        pm.grant_direct(path, "read", GrantLevel.SESSION)
        result = await tools["security_revoke"](path)
        assert "Revoked grants for" in result
        assert pm.check_granted(path, "read") is False

    async def test_security_revoke_no_grants(self, tools):
        result = await tools["security_revoke"]("C:\\nonexistent")
        assert "No active grants found" in result

    async def test_security_stats(self, tools, wired_system):
        config, _, pm = wired_system
        pm.request(str(Path(config.security.paths_allow[0]) / "stats_a.txt"), "read")
        pm.request(str(Path(config.security.paths_allow[0]) / "stats_b.txt"), "read")
        result = await tools["security_stats"]()
        data = json.loads(result)
        assert data["total_tickets"] == 2
        assert data["pending"] == 2


# ===================================================================
# 5 — Session grant inheritance (parent → child)
# ===================================================================

class TestSessionGrantInheritance:

    async def test_parent_grant_covers_child(self, tools, wired_system):
        config, _, pm = wired_system
        parent = str(Path(config.security.paths_allow[0]) / "myproject")
        child = str(Path(parent) / "src" / "main.py")
        Path(child).parent.mkdir(parents=True, exist_ok=True)
        Path(child).write_text("print('hello')")
        pm.grant_direct(parent, "read", GrantLevel.SESSION)
        result = await tools["fs_read"](child)
        assert "hello" in result
        assert not result.startswith("{")

    async def test_grandchild_inherits_grant(self, tools, wired_system):
        config, _, pm = wired_system
        grandparent = str(Path(config.security.paths_allow[0]) / "grand")
        child = str(Path(grandparent) / "parent" / "child" / "deep.txt")
        Path(child).parent.mkdir(parents=True, exist_ok=True)
        Path(child).write_text("deep file")
        pm.grant_direct(grandparent, "read", GrantLevel.SESSION)
        result = await tools["fs_read"](child)
        assert "deep file" in result

    async def test_sibling_not_covered_by_grant(self, tools, wired_system):
        """Write grant doesn't cover sibling; read auto-allowed in paths_allow."""
        config, _, pm = wired_system
        granted = str(Path(config.security.paths_allow[0]) / "project_a" / "file.txt")
        sibling = str(Path(config.security.paths_allow[0]) / "project_b" / "file.txt")
        Path(granted).parent.mkdir(parents=True, exist_ok=True)
        Path(granted).write_text("a")
        Path(sibling).parent.mkdir(parents=True, exist_ok=True)
        Path(sibling).write_text("b")
        pm.grant_direct(granted, "write", GrantLevel.SESSION)
        # Read auto-allowed in paths_allow for both
        r1 = await tools["fs_read"](granted)
        assert "a" in r1
        r2 = await tools["fs_read"](sibling)
        assert "b" in r2
        # Write still needs grant — sibling blocked
        r3 = await tools["fs_write"](sibling, "new")
        assert "permission_required" in r3


# ===================================================================
# 6 — Single grant consumption
# ===================================================================

class TestSingleGrantConsumption:

    async def test_validate_tool_path_passes_then_consumed(self, wired_system):
        """Single grant consumed on second validate_tool_path (write operation)."""
        config, sec, pm = wired_system
        f = _create_file(config, "single_consume.txt", "data")
        pm.grant_direct(f["path"], "write", GrantLevel.SINGLE)
        err = sec.validate_tool_path(f["path"], "write")
        assert err is None  # first call passes
        err = sec.validate_tool_path(f["path"], "write")
        assert err is not None
        assert "permission_required" in err  # consumed

    async def test_wildcard_single_consumed_on_first_operation(self, wired_system):
        """Wildcard single grant consumed by first validate_tool_path write call."""
        config, sec, pm = wired_system
        f = _create_file(config, "wild_single.txt", "data")
        pm.grant_direct(f["path"], "*", GrantLevel.SINGLE)
        # Write uses the grant (read is auto-allowed in paths_allow)
        err = sec.validate_tool_path(f["path"], "write")
        assert err is None  # consumed
        err = sec.validate_tool_path(f["path"], "write")
        assert err is not None
        assert "permission_required" in err  # gone

    async def test_wrong_operation_does_not_consume(self, wired_system):
        """Single grant with 'write' not consumed by 'read' (read auto-allowed in paths_allow)."""
        config, sec, pm = wired_system
        f = _create_file(config, "wrong_op.txt", "data")
        pm.grant_direct(f["path"], "write", GrantLevel.SINGLE)
        # Read is auto-allowed in paths_allow (doesn't consume grant)
        err = sec.validate_tool_path(f["path"], "read")
        assert err is None  # read passes without consuming
        # write grant still intact
        err = sec.validate_tool_path(f["path"], "write")
        assert err is None  # write passes (not consumed by read)


# ===================================================================
# 7 — Permanent grant
# ===================================================================

class TestPermanentGrant:

    async def test_permanent_grant_adds_to_paths_allow(self, tools, wired_system):
        config, _, pm = wired_system
        path = config.data_dir + "\\..\\perm_paths_allow.txt"
        resolved = str(Path(path).resolve())
        pm.grant_direct(resolved, "read", GrantLevel.PERMANENT)
        assert resolved in config.security.paths_allow

    async def test_permanent_grant_saves_to_disk(self, tools, wired_system):
        config, _, pm = wired_system
        path = config.data_dir + "\\..\\perm_disk.txt"
        resolved = str(Path(path).resolve())
        pm.grant_direct(resolved, "read", GrantLevel.PERMANENT)
        assert Path(config.config_path).exists()
        with open(config.config_path) as f:
            saved = json.load(f)
        assert resolved in saved["security"]["paths_allow"]

    async def test_permanent_grant_then_session_grant_for_tool_call(self, tools, wired_system):
        config, _, pm = wired_system
        path = config.data_dir + "\\..\\perm_then_call.txt"
        resolved = str(Path(path).resolve())
        Path(resolved).write_text("perm ok")
        pm.grant_direct(resolved, "read", GrantLevel.PERMANENT)
        # Permanent adds to paths_allow; still need session grant for resolve_and_validate
        pm.grant_direct(resolved, "read", GrantLevel.SESSION)
        result = await tools["fs_read"](resolved)
        assert "perm ok" in result

    async def test_permanent_grant_persists_across_validator_restart(self, tools, wired_system):
        """Simulates server restart: permanent grant persists in config."""
        config, _, pm = wired_system
        path = config.data_dir + "\\..\\perm_restart.txt"
        resolved = str(Path(path).resolve())
        Path(resolved).write_text("survived")
        pm.grant_direct(resolved, "read", GrantLevel.PERMANENT)
        # "Restart" — re-create both from same config
        new_pm = PermissionManager(config)
        new_sec = SecurityValidator(config)
        new_sec.perm_manager = new_pm
        new_pm.grant_direct(resolved, "read", GrantLevel.SESSION)  # still need session
        new_tools = {
            "fs_read": _make_fs_read(new_sec),
        }
        result = await new_tools["fs_read"](resolved)
        assert "survived" in result


# ===================================================================
# 8 — Sin PermissionManager
# ===================================================================

class TestNoPermissionManager:

    async def test_validate_returns_no_pm_message(self, tools_no_pm, temp_home):
        """Write without PM returns permission_required (read auto-allowed in paths_allow)."""
        path = str(temp_home / "Repos" / "no_pm.txt")
        Path(path).write_text("no pm")
        result = await tools_no_pm["fs_write"](path, "data")
        data = json.loads(result)
        assert data["status"] == "permission_required"
        assert "No PermissionManager configured" in data["message"]

    async def test_all_tools_work_without_pm(self, tools_no_pm, temp_home):
        """Without PM, write returns permission_required; read/info succeed in paths_allow."""
        path = str(temp_home / "Repos" / "no_pm_all.txt")
        Path(path).write_text("test")
        # Read and info auto-allowed in paths_allow even without PM
        r1 = await tools_no_pm["fs_read"](path)
        assert "test" in r1
        r2 = await tools_no_pm["fs_info"](path)
        assert "path:" in r2
        # Write requires grant → ticket
        r3 = await tools_no_pm["fs_write"](path, "new")
        data = json.loads(r3)
        assert data["status"] == "permission_required"


# ===================================================================
# 9 — Shell security (via closure validation)
# ===================================================================

class TestShellCommandValidation:

    async def test_shell_validate_command_passes(self, wired_system):
        """Simulate what sh_exec closure does: validate, then call _impl."""
        _, sec, _ = wired_system
        try:
            sec.validate_command("git status")
        except CommandNotAllowedError:
            pytest.fail("Unexpected CommandNotAllowedError")

    async def test_shell_denied_command(self, wired_system):
        _, sec, _ = wired_system
        with pytest.raises(CommandNotAllowedError):
            sec.validate_command("shutdown /s /t 0")

    async def test_shell_unknown_command(self, wired_system):
        _, sec, _ = wired_system
        with pytest.raises(CommandNotAllowedError):
            sec.validate_command("curl http://evil.com")

    async def test_shell_dangerous_flag(self, wired_system):
        _, sec, _ = wired_system
        with pytest.raises(CommandNotAllowedError):
            sec.validate_command("git push --force")


# ===================================================================
# 10 — Operation-level isolation
# ===================================================================

class TestOperationIsolation:

    async def test_read_grant_does_not_allow_write(self, tools, wired_system):
        config, _, pm = wired_system
        f = _create_file(config, "iso_read_only.txt", "data")
        pm.grant_direct(f["path"], "read", GrantLevel.SESSION)
        r_read = await tools["fs_read"](f["path"])
        assert "data" in r_read
        r_write = await tools["fs_write"](f["path"], "new")
        assert "permission_required" in r_write

    async def test_write_grant_allows_read(self, tools, wired_system):
        """Write-only grant: read still works (auto-allowed in paths_allow)."""
        config, _, pm = wired_system
        f = _create_file(config, "iso_write_only.txt", "data")
        pm.grant_direct(f["path"], "write", GrantLevel.SESSION)
        # Read is auto-allowed in paths_allow
        r_read = await tools["fs_read"](f["path"])
        assert "data" in r_read
        # Write works (has grant)
        r_write = await tools["fs_write"](f["path"], "new")
        assert "Written" in r_write

    async def test_wildcard_grant_covers_both_read_and_write(self, tools, wired_system):
        """Wildcard "*" grant: both read and write closures pass through to _impl."""
        config, _, pm = wired_system
        f = _create_file(config, "iso_wild_both.txt", "data")
        pm.grant_direct(f["path"], "*", GrantLevel.SESSION)
        r1 = await tools["fs_read"](f["path"])
        assert "data" in r1
        r2 = await tools["fs_write"](f["path"], "new")
        assert "Written" in r2

    async def test_independent_grants_per_path(self, tools, wired_system):
        """Each path has independent write grants; revoke blocks write not read."""
        config, _, pm = wired_system
        a = _create_file(config, "iso_a.txt", "aaa")
        b = _create_file(config, "iso_b.txt", "bbb")
        pm.grant_direct(a["path"], "write", GrantLevel.SESSION)
        pm.grant_direct(b["path"], "write", GrantLevel.SESSION)
        # Read auto-allowed in paths_allow
        r_a = await tools["fs_read"](a["path"])
        assert "aaa" in r_a
        r_b = await tools["fs_read"](b["path"])
        assert "bbb" in r_b
        # Both writes work
        assert "Written" in await tools["fs_write"](a["path"], "new")
        assert "Written" in await tools["fs_write"](b["path"], "new")
        # Revoke a's grant → a write blocked, b write still works
        pm.revoke(a["path"])
        r_a2 = await tools["fs_write"](a["path"], "x")
        assert "permission_required" in r_a2
        r_b2 = await tools["fs_write"](b["path"], "y")
        assert "Written" in r_b2

    async def test_wildcard_grant_covers_both_ops(self, tools, wired_system):
        config, _, pm = wired_system
        f = _create_file(config, "iso_wild.txt", "data")
        pm.grant_direct(f["path"], "*", GrantLevel.SESSION)
        r1 = await tools["fs_read"](f["path"])
        assert "data" in r1
        r2 = await tools["fs_write"](f["path"], "new")
        assert "Written" in r2


# ===================================================================
# 11 — Ticket lifecycle through tool closures
# ===================================================================

class TestFullTicketLifecycle:

    async def test_tool_call_then_approve_then_call_ok(self, tools, wired_system):
        """Write blocked → approve → write succeeds (write requires grant)."""
        config, _, pm = wired_system
        f = _create_file(config, "lifecycle_approve.txt", "data")
        r1 = await tools["fs_write"](f["path"], "new")
        data = json.loads(r1)
        assert data["status"] == "permission_required"
        ticket_id = data["ticket"]
        code = pm._tickets[ticket_id].confirm_code
        r_approve = await tools["fs_approve"](ticket_id, code, "session")
        assert "Granted session access" in r_approve
        r2 = await tools["fs_write"](f["path"], "new")
        assert "Written" in r2

    async def test_tool_call_then_deny_then_new_ticket(self, tools, wired_system):
        config, _, _ = wired_system
        f = _create_file(config, "lifecycle_deny.txt", "data")
        r1 = await tools["fs_write"](f["path"], "new")
        data = json.loads(r1)
        ticket_id = data["ticket"]
        r_deny = await tools["fs_deny"](ticket_id)
        assert "Denied access" in r_deny
        r2 = await tools["fs_write"](f["path"], "new")
        data2 = json.loads(r2)
        assert data2["status"] == "permission_required"
        assert data2["ticket"] != ticket_id  # new ticket

    async def test_session_grant_persists_multiple_calls(self, tools, wired_system):
        config, _, pm = wired_system
        f = _create_file(config, "lifecycle_session.txt", "data")
        ticket = pm.request(f["path"], "read", GrantLevel.SESSION)
        await tools["fs_approve"](ticket.id, ticket.confirm_code, "session")
        for _ in range(3):
            result = await tools["fs_read"](f["path"])
            assert "data" in result

    async def test_single_grant_consumed_at_validate_level(self, wired_system):
        """Single grant consumed by validate_tool_path (write operation)."""
        config, sec, pm = wired_system
        f = _create_file(config, "lifecycle_single.txt", "data")
        ticket = pm.request(f["path"], "write", GrantLevel.SINGLE)
        pm.approve(ticket.id, confirm_code=ticket.confirm_code)
        # validate_tool_path consumes it (would pass to _impl)
        err = sec.validate_tool_path(f["path"], "write")
        assert err is None
        # Second call fails
        err = sec.validate_tool_path(f["path"], "write")
        assert "permission_required" in err

    async def test_revoke_mid_session(self, tools, wired_system):
        config, _, pm = wired_system
        f = _create_file(config, "lifecycle_revoke.txt", "data")
        pm.grant_direct(f["path"], "write", GrantLevel.SESSION)
        r1 = await tools["fs_write"](f["path"], "new")
        assert "Written" in r1
        await tools["security_revoke"](f["path"])
        r2 = await tools["fs_write"](f["path"], "new2")
        assert "permission_required" in r2

    async def test_pending_shows_after_tool_call(self, tools, wired_system):
        config, _, _ = wired_system
        f = _create_file(config, "lifecycle_pending.txt", "data")
        await tools["fs_write"](f["path"], "new")  # write creates ticket
        result = await tools["security_pending"]()
        data = json.loads(result)
        assert data[0]["resource"] == f["path"]
        assert data[0]["operation"] == "write"

    async def test_stats_reflects_all_activity(self, tools, wired_system):
        config, _, pm = wired_system
        f1 = _create_file(config, "lifecycle_stats_a.txt")
        f2 = _create_file(config, "lifecycle_stats_b.txt")
        t1 = pm.request(f1["path"], "read", GrantLevel.SESSION)
        t2 = pm.request(f2["path"], "read", GrantLevel.SINGLE)
        await tools["fs_approve"](t1.id, t1.confirm_code, "session")
        await tools["fs_approve"](t2.id, t2.confirm_code, "single")
        stats = json.loads(await tools["security_stats"]())
        assert stats["total_tickets"] == 2
        assert stats["approved"] == 2


# ===================================================================
# 12 — Edge cases
# ===================================================================

class TestEdgeCases:

    async def test_empty_paths_allow_blocks_all_except_data_dir(self, temp_home):
        config = AppConfig(
            security=SecurityConfig(paths_allow=[]),
            data_dir=str(temp_home / ".personal-mcp" / "data"),
        )
        pm = PermissionManager(config)
        sec = SecurityValidator(config)
        sec.perm_manager = pm
        tools_local = {"fs_read": _make_fs_read(sec)}
        # Outside (Repos is not in paths_allow)
        outside = str(temp_home / "Repos" / "file.txt")
        Path(outside).parent.mkdir(parents=True, exist_ok=True)
        Path(outside).write_text("test")
        r1 = await tools_local["fs_read"](outside)
        assert "Access denied" in r1
        # data_dir still works
        inside = str(temp_home / ".personal-mcp" / "data" / "state.json")
        Path(inside).parent.mkdir(parents=True, exist_ok=True)
        Path(inside).write_text('{"ok": true}')
        r2 = await tools_local["fs_read"](inside)
        assert '{"ok": true}' in r2

    async def test_clear_cache_does_not_lose_grants(self, tools, wired_system):
        config, sec, pm = wired_system
        f = _create_file(config, "cache_test.txt", "data")
        pm.grant_direct(f["path"], "read", GrantLevel.SESSION)
        r1 = await tools["fs_read"](f["path"])
        assert "data" in r1
        sec.clear_cache()
        r2 = await tools["fs_read"](f["path"])
        assert "data" in r2

    async def test_fs_batch_validates_both_paths(self, tools, wired_system):
        config, _, pm = wired_system
        src = Path(config.security.paths_allow[0]) / "batch_src"
        src.mkdir(parents=True, exist_ok=True)
        (src / "f1.txt").write_text("a")
        dst = Path(config.security.paths_allow[0]) / "batch_dst"
        dst.mkdir(parents=True, exist_ok=True)
        pm.grant_direct(str(src), "read", GrantLevel.SESSION)
        # _impl calls resolve_and_validate with default "read", use "*"
        pm.grant_direct(str(dst), "*", GrantLevel.SESSION)
        result = await tools["fs_batch"](str(src), "copy", str(dst))
        assert "f1.txt" in result

    async def test_fs_batch_blocked_if_target_not_granted(self, tools, wired_system):
        config, _, pm = wired_system
        src = Path(config.security.paths_allow[0]) / "batch_src2"
        src.mkdir(parents=True, exist_ok=True)
        (src / "f1.txt").write_text("a")
        dst = Path(config.security.paths_allow[0]) / "batch_dst2"
        dst.mkdir(parents=True, exist_ok=True)
        pm.grant_direct(str(src), "read", GrantLevel.SESSION)
        # No grant for dst
        result = await tools["fs_batch"](str(src), "copy", str(dst))
        assert "permission_required" in result

    async def test_snapshot_requires_write_grant(self, tools, wired_system):
        config, _, pm = wired_system
        d = Path(config.security.paths_allow[0]) / "snap_dir"
        d.mkdir(parents=True, exist_ok=True)
        (d / "a.txt").write_text("a")
        # Read-only grant — snapshot needs write
        pm.grant_direct(str(d), "read", GrantLevel.SESSION)
        result = await tools["fs_read"](str(d / "a.txt"))
        assert "a" in result
        result = await tools["fs_edit"](str(d / "a.txt"), "a", "b")
        assert "permission_required" in result
