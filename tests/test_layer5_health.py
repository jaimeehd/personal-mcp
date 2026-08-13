import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.audit import AuditLog
from src.config import AppConfig, JournalConfig, SecurityConfig, ShellConfig, SSHConfig
from src.layers.layer5_health import _get_uptime, _get_version


@pytest.fixture
def test_config(tmp_path):
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    return AppConfig(
        security=SecurityConfig(
            paths_allow=[str(tmp_path)],
            paths_deny=["**\\node_modules\\**", "**\\.git\\**"],
        ),
        shell=ShellConfig(enabled=True, session_timeout_seconds=60),
        ssh=SSHConfig(enabled=False),
        journal=JournalConfig(
            enabled=True,
            path=str(tmp_path / "journal"),
        ),
        data_dir=str(tmp_path / "data"),
        audit_max_entries=1000,
        config_path=str(tmp_path / "config.json"),
    )


def test_get_version_found():
    result = _get_version("git", "--version")
    assert result != "not found"
    assert "git" in result.lower()


def test_get_version_not_found():
    result = _get_version("nonexistent_binary_xyz", "--version")
    assert result == "not found"


def test_get_uptime():
    result = _get_uptime()
    assert result != "unavailable"


def test_register_health_tools_produces_sync_tools(test_config):
    from mcp.server.fastmcp import FastMCP

    audit_log = AuditLog(max_entries=100)
    app = FastMCP("test")
    from src.layers.layer5_health import register_health_tools

    register_health_tools(app, test_config, audit_log)

    tool_names = [t.name for t in app._tool_manager.list_tools()]
    assert "health_check" in tool_names
    assert "health_disk" in tool_names
    assert "health_processes" in tool_names
    assert "mcp_diag" in tool_names
    assert "mcp_audit_log" in tool_names
    assert "mcp_benchmark" in tool_names
    assert "mcp_log" in tool_names


async def test_health_processes_tool_executes_without_recursion(test_config):
    """Regression test for a name-shadowing bug.

    The @mcp.tool-decorated `health_processes` closure previously shared its
    name with the module-level `_dispatch_processes` (formerly also named
    `health_processes`). Python's scoping resolved the call inside the closure
    to itself instead of the module-level implementation, so every invocation
    raised RecursionError — even though `test_register_health_tools_produces_sync_tools`
    passed, because it only checks that the name is registered and never calls
    the tool. This test calls it for real, the way an MCP client would.
    """
    from mcp.server.fastmcp import FastMCP

    audit_log = AuditLog(max_entries=100)
    app = FastMCP("test")
    from src.layers.layer5_health import register_health_tools

    register_health_tools(app, test_config, audit_log)

    result = await app._tool_manager.call_tool("health_processes", {"top": 3})
    assert isinstance(result, str)
