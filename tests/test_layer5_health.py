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
    raised RecursionError - even though `test_register_health_tools_produces_sync_tools`
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


async def test_mcp_log_clamps_and_tolerates_empty_level(test_config):
    import logging

    from src.server import AuditedFastMCP

    log_path = Path(test_config.data_dir) / "server.log"
    log_path.write_text(
        "".join(f"2026-01-01 00:00:0{i % 10}.000 [INFO ] line {i}\n" for i in range(50)),
        encoding="utf-8",
    )
    app = AuditedFastMCP("test", audit_log=AuditLog(max_entries=10),
                         logger=logging.getLogger("test-mcp-log"))
    from src.layers.layer5_health import register_health_tools

    register_health_tools(app, test_config, AuditLog(max_entries=10))
    # lines=0 se clampa a >=1 (no vuelca todo); level="" no lanza IndexError
    r0 = await app._tool_manager.call_tool("mcp_log", {"lines": 0, "level": ""})
    assert isinstance(r0, str)
    rbig = await app._tool_manager.call_tool(
        "mcp_log", {"lines": 999999, "level": "INFO"})
    assert isinstance(rbig, str)
    assert len(rbig.splitlines()) <= test_config.log.mcp_log_max_lines


async def test_health_processes_cached(test_config, monkeypatch):
    """P1.3: segunda llamada dentro del TTL no re-ejecuta el subprocess."""
    import src.layers.layer5_health as h

    calls = {"n": 0}
    real = h._dispatch_processes

    async def counting(top=10):
        calls["n"] += 1
        return await real(top)

    monkeypatch.setattr(h, "_dispatch_processes", counting)
    h._process_cache.clear()
    try:
        import logging

        from src.layers.layer5_health import register_health_tools as _register
        from src.server import AuditedFastMCP

        app = AuditedFastMCP("test", audit_log=AuditLog(max_entries=10),
                             logger=logging.getLogger("test-hp-cache"))
        _register(app, test_config, AuditLog(max_entries=10))
        await app._tool_manager.call_tool("health_processes", {"top": 3})
        await app._tool_manager.call_tool("health_processes", {"top": 3})
        assert calls["n"] == 1
    finally:
        h._process_cache.clear()


async def test_mcp_diag_versions_cached(test_config, monkeypatch):
    """M1: la 2ª llamada a mcp_diag dentro del TTL no re-lanza los 4 probes."""
    import src.layers.layer5_health as h

    calls = {"n": 0}
    real = h._get_version

    def counting(cmd, flag):
        calls["n"] += 1
        return real(cmd, flag)

    monkeypatch.setattr(h, "_get_version", counting)
    h._diag_versions_cache = None
    try:
        import logging

        from src.layers.layer5_health import register_health_tools as _register
        from src.server import AuditedFastMCP

        app = AuditedFastMCP("test", audit_log=AuditLog(max_entries=10),
                             logger=logging.getLogger("test-diag-cache"))
        _register(app, test_config, AuditLog(max_entries=10))
        await app._tool_manager.call_tool("mcp_diag", {})
        first = calls["n"]
        await app._tool_manager.call_tool("mcp_diag", {})
        assert calls["n"] == first, "2ª llamada no debe re-probear versiones"
        assert first == 4
    finally:
        h._diag_versions_cache = None
