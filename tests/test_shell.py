import asyncio
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import AppConfig, SecurityConfig, ShellConfig
from src.layers.layer2_shell import (
    ShellManager,
    _scan_command_warnings,
    _truncate,
    sh_exec_impl,
    sh_history_impl,
    sh_script_impl,
    sh_session_close_impl,
    sh_session_list_impl,
    sh_session_send_impl,
    sh_session_start_impl,
)
from src.oslayer import kill_process_tree
from src.security import CommandNotAllowedError, SecurityValidator
from src.shell_resolver import resolve_shell


@pytest.fixture
def sec(temp_home):
    config = AppConfig(
        security=SecurityConfig(
            paths_allow=[str(temp_home / "Repos")],
        ),
        shell=ShellConfig(enabled=True, session_timeout_seconds=300),
        data_dir=str(temp_home / ".personal-mcp" / "data"),
        config_path=str(temp_home / ".personal-mcp" / "config.json"),
    )
    return SecurityValidator(config)


@pytest.fixture
def manager(sec):
    return ShellManager(sec, default_timeout=300)


@pytest.mark.asyncio
async def test_sh_exec(sec, manager):
    result = await sh_exec_impl("echo hello", sec)
    assert "hello" in result


@pytest.mark.asyncio
async def test_sh_exec_denied_command(sec, manager):
    with pytest.raises(CommandNotAllowedError):
        await sh_exec_impl("shutdown /s", sec)


@pytest.mark.asyncio
async def test_sh_exec_custom_command(sec, manager):
    result = await sh_exec_impl("echo custom_tool test", sec)
    assert "test" in result


@pytest.mark.asyncio
async def test_sh_session_create_and_list(sec, manager):
    result = await sh_session_start_impl(manager)
    data = json.loads(result)
    assert "session_id" in data

    listing = await sh_session_list_impl(manager)
    assert data["session_id"][:8] in listing


@pytest.mark.asyncio
async def test_sh_session_send(sec, manager):
    result = await sh_session_start_impl(manager)
    data = json.loads(result)
    sid = data["session_id"]
    await sh_session_send_impl(sid, "echo test123", manager, sec)
    await sh_session_close_impl(sid, manager)


@pytest.mark.asyncio
async def test_sh_session_close(sec, manager):
    result = await sh_session_start_impl(manager)
    data = json.loads(result)
    sid = data["session_id"]
    close_result = await sh_session_close_impl(sid, manager)
    assert "closed" in close_result


@pytest.mark.asyncio
async def test_sh_session_expired(sec):
    manager = ShellManager(sec, default_timeout=0)
    result = await sh_session_start_impl(manager)
    data = json.loads(result)
    data["session_id"]
    listing = await sh_session_list_impl(manager)
    assert "No active sessions" in listing


@pytest.mark.asyncio
async def test_sh_script(sec, manager):
    result = await sh_script_impl("echo 'script test'", sec)
    assert "Exit code:" in result


@pytest.mark.asyncio
async def test_sh_history(sec, manager):
    result = await sh_history_impl(manager)
    assert "No history" in result or "session_id" in result


# --- Mejora 1: Output truncation ---

def test_truncate_under_limit():
    text = "hello world"
    result, truncated = _truncate(text, max_bytes=100)
    assert result == text
    assert truncated is False


def test_truncate_over_limit():
    text = "a" * 1000
    result, truncated = _truncate(text, max_bytes=100)
    assert len(result.encode("utf-8")) <= 100
    assert truncated is True


@pytest.mark.asyncio
async def test_sh_exec_truncated(sec, manager):
    large = "echo " + "a" * 2000
    result = await sh_exec_impl(large, sec, timeout=10)
    assert "Exit code:" in result


# --- Mejora 2: Shell detection ---

@ pytest.mark.asyncio
async def test_sh_exec_cmd_shell(sec, manager):
    cmd_shell = resolve_shell("cmd")
    result = await sh_exec_impl("echo hello_cmd", sec, timeout=10, shell_info=cmd_shell)
    assert "hello_cmd" in result


@ pytest.mark.asyncio
async def test_sh_session_cmd_rejected(sec):
    cmd_shell = resolve_shell("cmd")
    mgr = ShellManager(sec, default_timeout=300, shell_info=cmd_shell)
    result = await sh_session_start_impl(mgr)
    data = json.loads(result)
    assert "error" in data


@pytest.mark.asyncio
async def test_sh_exec_cmd_basic(sec, manager):
    cmd_shell = resolve_shell("cmd")
    result = await sh_exec_impl("echo hello_from_cmd", sec, timeout=10, shell_info=cmd_shell)
    assert "hello_from_cmd" in result


# --- #1: argv-style execution tests ---

@pytest.mark.asyncio
async def test_sh_exec_argv_native(sec, manager):
    """Native executable runs directly (no shell)."""
    result = await sh_exec_impl("python --version", sec, timeout=10)
    assert "Python" in result


@pytest.mark.asyncio
async def test_sh_exec_argv_fallback_shell(sec, manager):
    """Shell builtin (no native exe) falls back to shell execution."""
    result = await sh_exec_impl("echo builtin_test", sec, timeout=10)
    assert "builtin_test" in result


@pytest.mark.asyncio
async def test_sh_exec_argv_with_working_dir(sec, manager):
    """argv execution with cwd parameter (cwd via create_subprocess_exec)."""
    import os
    import tempfile
    tmpdir = tempfile.mkdtemp()
    result = await sh_exec_impl(
        'python -c "import os; print(os.getcwd())"',
        sec, timeout=10, working_dir=tmpdir
    )
    assert os.path.basename(tmpdir) in result
    os.rmdir(tmpdir)


@pytest.mark.asyncio
async def test_sh_exec_shell_operators_fallback(sec, manager):
    """Commands with shell operators fall back to shell execution."""
    result = await sh_exec_impl("echo pipe_test | python --version", sec, timeout=10)
    assert "Exit code:" in result


# --- Mejora 3: Warnings estructurados ---

def test_scan_command_warnings_no_paths(sec):
    warnings = _scan_command_warnings("echo hello", sec)
    assert warnings == []


def test_scan_command_warnings_external_path(sec, temp_home):
    external = "C:\\Windows\\system.ini"
    warnings = _scan_command_warnings(f"type {external}", sec)
    assert len(warnings) >= 1
    assert "external" in warnings[0].lower()


# --- Mejora 4: Kill recursivo ---

@ pytest.mark.asyncio
async def test_kill_process_tree(sec):
    proc = await asyncio.create_subprocess_exec(
        "powershell.exe", "-NoProfile", "-Command",
        "Start-Sleep -Seconds 30",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await asyncio.sleep(0.5)
    await kill_process_tree(proc.pid)
    ret = await proc.wait()
    assert ret != 0


# --- Shell switching — parámetro shell en tools ---

@pytest.mark.asyncio
async def test_sh_script_with_cmd_shell(sec, manager):
    cmd_shell = resolve_shell("cmd")
    result = await sh_script_impl("echo hello_script_cmd", sec, timeout=10, shell_info=cmd_shell)
    assert "hello_script_cmd" in result


@pytest.mark.asyncio
async def test_manager_resolve_shell(sec):
    mgr = ShellManager(sec, default_timeout=300)
    si = mgr.resolve_shell("cmd")
    assert si.name == "cmd"
    assert "cmd.exe" in si.executable.lower() or "comspec" in si.executable.lower()


@pytest.mark.asyncio
async def test_manager_shell_map_storage(sec):
    shell_map = {"bash": "C:\\custom\\bash.exe"}
    mgr = ShellManager(sec, default_timeout=300, shell_map=shell_map)
    assert mgr.shell_map == shell_map


def test_resolve_shell_invalid_name():
    with pytest.raises(ValueError, match="Unknown shell"):
        resolve_shell("nonexistent_shell")


@pytest.mark.asyncio
async def test_sh_session_start_with_shell_param(sec):
    si = resolve_shell("cmd")
    mgr = ShellManager(sec, default_timeout=300)
    result = await sh_session_start_impl(mgr, shell_info=si)
    data = json.loads(result)
    assert "error" in data
    assert "cmd" in data["error"].lower()
