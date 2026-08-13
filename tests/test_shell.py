import asyncio
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import AppConfig, SecurityConfig, ShellConfig
from src.layers.layer2_shell import (
    ShellManager,
    SpawnManager,
    _check_spawn_permission,
    _escape_workdir,
    _truncate,
    _validate_command_paths,
    sh_exec_impl,
    sh_history_impl,
    sh_script_impl,
    sh_session_close_impl,
    sh_session_list_impl,
    sh_session_send_impl,
    sh_session_start_impl,
    sh_spawn_impl,
    sh_spawn_kill_impl,
    sh_spawn_list_impl,
    sh_spawn_read_impl,
)
from src.oslayer import kill_process_tree, reap_after_kill
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


@pytest.mark.usefixtures("skip_on_linux")
@pytest.mark.asyncio
async def test_sh_session_create_and_list(sec, manager):
    result = await sh_session_start_impl(manager)
    data = json.loads(result)
    assert "session_id" in data

    listing = await sh_session_list_impl(manager)
    assert data["session_id"][:8] in listing


@pytest.mark.usefixtures("skip_on_linux")
@pytest.mark.asyncio
async def test_sh_session_send(sec, manager):
    result = await sh_session_start_impl(manager)
    data = json.loads(result)
    sid = data["session_id"]
    await sh_session_send_impl(sid, "echo test123", manager, sec)
    await sh_session_close_impl(sid, manager)


@pytest.mark.usefixtures("skip_on_linux")
@pytest.mark.asyncio
async def test_sh_session_close(sec, manager):
    result = await sh_session_start_impl(manager)
    data = json.loads(result)
    sid = data["session_id"]
    close_result = await sh_session_close_impl(sid, manager)
    assert "closed" in close_result


@pytest.mark.usefixtures("skip_on_linux")
@pytest.mark.asyncio
async def test_sh_session_expired(sec):
    manager = ShellManager(sec, default_timeout=0)
    result = await sh_session_start_impl(manager)
    data = json.loads(result)
    data["session_id"]
    listing = await sh_session_list_impl(manager)
    assert "No active sessions" in listing


# --- ShellSession stale-output fix (2026-08-08, found via external audit,
# no reported incident): _reader() queues continuously and independently of
# which execute() call is "current" -- a command whose output arrives AFTER
# its own execute() already returned (timed out while the shell kept running)
# used to sit in the queue and get misattributed to the NEXT command sent to
# the same session. ---

@pytest.mark.asyncio
async def test_drain_stale_output_clears_queue():
    from src.layers.layer2_shell import ShellSession
    from src.shell_resolver import ShellInfo

    # _drain_stale_output() is shell-independent; use a synthetic ShellInfo
    # instead of resolving a real shell (the previous `resolve_shell("cmd")`
    # failed on non-Windows, where "cmd" isn't in SHELL_REGISTRY).
    session = ShellSession("test-id", 300, ShellInfo(name="fake", executable="fake"))
    await session._output_buffer.put(b"leftover1\n")
    await session._output_buffer.put(b"leftover2\n")
    drained = session._drain_stale_output()
    assert drained == 2
    assert session._output_buffer.empty()


@pytest.mark.usefixtures("skip_on_linux")
@pytest.mark.asyncio
async def test_session_execute_does_not_leak_stale_output_into_next_command(sec, manager):
    session = await manager.create_session()
    try:
        # Sleeps then prints a marker -- execute()'s own short timeout elapses
        # long before that output arrives, so it returns with no output while
        # the shell keeps running the sleep in the background.
        first = await session.execute(
            "Start-Sleep -Milliseconds 800; Write-Output LATE_MARKER", timeout=0.3
        )
        assert "LATE_MARKER" not in first

        # Wait deterministically for the background command's output to actually
        # be queued by _reader(), instead of a fixed sleep (timing-flaky under
        # load: the 800ms Start-Sleep + _reader()'s ~0.5s readline poll may not
        # complete by a fixed 1.2s). Poll until the buffer has content, so the
        # next execute()'s _drain_stale_output() is guaranteed to find it.
        for _ in range(100):  # up to ~10s
            if not session._output_buffer.empty():
                break
            await asyncio.sleep(0.1)

        second = await session.execute("echo FRESH_MARKER", timeout=5)
        assert "FRESH_MARKER" in second
        assert "LATE_MARKER" not in second
    finally:
        await session.close()


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

@ pytest.mark.usefixtures("skip_on_linux")
@pytest.mark.asyncio
async def test_sh_exec_cmd_shell(sec, manager):
    cmd_shell = resolve_shell("cmd")
    result = await sh_exec_impl("echo hello_cmd", sec, timeout=10, shell_info=cmd_shell)
    assert "hello_cmd" in result


@ pytest.mark.usefixtures("skip_on_linux")
@pytest.mark.asyncio
async def test_sh_session_cmd_rejected(sec):
    cmd_shell = resolve_shell("cmd")
    mgr = ShellManager(sec, default_timeout=300, shell_info=cmd_shell)
    result = await sh_session_start_impl(mgr)
    data = json.loads(result)
    assert "error" in data


@pytest.mark.usefixtures("skip_on_linux")
@pytest.mark.asyncio
async def test_sh_exec_cmd_basic(sec, manager):
    cmd_shell = resolve_shell("cmd")
    result = await sh_exec_impl("echo hello_from_cmd", sec, timeout=10, shell_info=cmd_shell)
    assert "hello_from_cmd" in result


# --- #1: argv-style execution tests ---

@pytest.mark.skipif(shutil.which("python") is None, reason="'python' not on PATH (some Linux distros only ship python3)")
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


@pytest.mark.skipif(shutil.which("python") is None, reason="'python' not on PATH (some Linux distros only ship python3)")
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


# --- Mejora 3: Warnings estructurados (removidos 2026-08-08, ver CHANGELOG --
# _scan_command_warnings/_format_warnings eran codigo muerto: el gate previo
# _validate_command_paths() usa el mismo predicado y ya corta con error antes
# de que el escaneo de warnings pudiera encontrar algo)


# --- Mejora 4: Kill recursivo ---

@pytest.mark.usefixtures("skip_on_linux")
@pytest.mark.asyncio
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

@pytest.mark.usefixtures("skip_on_linux")
@pytest.mark.asyncio
async def test_sh_script_with_cmd_shell(sec, manager):
    cmd_shell = resolve_shell("cmd")
    result = await sh_script_impl("echo hello_script_cmd", sec, timeout=10, shell_info=cmd_shell)
    assert "hello_script_cmd" in result


@pytest.mark.usefixtures("skip_on_linux")
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


@pytest.mark.usefixtures("skip_on_linux")
@pytest.mark.asyncio
async def test_sh_session_start_with_shell_param(sec):
    si = resolve_shell("cmd")
    mgr = ShellManager(sec, default_timeout=300)
    result = await sh_session_start_impl(mgr, shell_info=si)
    data = json.loads(result)
    assert "error" in data
    assert "cmd" in data["error"].lower()


# --- sh_spawn ---

@pytest.fixture
def spawn_manager(sec):
    return SpawnManager(sec)


@pytest.mark.asyncio
async def test_sh_spawn_basic(sec, manager, spawn_manager):
    result = await sh_spawn_impl("echo spawned_hello", sec, manager, spawn_manager)
    data = json.loads(result)
    assert "spawn_id" in data
    assert "pid" in data
    await asyncio.sleep(0.5)
    read_result = await sh_spawn_read_impl(data["spawn_id"], spawn_manager)
    assert "spawned_hello" in read_result


@pytest.mark.asyncio
async def test_sh_spawn_reaps_process_that_exits_on_its_own(sec, manager, spawn_manager):
    """2026-08-08 fix: a spawned process that exits by itself (not via
    sh_spawn_kill) used to never be reaped -- SpawnedProcess._reader() set
    status='exited' but never called process.wait(), leaking a handle.
    """
    result = await sh_spawn_impl("echo quick_exit", sec, manager, spawn_manager)
    data = json.loads(result)
    spawned = spawn_manager.get(data["spawn_id"])
    for _ in range(30):
        if spawned.status == "exited":
            break
        await asyncio.sleep(0.1)
    assert spawned.status == "exited"
    assert spawned._process.returncode is not None


@pytest.mark.asyncio
async def test_sh_spawn_read_not_found(spawn_manager):
    result = await sh_spawn_read_impl("nonexistent-id", spawn_manager)
    assert "not found" in result.lower()


@pytest.mark.usefixtures("skip_on_linux")
@pytest.mark.asyncio
async def test_sh_spawn_kill(sec, manager, spawn_manager):
    result = await sh_spawn_impl("Start-Sleep -Seconds 30", sec, manager, spawn_manager)
    data = json.loads(result)
    spawn_id = data["spawn_id"]

    kill_result = await sh_spawn_kill_impl(spawn_id, spawn_manager)
    assert "Killed" in kill_result

    read_result = await sh_spawn_read_impl(spawn_id, spawn_manager)
    assert "not found" in read_result.lower()


@pytest.mark.asyncio
async def test_sh_spawn_kill_not_found(spawn_manager):
    result = await sh_spawn_kill_impl("nonexistent-id", spawn_manager)
    assert "not found" in result.lower()


@pytest.mark.asyncio
async def test_sh_spawn_list(sec, manager, spawn_manager):
    result = await sh_spawn_impl("echo list_test", sec, manager, spawn_manager)
    data = json.loads(result)
    listing = await sh_spawn_list_impl(spawn_manager)
    assert data["spawn_id"][:8] in listing


@pytest.mark.asyncio
async def test_sh_spawn_list_empty(spawn_manager):
    result = await sh_spawn_list_impl(spawn_manager)
    assert "No spawned processes" in result


@pytest.mark.asyncio
async def test_sh_spawn_requires_execute_permission(temp_home):
    """sh_spawn must go through its own 'execute' ticket when a
    PermissionManager is attached -- regression test for security
    requirement #3 (AGENTS.md 'Feature diferida'): a spawn must never be
    reachable purely because some unrelated wildcard grant exists."""
    from src.permissions import PermissionManager

    config = AppConfig(
        security=SecurityConfig(paths_allow=[str(temp_home / "Repos")]),
        data_dir=str(temp_home / ".personal-mcp" / "data"),
        config_path=str(temp_home / ".personal-mcp" / "config.json"),
    )
    security = SecurityValidator(config)
    security.perm_manager = PermissionManager(config)

    result = _check_spawn_permission("echo gated", security)
    assert result is not None
    data = json.loads(result)
    assert data["status"] == "permission_required"
    assert data["operation"] == "execute"


@pytest.mark.asyncio
async def test_sh_spawn_wildcard_grant_is_not_sufficient(temp_home):
    """A wildcard '*' grant on some resource must not satisfy sh_spawn's
    'execute' check -- exercises the existing
    `operation not in ("delete", "execute")` exclusion in
    PermissionManager.check_granted(), which is what actually enforces
    requirement #3 (no new code was added for this in security.py/
    permissions.py, see _check_spawn_permission's docstring)."""
    from src.permissions import PermissionManager

    config = AppConfig(
        security=SecurityConfig(paths_allow=[str(temp_home / "Repos")]),
        data_dir=str(temp_home / ".personal-mcp" / "data"),
        config_path=str(temp_home / ".personal-mcp" / "config.json"),
    )
    security = SecurityValidator(config)
    perm_manager = PermissionManager(config)
    security.perm_manager = perm_manager

    # Simulate a broad wildcard grant a user might have approved for some
    # other resource entirely -- must not leak into spawn permission.
    perm_manager._session_grants["some_other_resource"] = {"*"}

    result = _check_spawn_permission("echo should_still_be_gated", security)
    assert result is not None
    data = json.loads(result)
    assert data["status"] == "permission_required"


@pytest.mark.asyncio
async def test_spawn_manager_detects_orphan(sec):
    """Core safety property of SpawnManager: a record whose owner_pid is
    confirmed dead, but whose child process is still alive, must be
    reported as orphaned -- not silently ignored, not auto-killed."""
    child = await asyncio.create_subprocess_exec(
        sys.executable, "-c", "import time; time.sleep(30)",
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        registry_path = Path(sec.config.data_dir) / "spawned_processes.jsonl"
        registry_path.parent.mkdir(parents=True, exist_ok=True)
        registry_path.write_text(
            json.dumps({
                "spawn_id": "fake-orphan-1", "pid": child.pid,
                "owner_pid": 999999,  # astronomically unlikely to be a real live pid
                "command": "some long running thing", "started_at": 0,
                "status": "running",
            }) + "\n",
            encoding="utf-8",
        )

        mgr = SpawnManager(sec)
        listing = json.loads(await sh_spawn_list_impl(mgr))
        orphans = [i for i in listing if i.get("status") == "orphaned"]
        assert len(orphans) == 1
        assert orphans[0]["pid"] == child.pid
    finally:
        await kill_process_tree(child.pid)
        await reap_after_kill(child)


@pytest.mark.asyncio
async def test_spawn_manager_ignores_record_with_alive_owner(sec):
    """A record whose owner_pid is still alive belongs to a sibling server
    still running -- must be left completely untouched, not reported as
    orphaned, not dropped from the registry."""
    registry_path = Path(sec.config.data_dir) / "spawned_processes.jsonl"
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text(
        json.dumps({
            "spawn_id": "fake-owned-1", "pid": 999998,
            "owner_pid": os.getpid(),  # this test process is very much alive
            "command": "something", "started_at": 0, "status": "running",
        }) + "\n",
        encoding="utf-8",
    )

    mgr = SpawnManager(sec)
    assert len(mgr._orphans) == 0
    records = [json.loads(l) for l in registry_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert any(r["spawn_id"] == "fake-owned-1" and r["status"] == "running" for r in records)


@pytest.mark.asyncio
async def test_spawn_manager_drops_fully_dead_record(sec):
    """A record whose owner AND child are both dead has nothing left to
    track or report -- must be dropped silently from the registry on the
    next reconciliation."""
    registry_path = Path(sec.config.data_dir) / "spawned_processes.jsonl"
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text(
        json.dumps({
            "spawn_id": "fake-dead-1", "pid": 999997, "owner_pid": 999996,
            "command": "long gone", "started_at": 0, "status": "running",
        }) + "\n",
        encoding="utf-8",
    )

    mgr = SpawnManager(sec)
    assert len(mgr._orphans) == 0
    records = [json.loads(l) for l in registry_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert not any(r["spawn_id"] == "fake-dead-1" for r in records)


# --- C-3 (auditoría 2026-08-11): _escape_workdir metacharacter escaping ---

def test_escape_workdir_powershell_escapes_dollar_and_backtick():
    escaped = _escape_workdir("C:\\temp$(calc)", "powershell")
    assert escaped == "C:\\temp`$(calc)"


def test_escape_workdir_powershell_escapes_backtick_first():
    escaped = _escape_workdir("C:\\temp`x", "powershell")
    assert escaped == "C:\\temp``x"


def test_escape_workdir_bash_escapes_dollar():
    escaped = _escape_workdir("/tmp/$(whoami)", "bash")
    assert escaped == "/tmp/\\$(whoami)"


def test_escape_workdir_cmd_escapes_percent():
    escaped = _escape_workdir("C:\\temp%PATH%", "cmd")
    assert escaped == "C:\\temp%%PATH%%"


def test_escape_workdir_still_escapes_quote():
    assert '`"' in _escape_workdir('C:\\a"b', "powershell")
    assert '\\"' in _escape_workdir('/a"b', "bash")
    assert '""' in _escape_workdir('C:\\a"b', "cmd")


def test_escape_workdir_plain_path_unchanged():
    assert _escape_workdir("C:\\Users\\usuario\\Repos\\proj", "powershell") == "C:\\Users\\usuario\\Repos\\proj"
    assert _escape_workdir("/home/user/proj", "bash") == "/home/user/proj"


# --- A-3 (auditoría 2026-08-11): relative traversal blocked in shell commands ---

def test_validate_command_paths_blocks_relative_traversal(sec):
    err = _validate_command_paths("cat ..\\..\\secret.txt", sec)
    assert "Access denied" in err


def test_validate_command_paths_blocks_home_relative(sec):
    err = _validate_command_paths("ls ~/.ssh", sec)
    assert "Access denied" in err


def test_validate_command_paths_allows_git_range_notation(sec):
    err = _validate_command_paths("git log ..HEAD", sec)
    assert err == ""


# --- M-S4 (auditoría 2026-08-11): orphan lookup by truncated id ---

def test_spawn_manager_get_orphan_prefix(sec):
    mgr = SpawnManager(sec)
    mgr._orphans = [{"spawn_id": "abcdef1234567890", "pid": 12345}]
    assert mgr.get_orphan("abcdef12") is not None
    assert mgr.get_orphan("zzzz") is None


# --- M-S5 (auditoría 2026-08-11): capped stream read bounds memory ---

class _FakeStream:
    def __init__(self, data):
        self._data = data
        self._pos = 0

    async def read(self, n):
        if self._pos >= len(self._data):
            return b""
        chunk = self._data[self._pos:self._pos + n]
        self._pos += len(chunk)
        return chunk


@pytest.mark.asyncio
async def test_read_stream_capped_truncates():
    from src.layers.layer2_shell import _read_stream_capped

    out, truncated = await _read_stream_capped(_FakeStream(b"x" * 200), 100)
    assert len(out) == 100
    assert truncated is True


@pytest.mark.asyncio
async def test_read_stream_capped_no_truncation():
    from src.layers.layer2_shell import _read_stream_capped

    out, truncated = await _read_stream_capped(_FakeStream(b"hello"), 100)
    assert out == b"hello"
    assert truncated is False
