import asyncio
import json
import os
import platform
import shutil
import subprocess
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from src.audit import AuditLog
from src.config import AppConfig
from src.oslayer.system import available_memory_info, uptime_seconds


def _get_version(cmd: str, flag: str) -> str:
    try:
        if shutil.which(cmd) is None:
            return "not found"
        r = subprocess.run([cmd, flag],
                           stdin=subprocess.DEVNULL,
                           capture_output=True,
                           text=True, timeout=5)
        return (r.stdout or r.stderr).strip()[:100]
    except Exception:
        return "not found"


def _get_uptime() -> str:
    """Return OS boot time string via platform-native call (no subprocess)."""
    uptime = uptime_seconds()
    if uptime is not None:
        boot_time = datetime.now() - timedelta(seconds=uptime)
        return boot_time.strftime("%Y-%m-%d %H:%M:%S")
    return "unavailable"


def _fetch_processes_linux(top: int) -> str:
    """Fetch top processes on Linux using ps."""
    try:
        r = subprocess.run(
            ["ps", "aux", "--sort=-%cpu"],
            capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL,
        )
        lines = r.stdout.splitlines()
        if len(lines) > top + 1:
            lines = lines[:top + 1]  # header + top N
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


def _fetch_processes_macos(top: int) -> str:
    """Fetch top processes on macOS using ps."""
    try:
        r = subprocess.run(
            ["ps", "aux", "-r"],
            capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL,
        )
        lines = r.stdout.splitlines()
        if len(lines) > top + 1:
            lines = lines[:top + 1]
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


def _fetch_processes_windows(top: int) -> str:
    """Fetch top processes on Windows using PowerShell."""
    try:
        env = os.environ.copy()
        env["_MCP_TOP"] = str(top)
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             ("Get-Process | Sort-Object CPU -Descending | Select-Object -First $env:_MCP_TOP "
             "Name, Id, @{N='CPU(s)';E={$_.CPU.ToString('F1')}}, "
             "@{N='MemMB';E={($_.WorkingSet/1MB).ToString('F0')}} | Format-Table -AutoSize")],
            capture_output=True, text=True, timeout=10, env=env, stdin=subprocess.DEVNULL,
        )
        return r.stdout or r.stderr
    except Exception as e:
        return f"Error: {e}"


async def _dispatch_processes(top: int = 10) -> str:
    """Cross-platform top processes."""
    if platform.system() == "Windows":
        return await asyncio.to_thread(_fetch_processes_windows, top)
    elif platform.system() == "Darwin":
        return await asyncio.to_thread(_fetch_processes_macos, top)
    else:
        return await asyncio.to_thread(_fetch_processes_linux, top)


# P1.3: cache corta para health_processes (lanza un powershell/ps por llamada,
# medido ~1.9s en vivo). TTL 15s por defecto, clave por `top`.
_PROCESS_CACHE_TTL = 15.0
_process_cache: dict[int, tuple[float, str]] = {}

# M1 (v1.4.85): cache de los probes de versión de mcp_diag (4 subprocess por
# llamada). TTL 60s — la versión de node/npm/git/ssh casi no cambia en runtime.
_DIAG_CACHE_TTL = 60.0
_diag_versions_cache: tuple[float, dict] | None = None


def register_health_tools(mcp: FastMCP, config: AppConfig,
                          audit_log: AuditLog) -> None:

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
    async def health_check() -> str:
        checks = {}
        checks["timestamp"] = datetime.now().isoformat()
        checks["platform"] = platform.platform()
        checks["python_version"] = platform.python_version()
        try:
            d = shutil.disk_usage(Path.home())
            checks["disk"] = {
                "total_gb": round(d.total / (1024**3), 1),
                "free_gb": round(d.free / (1024**3), 1),
                "used_pct": round((d.used / d.total) * 100, 1),
            }
        except Exception:
            checks["disk"] = "unavailable"

        mem_info = available_memory_info()
        if mem_info:
            checks["memory"] = mem_info
        else:
            checks["memory"] = "unavailable"

        checks["hostname"] = platform.node()
        try:
            config.model_dump(mode="json")
            checks["config_valid"] = True
        except Exception:
            checks["config_valid"] = False
        checks["uptime"] = _get_uptime()
        audit_stats = audit_log.stats()
        checks["audit"] = {
            "total_operations": audit_stats["total_entries"],
            "failed": audit_stats["failed"],
        }
        return json.dumps(checks, indent=2, ensure_ascii=False)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
    async def health_disk(paths: str | None = None) -> str:
        check_paths = [Path(p.strip()) for p in (paths or str(Path.home())).split(";") if p.strip()]
        results = {}
        for p in check_paths:
            try:
                d = shutil.disk_usage(p)
                results[str(p)] = {
                    "total_gb": round(d.total / (1024**3), 1),
                    "used_gb": round(d.used / (1024**3), 1),
                    "free_gb": round(d.free / (1024**3), 1),
                    "used_pct": round((d.used / d.total) * 100, 1),
                }
            except Exception as e:
                results[str(p)] = f"error: {e}"
        return json.dumps(results, indent=2, ensure_ascii=False)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
    async def health_processes(top: int = 10) -> str:
        try:
            top = int(top)
        except (TypeError, ValueError):
            top = 10
        top = max(1, min(top, 50))
        now = time.time()
        hit = _process_cache.get(top)
        if hit and (now - hit[0]) < _PROCESS_CACHE_TTL:
            return hit[1]
        out = await _dispatch_processes(top)
        _process_cache[top] = (now, out)
        return out

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
    async def health_config() -> str:
        try:
            return json.dumps(config.model_dump(mode="json"), indent=2, ensure_ascii=False)
        except Exception as e:
            return f"Config validation error: {e}"

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
    async def mcp_diag() -> str:
        diag = {}
        diag["timestamp"] = datetime.now().isoformat()
        diag["python"] = platform.python_version()
        # M-H1 (auditoría 2026-08-11): _get_version runs a blocking subprocess
        # (up to 5s each, 4 calls = up to 20s). Wrapped in to_thread so the event
        # loop isn't stalled while probing tool versions.
        # M1 (v1.4.85): cache de 60s — solo los probes; timestamp/demás se
        # recalculan por llamada.
        global _diag_versions_cache
        now = time.time()
        if _diag_versions_cache and (now - _diag_versions_cache[0]) < _DIAG_CACHE_TTL:
            versions = _diag_versions_cache[1]
        else:
            versions = {
                "node": await asyncio.to_thread(_get_version, "node", "--version"),
                "npm": await asyncio.to_thread(_get_version, "npm", "--version"),
                "git": await asyncio.to_thread(_get_version, "git", "--version"),
                "ssh": await asyncio.to_thread(_get_version, "ssh", "-V"),
            }
            _diag_versions_cache = (now, versions)
        diag.update(versions)
        diag["config_path"] = str(config.default_path())
        diag["config_exists"] = config.default_path().exists()
        diag["data_dir"] = config.data_dir
        diag["data_dir_exists"] = Path(config.data_dir).exists()
        diag["journal_path"] = config.journal.path
        diag["os"] = platform.platform()
        diag["hostname"] = platform.node()
        diag["allowed_paths"] = config.security.paths_allow
        diag["ssh_enabled"] = config.ssh.enabled
        diag["shell_enabled"] = config.shell.enabled
        audit_stats = audit_log.stats()
        diag["audit"] = f"{audit_stats['total_entries']} operations ({audit_stats['failed']} failed)"
        return json.dumps(diag, indent=2, ensure_ascii=False)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
    async def mcp_audit_log(n: int = 50) -> str:
        entries = audit_log.recent(n)
        return json.dumps(entries, indent=2, ensure_ascii=False)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
    async def mcp_list_tools() -> str:
        try:
            tm = mcp._tool_manager
            tools_list = []
            for t_name, t_def in tm._tools.items():
                desc = t_def.description or ""
                tools_list.append(f"- {t_name}: {desc}")
            return "\n".join(tools_list) if tools_list else "No tools found"
        except Exception as e:
            return f"Tool listing unavailable: {e}"

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False))
    async def mcp_benchmark() -> str:
        results = {}
        start = time.time()
        try:
            bench_path = Path(config.data_dir) / f".benchmark_{os.getpid()}_{uuid.uuid4().hex[:8]}"
            await asyncio.to_thread(bench_path.write_text, "ok")
            await asyncio.to_thread(bench_path.unlink)
            results["fs_write_delete"] = round((time.time() - start) * 1000, 1)
        except Exception as e:
            results["fs_write_delete"] = f"error: {e}"
        start = time.time()
        try:
            # Use platform-appropriate shell for benchmark — wrapped in to_thread
            # to avoid blocking the asyncio event loop during subprocess execution.
            if platform.system() == "Windows":
                await asyncio.to_thread(
                    subprocess.run,
                    ["powershell", "-NoProfile", "-Command", "echo test"],
                    capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL
                )
            else:
                await asyncio.to_thread(
                    subprocess.run,
                    ["bash", "-c", "echo test"],
                    capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL
                )
            results["shell_exec"] = round((time.time() - start) * 1000, 1)
        except Exception as e:
            results["shell_exec"] = f"error: {e}"
        start = time.time()
        try:
            audit_log.record("_benchmark", {}, True, 0)
            results["audit_record"] = round((time.time() - start) * 1000, 1)
        except Exception as e:
            results["audit_record"] = f"error: {e}"
        return json.dumps(results, indent=2, ensure_ascii=False)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
    async def mcp_log(lines: int = 50, level: str = "INFO") -> str:
        # P1.2: clamp + lectura por cola (no read_text completo de hasta 10MB).
        try:
            lines = int(lines)
        except (TypeError, ValueError):
            lines = 50
        max_lines = getattr(config.log, "mcp_log_max_lines", 1000)
        max_bytes = getattr(config.log, "mcp_log_max_bytes", 2 * 1024 * 1024)
        lines = max(1, min(lines, max_lines))
        if not level:
            level = "INFO"
        log_path = Path(config.data_dir) / "server.log"
        exists = await asyncio.to_thread(log_path.exists)
        if not exists:
            return "No log file found"

        def _tail() -> str:
            level_prefix = level[0]
            try:
                size = log_path.stat().st_size
            except OSError:
                return "No log file found"
            with open(log_path, "rb") as f:
                if size > max_bytes:
                    f.seek(size - max_bytes)
                    # descartar primera línea parcial
                    f.readline()
                data = f.read()
            content = data.decode("utf-8", errors="replace")
            filtered = [l for l in content.splitlines() if f"[{level_prefix}" in l]
            return "\n".join(filtered[-lines:])

        return await asyncio.to_thread(_tail)