import json
import os
import platform
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from src.config import AppConfig
from src.audit import AuditLog


def _get_version(cmd: str, flag: str) -> str:
    try:
        if shutil.which(cmd) is None:
            return "not found"
        r = subprocess.run([cmd, flag],
                           stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE,
                           text=True, timeout=5)
        return (r.stdout or r.stderr).strip()[:100]
    except Exception:
        return "not found"


def _get_uptime() -> str:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime"],
            capture_output=True, text=True, timeout=5
        )
        return r.stdout.strip()
    except Exception:
        return "unavailable"


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
        try:
            mem = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "$os = Get-CimInstance Win32_OperatingSystem; Write-Output \"$($os.TotalVisibleMemorySize),$($os.FreePhysicalMemory)\""],
                capture_output=True, text=True, timeout=5
            )
            line = mem.stdout.strip()
            parts = line.split(",")
            if len(parts) >= 2:
                total_kb = int(parts[0].strip())
                free_kb = int(parts[1].strip())
                checks["memory"] = {
                    "total_gb": round(total_kb / (1024**2), 1),
                    "free_gb": round(free_kb / (1024**2), 1),
                    "free_pct": round((free_kb / total_kb) * 100, 1),
                }
        except Exception:
            checks["memory"] = "unavailable"
        checks["hostname"] = platform.node()
        checks["config_valid"] = True
        checks["uptime"] = _get_uptime()
        audit_stats = audit_log.stats()
        checks["audit"] = {
            "total_operations": audit_stats["total_entries"],
            "failed": audit_stats["failed"],
        }
        return json.dumps(checks, indent=2, ensure_ascii=False)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
    async def health_disk(paths: Optional[str] = None) -> str:
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
            # top va por env var, no interpolado en el string de PowerShell -
            # top: int en la firma deberia bastar (FastMCP/pydantic coerciona),
            # pero esto no depende de esa validacion para estar a salvo de
            # inyeccion si algun dia el tipo cambia o se relaja.
            env = os.environ.copy()
            env["_MCP_TOP"] = str(top)
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-Process | Sort-Object CPU -Descending | Select-Object -First $env:_MCP_TOP "
                 "Name, Id, @{N='CPU(s)';E={$_.CPU.ToString('F1')}}, "
                 "@{N='MemMB';E={($_.WorkingSet/1MB).ToString('F0')}} | Format-Table -AutoSize"],
                capture_output=True, text=True, timeout=10, env=env,
            )
            return r.stdout or r.stderr
        except Exception as e:
            return f"Error: {e}"

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
        diag["node"] = _get_version("node", "--version")
        diag["npm"] = _get_version("npm", "--version")
        diag["git"] = _get_version("git", "--version")
        diag["ssh"] = _get_version("ssh", "-V")
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
            (Path(config.data_dir) / ".benchmark").write_text("ok")
            (Path(config.data_dir) / ".benchmark").unlink()
            results["fs_write_delete"] = round((time.time() - start) * 1000, 1)
        except Exception as e:
            results["fs_write_delete"] = f"error: {e}"
        start = time.time()
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command", "echo test"],
                capture_output=True, text=True, timeout=10
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
        log_path = Path(config.data_dir) / "server.log"
        if not log_path.exists():
            return "No log file found"
        content = log_path.read_text(encoding="utf-8", errors="replace")
        level_prefix = level[0]
        filtered = [l for l in content.splitlines() if f"[{level_prefix}" in l]
        return "\n".join(filtered[-lines:])
