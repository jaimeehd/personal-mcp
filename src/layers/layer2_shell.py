import asyncio
import json
import os
import shutil
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from src.security import SecurityValidator, CommandNotAllowedError
from src.shell_resolver import ShellInfo, resolve_shell, tokenize_command, has_shell_operators
from src.secretscanner import scan_text, format_findings
from src.log import get_logger, sanitize_log_value, memory_pressure_hint

logger = get_logger("layer2_shell")

MAX_CAPTURE_BYTES: int = 1_048_576


def _truncate(output: str, max_bytes: int = MAX_CAPTURE_BYTES) -> tuple[str, bool]:
    encoded = output.encode("utf-8")
    if len(encoded) <= max_bytes:
        return output, False
    truncated = encoded[:max_bytes].decode("utf-8", errors="replace")
    return truncated, True


def _append_secret_scan(result: str, output_text: str, security: SecurityValidator, source: str) -> str:
    if not security.config.security.secret_scanning_enabled or not output_text.strip():
        return result
    findings = scan_text(output_text)
    if findings:
        logger.warning("SECRET_SCAN findings=%d source=%s", len(findings), source)
        result += format_findings(findings)
    return result


async def _kill_process_tree(pid: int) -> None:
    logger.warning("kill_process_tree pid=%d", pid)
    try:
        proc = await asyncio.create_subprocess_exec(
            "taskkill", "/pid", str(pid), "/T", "/F",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            await asyncio.wait_for(proc.wait(), timeout=10)
        except asyncio.TimeoutError:
            logger.error("kill_process_tree pid=%d taskkill did not exit within 10s", pid)
    except Exception:
        pass


async def _reap_after_kill(process: asyncio.subprocess.Process) -> None:
    """After _kill_process_tree(), the original Process object still has a pending
    exit-wait registered with the event loop's subprocess watcher, and its stdout/
    stderr pipe transports are still open - nothing ever calls process.wait() on it,
    so asyncio never releases those handles (IOCP handles on Windows). Left
    unreaped across enough repeated timeouts, this leaks OS-level async I/O
    resources and can progressively degrade the event loop's ability to spawn or
    await NEW subprocesses - up to and including making unrelated commands hang.
    Best-effort: taskkill /F already ran, so this should return near-instantly;
    if it doesn't, we log and move on rather than hang the caller further.
    """
    try:
        await asyncio.wait_for(process.wait(), timeout=10)
    except asyncio.TimeoutError:
        logger.error("reap_after_kill pid=%d did not reap within 10s - possible handle leak", process.pid)
    except Exception:
        pass


def _scan_command_warnings(command: str, security: SecurityValidator) -> List[str]:
    warnings: List[str] = []
    for p in security.extract_absolute_paths(command):
        if not security.is_path_allowed(p):
            warnings.append(f"Command argument references external path: {p}")
    return warnings


def _escape_workdir(working_dir: str, shell_name: str) -> str:
    """Escape a double-quote inside working_dir for the shell that will interpolate it.

    workdir_prefix embeds working_dir inside a double-quoted string per shell
    (Set-Location -LiteralPath "{wd}"; / cd /d "{wd}" && / cd "{wd}" &&). Each shell
    has a different escape sequence for an embedded double-quote; using PowerShell's
    backtick-quote for all three let a `"` in working_dir break out of the quoted
    string on cmd.exe and bash (INJ-02 fix).
    """
    if shell_name == "cmd":
        return working_dir.replace('"', '""')
    if shell_name == "bash":
        return working_dir.replace('"', '\\"')
    return working_dir.replace('"', '`"')


class ShellSession:
    def __init__(self, session_id: str, timeout: int, shell_info: ShellInfo):
        self.session_id = session_id
        self.timeout = timeout
        self.shell_info = shell_info
        self.created_at = time.time()
        self.last_activity = time.time()
        self.command_count = 0
        self._process: Optional[asyncio.subprocess.Process] = None
        self._output_buffer: asyncio.Queue = asyncio.Queue()
        self._reader_task: Optional[asyncio.Task] = None

    @property
    def uptime_seconds(self) -> float:
        return time.time() - self.created_at

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.last_activity) > self.timeout

    async def start(self) -> None:
        self._process = await asyncio.create_subprocess_exec(
            self.shell_info.executable, *self.shell_info.session_args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        self._reader_task = asyncio.create_task(self._reader())

    async def _reader(self) -> None:
        while self._process and self._process.stdout and not self._process.stdout.at_eof():
            try:
                line = await asyncio.wait_for(
                    self._process.stdout.readline(), timeout=0.5
                )
                if line:
                    await self._output_buffer.put(line)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

    async def execute(self, command: str, timeout: int = 30) -> str:
        if not self._process or not self._process.stdin:
            return "Session not started"
        self.command_count += 1
        self.last_activity = time.time()
        logger.debug("session_send id=%s command=%.100s", self.session_id, sanitize_log_value(command))
        lines: List[str] = []
        self._process.stdin.write(f"{command}\n".encode("utf-8"))
        await self._process.stdin.drain()
        read_start = time.time()
        while (time.time() - read_start) < timeout:
            try:
                line = await asyncio.wait_for(self._output_buffer.get(), timeout=0.3)
                decoded = line.decode("utf-8", errors="replace").rstrip()
                if decoded:
                    lines.append(decoded)
            except asyncio.TimeoutError:
                break
        return "\n".join(lines) if lines else "(no output)"

    async def read_output(self, timeout: float = 1.0) -> str:
        lines: List[str] = []
        try:
            while True:
                line = await asyncio.wait_for(self._output_buffer.get(), timeout=timeout)
                decoded = line.decode("utf-8", errors="replace").rstrip()
                if decoded:
                    lines.append(decoded)
                timeout = 0.3
        except asyncio.TimeoutError:
            pass
        return "\n".join(lines) if lines else "(no output)"

    async def interrupt(self) -> str:
        if self._process:
            try:
                self._process.stdin.write("\x03".encode("utf-8"))
                await self._process.stdin.drain()
                return "Interrupt sent"
            except Exception as e:
                return f"Error sending interrupt: {e}"
        return "No active process"

    async def close(self) -> None:
        if self._reader_task:
            self._reader_task.cancel()
        if self._process:
            if self._process.stdin:
                self._process.stdin.close()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5)
            except asyncio.TimeoutError:
                await _kill_process_tree(self._process.pid)
                await _reap_after_kill(self._process)


class ShellManager:
    def __init__(self, security: SecurityValidator, default_timeout: int = 600,
                 shell_info: Optional[ShellInfo] = None,
                 shell_map: Optional[Dict[str, str]] = None):
        self.security = security
        self.default_timeout = default_timeout
        self.shell_info = shell_info or self._default_shell()
        self.shell_map = shell_map or {}
        self._sessions: Dict[str, ShellSession] = {}

    def resolve_shell(self, name: str) -> ShellInfo:
        return resolve_shell(name, self.shell_map)

    @staticmethod
    def _default_shell() -> ShellInfo:
        try:
            return resolve_shell("powershell")
        except ValueError:
            return ShellInfo(name="powershell", executable="powershell.exe",
                             command_args=["-NoProfile", "-Command"],
                             session_args=["-NoExit", "-Command", "-"],
                             script_args=["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"],
                             workdir_prefix='Set-Location -LiteralPath "{wd}"; ')

    async def create_session(self, timeout: Optional[int] = None,
                             shell_info: Optional[ShellInfo] = None) -> Optional[ShellSession]:
        si = shell_info or self.shell_info
        if not si.session_args:
            return None
        session_id = str(uuid.uuid4())
        session = ShellSession(session_id, timeout or self.default_timeout, si)
        await session.start()
        self._sessions[session_id] = session
        return session

    def _cleanup_expired(self) -> None:
        for sid, sess in list(self._sessions.items()):
            if sess.is_expired:
                self._sessions.pop(sid, None)

    def get_session(self, session_id: str) -> Optional[ShellSession]:
        session = self._sessions.get(session_id)
        if session and session.is_expired:
            self._sessions.pop(session_id, None)
            return None
        return session

    def list_sessions(self) -> List[dict]:
        self._cleanup_expired()
        now = time.time()
        active: List[dict] = []
        for sess in self._sessions.values():
            active.append({
                "session_id": sess.session_id,
                "uptime_seconds": round(now - sess.created_at),
                "command_count": sess.command_count,
            })
        return active

    async def close_session(self, session_id: str) -> bool:
        self._cleanup_expired()
        session = self._sessions.pop(session_id, None)
        if session:
            await session.close()
            return True
        return False

    def get_session_count(self) -> int:
        self._cleanup_expired()
        return len(self._sessions)


async def sh_exec_impl(command: str, security: SecurityValidator, timeout: int = 30,
                       working_dir: Optional[str] = None,
                       shell_info: Optional[ShellInfo] = None) -> str:
    security.validate_command(command)
    logger.info("sh_exec command=%.200s shell=%s timeout=%d", sanitize_log_value(command), shell_info.name if shell_info else "default", timeout)
    proc_kwargs = dict(
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    if working_dir:
        proc_kwargs["cwd"] = working_dir

    # Try native argv execution when no shell operators are present
    if not has_shell_operators(command):
        tokens = tokenize_command(command)
        if tokens:
            native = shutil.which(tokens[0])
            if native and os.path.isfile(native):
                process = await asyncio.create_subprocess_exec(
                    native, *tokens[1:], **proc_kwargs,
                )
                try:
                    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
                    out = stdout.decode("utf-8", errors="replace")
                    err = stderr.decode("utf-8", errors="replace")
                    out, out_trunc = _truncate(out)
                    err, err_trunc = _truncate(err)
                    result = f"Exit code: {process.returncode}"
                    if out.strip():
                        result += f"\n[stdout]\n{out.rstrip()}"
                    if err.strip():
                        result += f"\n[stderr]\n{err.rstrip()}"
                    if out_trunc or err_trunc:
                        result += f"\n[output truncated at {MAX_CAPTURE_BYTES:,} bytes — use a more specific command to narrow results]"
                    result = _append_secret_scan(result, out + "\n" + err, security, "sh_exec")
                    return result
                except asyncio.TimeoutError:
                    await _kill_process_tree(process.pid)
                    await _reap_after_kill(process)
                    return f"Command timed out after {timeout}s{memory_pressure_hint()}"

    # Fallback: shell execution
    si = shell_info or ShellInfo(name="powershell", executable="powershell.exe",
                                  command_args=["-NoProfile", "-Command"],
                                  session_args=[], script_args=[],
                                  workdir_prefix='Set-Location -LiteralPath "{wd}"; ')
    cmd = command
    if working_dir:
        safe_wd = _escape_workdir(working_dir, si.name)
        cmd = si.workdir_prefix.replace("{wd}", safe_wd) + command
    process = await asyncio.create_subprocess_exec(
        si.executable, *si.command_args, cmd, **proc_kwargs,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        out = stdout.decode("utf-8", errors="replace")
        err = stderr.decode("utf-8", errors="replace")
        out, out_trunc = _truncate(out)
        err, err_trunc = _truncate(err)
        result = f"Exit code: {process.returncode}"
        if out.strip():
            result += f"\n[stdout]\n{out.rstrip()}"
        if err.strip():
            result += f"\n[stderr]\n{err.rstrip()}"
        if out_trunc or err_trunc:
            result += f"\n[output truncated at {MAX_CAPTURE_BYTES:,} bytes — use a more specific command to narrow results]"
        result = _append_secret_scan(result, out + "\n" + err, security, "sh_exec")
        return result
    except asyncio.TimeoutError:
        await _kill_process_tree(process.pid)
        await _reap_after_kill(process)
        return f"Command timed out after {timeout}s{memory_pressure_hint()}"


async def sh_session_start_impl(manager: ShellManager, timeout: Optional[int] = None,
                                shell_info: Optional[ShellInfo] = None) -> str:
    session = await manager.create_session(timeout=timeout, shell_info=shell_info)
    if session is None:
        name = shell_info.name if shell_info else (manager.shell_info.name if manager.shell_info else 'unknown')
        return json.dumps({
            "error": f"Shell '{name}' does not support interactive sessions. Use sh_exec instead.",
        })
    return json.dumps({
        "session_id": session.session_id,
        "message": f"Session {session.session_id[:8]}... started",
        "timeout_seconds": manager.default_timeout,
    })


async def sh_session_list_impl(manager: ShellManager) -> str:
    sessions = manager.list_sessions()
    if not sessions:
        return "No active sessions"
    return json.dumps(sessions, indent=2)


async def sh_session_send_impl(session_id: str, command: str, manager: ShellManager,
                               security: SecurityValidator, timeout: int = 30) -> str:
    security.validate_command(command)
    session = manager.get_session(session_id)
    if not session:
        return f"Session not found or expired: {session_id[:8]}..."
    return await session.execute(command, timeout=timeout)


async def sh_session_read_impl(session_id: str, manager: ShellManager, timeout: float = 1.0) -> str:
    session = manager.get_session(session_id)
    if not session:
        return f"Session not found or expired: {session_id[:8]}..."
    return await session.read_output(timeout=timeout)


async def sh_session_interrupt_impl(session_id: str, manager: ShellManager) -> str:
    session = manager.get_session(session_id)
    if not session:
        return f"Session not found or expired: {session_id[:8]}..."
    return await session.interrupt()


async def sh_session_close_impl(session_id: str, manager: ShellManager) -> str:
    success = await manager.close_session(session_id)
    return f"Session {session_id[:8]}... closed" if success else "Session not found"


async def sh_script_impl(script: str, security: SecurityValidator, timeout: int = 60,
                         working_dir: Optional[str] = None,
                         shell_info: Optional[ShellInfo] = None) -> str:
    readonly_ok, readonly_reason = security.config.security.commands.is_script_readonly(script)
    if not readonly_ok:
        raise CommandNotAllowedError(
            f"sh_script only allows read-only commands, validated line by line: "
            f"{readonly_reason}. Use sh_exec for commands that modify state."
        )
    logger.info("sh_script script=%.100s shell=%s timeout=%d", sanitize_log_value(script), shell_info.name if shell_info else "default", timeout)
    si = shell_info or ShellInfo(name="powershell", executable="powershell.exe",
                                  command_args=[], session_args=[],
                                  script_args=["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"],
                                  workdir_prefix='Set-Location -LiteralPath "{wd}"; ')
    full_script = script
    if working_dir:
        safe_wd = _escape_workdir(working_dir, si.name)
        full_script = si.workdir_prefix.replace("{wd}", safe_wd) + script
    ext = ".ps1" if "powershell" in si.name or "pwsh" == si.name else ".bat" if si.name == "cmd" else ".sh"
    temp_file = Path(security.config.data_dir) / f"script_{uuid.uuid4().hex[:8]}{ext}"
    await asyncio.to_thread(temp_file.parent.mkdir, parents=True, exist_ok=True)
    await asyncio.to_thread(temp_file.write_text, full_script, encoding="utf-8")
    try:
        process = await asyncio.create_subprocess_exec(
            si.executable, *si.script_args, str(temp_file),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        out = stdout.decode("utf-8", errors="replace")
        err = stderr.decode("utf-8", errors="replace")
        out, out_trunc = _truncate(out)
        err, err_trunc = _truncate(err)
        result = f"Exit code: {process.returncode}"
        if out.strip():
            result += f"\n[stdout]\n{out.rstrip()}"
        if err.strip():
            result += f"\n[stderr]\n{err.rstrip()}"
        if out_trunc or err_trunc:
            result += f"\n[output truncated at {MAX_CAPTURE_BYTES:,} bytes — use a more specific command to narrow results]"
        result = _append_secret_scan(result, out + "\n" + err, security, "sh_script")
        return result
    except asyncio.TimeoutError:
        await _kill_process_tree(process.pid)
        await _reap_after_kill(process)
        return f"Script timed out after {timeout}s{memory_pressure_hint()}"
    finally:
        exists = await asyncio.to_thread(temp_file.exists)
        if exists:
            await asyncio.to_thread(temp_file.unlink)


async def sh_history_impl(manager: ShellManager) -> str:
    data = []
    for sid, sess in manager._sessions.items():
        data.append({
            "session_id": sid[:8],
            "commands": sess.command_count,
            "uptime": round(sess.uptime_seconds),
        })
    return json.dumps(data, indent=2) if data else "No history"


def _validate_command_paths(command: str, security: SecurityValidator) -> str:
    for p in security.extract_absolute_paths(command):
        if not security.is_path_allowed(p):
            return f"Access denied: path '{p}' is not in allowed directories"
    return ""


def _format_warnings(warnings: List[str]) -> str:
    if not warnings:
        return ""
    return "\n".join(f"[warning] {w}" for w in warnings) + "\n---"


def register_shell_tools(mcp: FastMCP, security: SecurityValidator,
                         manager: ShellManager) -> None:

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False))
    async def sh_exec(command: str, timeout: int = 30,
                      working_dir: Optional[str] = None,
                      shell: Optional[str] = None) -> str:
        if working_dir:
            err = security.validate_tool_path(working_dir)
            if err:
                return err
        err = _validate_command_paths(command, security)
        if err:
            return err
        err = security.validate_shell_execution(command)
        if err:
            return err
        try:
            si = await asyncio.to_thread(manager.resolve_shell, shell) if shell else manager.shell_info
        except ValueError as e:
            return str(e)
        warnings = _scan_command_warnings(command, security)
        result = await sh_exec_impl(command, security, timeout, working_dir, si)
        wtext = _format_warnings(warnings)
        if wtext:
            result = wtext + "\n" + result
        return result

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False))
    async def sh_session_start(timeout: Optional[int] = None,
                                shell: Optional[str] = None) -> str:
        if shell:
            try:
                si = await asyncio.to_thread(manager.resolve_shell, shell)
            except ValueError as e:
                return str(e)
        else:
            si = None
        return await sh_session_start_impl(manager, timeout, si)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True))
    async def sh_session_list() -> str:
        return await sh_session_list_impl(manager)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False))
    async def sh_session_send(session_id: str, command: str, timeout: int = 30) -> str:
        err = _validate_command_paths(command, security)
        if err:
            return err
        err = security.validate_shell_execution(command)
        if err:
            return err
        warnings = _scan_command_warnings(command, security)
        result = await sh_session_send_impl(session_id, command, manager, security, timeout)
        wtext = _format_warnings(warnings)
        if wtext:
            result = wtext + "\n" + result
        return result

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True))
    async def sh_session_read(session_id: str, timeout: float = 1.0) -> str:
        return await sh_session_read_impl(session_id, manager, timeout)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False))
    async def sh_session_interrupt(session_id: str) -> str:
        return await sh_session_interrupt_impl(session_id, manager)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True))
    async def sh_session_close(session_id: str) -> str:
        return await sh_session_close_impl(session_id, manager)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False))
    async def sh_script(script: str, timeout: int = 60,
                        working_dir: Optional[str] = None,
                        shell: Optional[str] = None) -> str:
        if working_dir:
            err = security.validate_tool_path(working_dir)
            if err:
                return err
        err = _validate_command_paths(script, security)
        if err:
            return err
        try:
            si = await asyncio.to_thread(manager.resolve_shell, shell) if shell else manager.shell_info
        except ValueError as e:
            return str(e)
        warnings = _scan_command_warnings(script, security)
        result = await sh_script_impl(script, security, timeout, working_dir, si)
        wtext = _format_warnings(warnings)
        if wtext:
            result = wtext + "\n" + result
        return result

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True))
    async def sh_history() -> str:
        return await sh_history_impl(manager)
