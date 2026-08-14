import asyncio
import json
import os
import shutil
import sys
import time
import uuid
from collections import deque
from pathlib import Path

import psutil
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from src.log import get_logger, memory_pressure_hint, sanitize_log_value
from src.oslayer.process import kill_process_tree, reap_after_kill, run_subprocess
from src.secretscanner import format_findings, scan_text
from src.security import CommandNotAllowedError, SecurityValidator
from src.shell_resolver import (
    ShellInfo,
    has_shell_operators,
    resolve_shell,
    tokenize_command,
)

logger = get_logger("layer2_shell")

MAX_CAPTURE_BYTES: int = 1_048_576

# _read_stream_capped() poll cadence: idle reads are bounded so the loop can
# notice a stop_event (process exited while a detached grandchild holds the
# pipe) instead of blocking on read() forever. Once stop_event is set, the
# grace is longer: EOF after a normal exit arrives immediately, so this only
# cuts off output when a detached child really is keeping the pipe open.
_READ_POLL_SECONDS: float = 0.5
_STOP_GRACE_SECONDS: float = 1.0


async def _wait_for_exit(process, poll_interval: float = 0.1) -> int | None:
    """Return the exit code once the process has actually exited.

    NOT a substitute for process.wait() in general -- it is a workaround for
    one specific asyncio behavior (2026-08-13, scenario-B hang): asyncio's
    subprocess transport only wakes up the awaiters of process.wait() once
    ALL of the process's pipes have hit EOF (_try_finish() then
    _call_connection_lost() in asyncio/base_subprocess.py). A detached
    grandchild that inherited the pipe write-ends (`Popen(close_fds=False)`,
    daemonized children) prevents EOF forever, so wait() stays pending even
    though the process itself died long ago. The process returncode, by
    contrast, is populated on death regardless of pipe state
    (_process_exited()), so polling it detects exit reliably in both cases.
    """
    while process.returncode is None:
        await asyncio.sleep(poll_interval)
    return process.returncode


def _truncate(output: str, max_bytes: int = MAX_CAPTURE_BYTES) -> tuple[str, bool]:
    encoded = output.encode("utf-8")
    if len(encoded) <= max_bytes:
        return output, False
    truncated = encoded[:max_bytes].decode("utf-8", errors="replace")
    return truncated, True


async def _read_stream_capped(stream, cap_bytes: int,
                              stop_event: asyncio.Event | None = None) -> tuple[bytes, bool]:
    """Read a stream to EOF but keep at most cap_bytes in memory (M-S5).

    M-S5 (auditoría 2026-08-11): `process.communicate()` buffered the FULL output
    before `_truncate()` ran, so a noisy command could grow memory without bound
    before the 1 MiB cap ever applied. Read in chunks and keep only the first
    cap_bytes; the rest is drained (so the child never blocks on a full pipe) but
    discarded. Returns (bytes, truncated).

    stop_event (2026-08-13, scenario-B fix): when set, EOF may never arrive --
    the main process exited but a detached grandchild (`cmd /c start /b ...`,
    daemonized children) still holds the pipe write-ends. The loop then gives
    the stream a short grace to reach a real EOF (normal case: the parent
    closes its pipes on exit, so EOF follows immediately and nothing is lost);
    if no data arrives during the grace, it cuts off and returns the partial
    output captured so far instead of waiting forever.
    """
    chunks: list[bytes] = []
    total = 0
    truncated = False
    while True:
        # Once the process has exited, EOF is expected immediately; only a
        # detached grandchild keeping the pipe open delays it. Poll with a
        # short grace in that state, otherwise with the regular poll timeout.
        if stop_event and stop_event.is_set():
            timeout = _STOP_GRACE_SECONDS
        else:
            timeout = _READ_POLL_SECONDS
        try:
            chunk = await asyncio.wait_for(stream.read(65536), timeout=timeout)
        except TimeoutError:
            if stop_event and stop_event.is_set():
                break
            continue
        if not chunk:
            break
        if total >= cap_bytes:
            truncated = True
            continue
        room = cap_bytes - total
        if len(chunk) > room:
            chunks.append(chunk[:room])
            total += room
            truncated = True
        else:
            chunks.append(chunk)
            total += len(chunk)
    return b"".join(chunks), truncated


def _append_secret_scan(result: str, output_text: str, security: SecurityValidator, source: str) -> str:
    if not security.config.security.secret_scanning_enabled or not output_text.strip():
        return result
    findings = scan_text(output_text)
    if findings:
        logger.warning("SECRET_SCAN findings=%d source=%s", len(findings), source)
        result += format_findings(findings)
    return result


def _escape_workdir(working_dir: str, shell_name: str) -> str:
    """Escape shell metacharacters inside working_dir for the shell that will
    interpolate it into workdir_prefix (Set-Location "{wd}"; / cd /d "{wd}" && /
    cd "{wd}" &&). Each shell has a different escape sequence for an embedded
    double-quote; using PowerShell's backtick-quote for all three let a `"` in
    working_dir break out of the quoted string on cmd.exe and bash (INJ-02 fix).

    But quotes are not the only metacharacter a shell expands inside double
    quotes: $() and backticks are command substitution (PowerShell/bash), and
    %VAR% is env expansion (cmd) -- a working_dir like `$(rm -rf /)` would be
    executed before the real command ever runs (C-3, auditoría 2026-08-11).
    Escape them per shell. The escape character itself is escaped FIRST, so the
    escapes we then add for the other metachars are not themselves re-escaped.
    """
    # Linux/macOS shells: bash, zsh, fish, sh all use backslash
    if shell_name in ("bash", "zsh", "fish", "sh"):
        return (
            working_dir.replace('\\', '\\\\')
            .replace('`', '\\`')
            .replace('$', '\\$')
            .replace('"', '\\"')
        )
    # Windows cmd.exe: caret is the escape char, % starts env-var expansion
    if shell_name == "cmd":
        return (
            working_dir.replace('^', '^^')
            .replace('%', '%%')
            .replace('"', '""')
        )
    # Windows PowerShell / pwsh: backtick is the escape char
    return (
        working_dir.replace('`', '``')
        .replace('$', '`$')
        .replace('"', '`"')
    )


class ShellSession:
    def __init__(self, session_id: str, timeout: int, shell_info: ShellInfo):
        self.session_id = session_id
        self.timeout = timeout
        self.shell_info = shell_info
        self.created_at = time.time()
        self.last_activity = time.time()
        self.command_count = 0
        self._process: asyncio.subprocess.Process | None = None
        self._output_buffer: asyncio.Queue = asyncio.Queue()
        self._reader_task: asyncio.Task | None = None
        # 2026-08-08 fix (found via external audit, no reported incident): guards
        # only the "drain stale output + write the new command to stdin" step,
        # NOT the read loop that follows. Two reasons: (1) _reader() queues
        # continuously and independently of which execute() call is "current" --
        # without draining first, leftover lines from a PREVIOUS command that
        # timed out while the shell kept producing output would be misattributed
        # to the NEXT command sent to this session; (2) the lock must NOT cover
        # the read loop, or interrupt() (meant to cut off a hung command) would
        # block behind execute()'s own up-to-`timeout`-second wait -- exactly the
        # case it exists to handle. This does not make truly concurrent execute()
        # calls on the same session fully safe (both could still read from the
        # same live queue once the loop starts) -- sessions are inherently a
        # serial conversation; this closes the two concrete failure modes above,
        # not a full command-boundary redesign that wasn't asked for.
        self._lock = asyncio.Lock()

    def _drain_stale_output(self) -> int:
        drained = 0
        while not self._output_buffer.empty():
            try:
                self._output_buffer.get_nowait()
                drained += 1
            except asyncio.QueueEmpty:
                break
        return drained

    @property
    def uptime_seconds(self) -> float:
        return time.time() - self.created_at

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.last_activity) > self.timeout

    async def start(self) -> None:
        self._process = await run_subprocess(
            [self.shell_info.executable, *self.shell_info.session_args],
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
            except TimeoutError:
                continue
            except asyncio.CancelledError:
                break

    async def execute(self, command: str, timeout: int = 30) -> str:
        if not self._process or not self._process.stdin:
            return "Session not started"
        self.command_count += 1
        self.last_activity = time.time()
        logger.debug("session_send id=%s command=%.100s", self.session_id, sanitize_log_value(command))
        async with self._lock:
            stale = self._drain_stale_output()
            if stale:
                logger.warning(
                    "session_send id=%s discarded %d stale queued line(s) left over from "
                    "a previous command that timed out while still producing output",
                    self.session_id, stale,
                )
            self._process.stdin.write(f"{command}\n".encode())
            await self._process.stdin.drain()
        lines: list[str] = []
        read_start = time.time()
        while (time.time() - read_start) < timeout:
            try:
                line = await asyncio.wait_for(self._output_buffer.get(), timeout=0.3)
                decoded = line.decode("utf-8", errors="replace").rstrip()
                if decoded:
                    lines.append(decoded)
            except TimeoutError:
                break
        return "\n".join(lines) if lines else "(no output)"

    async def read_output(self, timeout: float = 1.0) -> str:
        lines: list[str] = []
        try:
            while True:
                line = await asyncio.wait_for(self._output_buffer.get(), timeout=timeout)
                decoded = line.decode("utf-8", errors="replace").rstrip()
                if decoded:
                    lines.append(decoded)
                timeout = 0.3
        except TimeoutError:
            pass
        return "\n".join(lines) if lines else "(no output)"

    async def interrupt(self) -> str:
        if self._process:
            try:
                self._process.stdin.write(b"\x03")
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
            except TimeoutError:
                await kill_process_tree(self._process.pid)
                await reap_after_kill(self._process)


class ShellManager:
    def __init__(self, security: SecurityValidator, default_timeout: int = 600,
                 shell_info: ShellInfo | None = None,
                 shell_map: dict[str, str] | None = None):
        self.security = security
        self.default_timeout = default_timeout
        self.shell_info = shell_info or self._default_shell()
        self.shell_map = shell_map or {}
        self._sessions: dict[str, ShellSession] = {}

    def resolve_shell(self, name: str) -> ShellInfo:
        return resolve_shell(name, self.shell_map)

    @staticmethod
    def _default_shell() -> ShellInfo:
        if sys.platform == "win32":
            try:
                return resolve_shell("powershell")
            except ValueError:
                return ShellInfo(name="powershell", executable="powershell.exe",
                                 command_args=["-NoProfile", "-NonInteractive", "-Command"],
                                 session_args=["-NoExit", "-NonInteractive", "-Command", "-"],
                                 script_args=["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"],
                                 workdir_prefix='Set-Location -LiteralPath "{wd}"; ')
        try:
            return resolve_shell("bash")
        except ValueError:
            return ShellInfo(name="bash", executable="/bin/bash",
                             command_args=["-c"],
                             session_args=[],
                             script_args=[],
                             workdir_prefix='cd "{wd}"; ')

    async def create_session(self, timeout: int | None = None,
                             shell_info: ShellInfo | None = None) -> ShellSession | None:
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
                # M-S1 (auditoría 2026-08-11): popping the session left the shell
                # process and its reader task running forever (orphan). Schedule a
                # close() so the process is killed/reaped and the reader cancelled.
                try:
                    asyncio.create_task(sess.close())
                except RuntimeError:
                    pass  # no running loop (e.g. some tests) -- skip async close

    def get_session(self, session_id: str) -> ShellSession | None:
        session = self._sessions.get(session_id)
        if session and session.is_expired:
            self._sessions.pop(session_id, None)
            # M-S1: same orphan-leak fix as _cleanup_expired above.
            try:
                asyncio.create_task(session.close())
            except RuntimeError:
                pass
            return None
        return session

    def list_sessions(self) -> list[dict]:
        self._cleanup_expired()
        now = time.time()
        active: list[dict] = []
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


_SPAWN_RING_MAX_LINES = 500
SPAWN_REGISTRY_FILE = "spawned_processes.jsonl"


class SpawnedProcess:
    """A long-running background process started via sh_spawn.

    Distinct from ShellSession (interactive REPL, send-a-command/read-the-
    result repeatedly): this is start-once/poll-output-over-time/eventually-
    kill, the pattern needed for a dev server or a file watcher. Output is
    kept in a bounded ring buffer (deque maxlen) rather than an unbounded
    queue -- a noisy long-running process must not be able to grow memory
    without limit just from being read infrequently (security requirement
    #2 from the original design, AGENTS.md 'Feature diferida').
    """

    def __init__(self, spawn_id: str, command: str, process: asyncio.subprocess.Process):
        self.spawn_id = spawn_id
        self.command = command
        self.pid = process.pid
        self.created_at = time.time()
        self.status = "running"
        self._process = process
        self._ring: deque = deque(maxlen=_SPAWN_RING_MAX_LINES)
        self._reader_task: asyncio.Task | None = None

    async def _reader(self) -> None:
        try:
            while self._process.stdout and not self._process.stdout.at_eof():
                try:
                    line = await asyncio.wait_for(self._process.stdout.readline(), timeout=0.5)
                except TimeoutError:
                    continue
                if not line:
                    break
                self._ring.append(line.decode("utf-8", errors="replace").rstrip())
        except asyncio.CancelledError:
            pass
        finally:
            if self.status == "running":
                self.status = "exited"
                # 2026-08-08 fix (found via external audit): a process that exits
                # on its own (not via sh_spawn_kill) was never reaped -- only
                # sh_spawn_kill_impl called reap_after_kill(). Reusing that same
                # helper here (its implementation is just a generic tolerant
                # process.wait(); the "after kill" in its name doesn't make it
                # kill-specific) avoids a leaked handle for the common case of a
                # spawned process finishing normally on its own.
                await reap_after_kill(self._process)

    def read_recent(self, n: int = 100) -> list[str]:
        items = list(self._ring)
        return items[-n:] if n else items


class SpawnManager:
    """Tracks background processes started via sh_spawn.

    Persists {spawn_id, pid, owner_pid, command, working_dir, started_at,
    status} to spawned_processes.jsonl in data_dir on every spawn/kill --
    same append-then-reconcile-on-boot pattern as PermissionManager's
    tickets.jsonl (v1.4.41). Needed because on this machine it is normal,
    not exceptional, to have several personal-mcp server processes running
    concurrently (confirmed live 2026-08-02: 3 processes for 3 different
    Claude Desktop windows/profiles). A process spawned by one server has no
    way to be tracked by another unless this state survives on disk.

    owner_pid is the key design choice (2026-08-01/02, security requirement
    #1 from AGENTS.md 'Feature diferida'): reconciliation on startup only
    acts on a record whose owner_pid is confirmed DEAD. A record whose owner
    is still alive is left completely untouched, even though this new
    process can see the same file -- that record belongs to a sibling server
    that is still responsible for it. Checking only "is the child pid
    alive" (without the owner_pid distinction) would have no way to tell
    "still legitimately owned by a running sibling" apart from "genuinely
    orphaned", and would misreport every process owned by a sibling that is
    simply still running as if it needed attention.

    Orphans are reported (sh_spawn_list marks them "orphaned"), never
    auto-killed -- a spawned dev server surviving its own server's restart
    may still be exactly what the user wants running.
    """

    def __init__(self, security: SecurityValidator):
        self.security = security
        self._spawned: dict[str, SpawnedProcess] = {}
        self._owner_pid = os.getpid()
        self._orphans: list[dict] = []
        self._reconcile_on_startup()

    def _registry_path(self) -> Path:
        return Path(self.security.config.data_dir) / SPAWN_REGISTRY_FILE

    def _reconcile_on_startup(self) -> None:
        path = self._registry_path()
        if not path.exists():
            return
        latest: dict[str, dict] = {}
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                if item.get("spawn_id"):
                    latest[item["spawn_id"]] = item
        except OSError:
            return
        surviving = []
        for record in latest.values():
            if record.get("status") != "running":
                continue
            owner_pid = record.get("owner_pid")
            child_pid = record.get("pid")
            owner_alive = owner_pid is not None and psutil.pid_exists(owner_pid)
            if owner_alive:
                surviving.append(record)
                continue
            child_alive = child_pid is not None and psutil.pid_exists(child_pid)
            if child_alive:
                logger.warning(
                    "ORPHANED spawn=%s pid=%s command=%.80s owner_pid=%s no longer running "
                    "-- reporting via sh_spawn_list, NOT auto-killed",
                    record.get("spawn_id"), child_pid,
                    sanitize_log_value(record.get("command", "")), owner_pid,
                )
                record["orphaned_from"] = owner_pid
                self._orphans.append(record)
                surviving.append(record)
            # else: both owner and child are dead -- drop silently, nothing to track
        self._rewrite_registry(surviving)

    def _rewrite_registry(self, records: list[dict]) -> None:
        path = self._registry_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(json.dumps(r, ensure_ascii=False) + "\n" for r in records)

    def _append_record(self, record: dict) -> None:
        path = self._registry_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def register(self, spawned: SpawnedProcess, working_dir: str | None) -> None:
        self._spawned[spawned.spawn_id] = spawned
        self._append_record({
            "spawn_id": spawned.spawn_id, "pid": spawned.pid,
            "owner_pid": self._owner_pid, "command": spawned.command,
            "working_dir": working_dir, "started_at": spawned.created_at,
            "status": "running",
        })

    def mark_killed(self, spawn_id: str, pid: int, command: str) -> None:
        self._append_record({
            "spawn_id": spawn_id, "pid": pid, "owner_pid": self._owner_pid,
            "command": command, "started_at": None, "status": "killed",
        })

    def get(self, spawn_id: str) -> SpawnedProcess | None:
        return self._spawned.get(spawn_id)

    def get_orphan(self, spawn_id: str) -> dict | None:
        """Find an orphaned record by (possibly truncated) spawn_id.

        M-S4 (auditoría 2026-08-11): sh_spawn_list shows orphans with a truncated
        8-char id and tells the user "use sh_spawn_kill to stop it", but get()
        only searches the in-memory _spawned dict, so sh_spawn_kill could never
        find an orphan. Match by full id or prefix.
        """
        for o in self._orphans:
            sid = o.get("spawn_id") or ""
            if sid == spawn_id or sid.startswith(spawn_id):
                return o
        return None

    def list_all(self) -> list[dict]:
        items = []
        now = time.time()
        for sid, sp in self._spawned.items():
            items.append({
                "spawn_id": sid[:8], "pid": sp.pid, "command": sp.command[:100],
                "status": sp.status, "uptime_seconds": round(now - sp.created_at),
            })
        for o in self._orphans:
            items.append({
                "spawn_id": (o.get("spawn_id") or "")[:8], "pid": o.get("pid"),
                "command": (o.get("command") or "")[:100], "status": "orphaned",
                "note": f"owner pid {o.get('orphaned_from')} no longer running -- use sh_spawn_kill to stop it",
            })
        return items


def _check_spawn_permission(command: str, security: SecurityValidator) -> str | None:
    """Gate sh_spawn behind its own 'execute' ticket, keyed by the exact command
    string -- same operation type already used for python/node/bash via
    validate_shell_execution()/approval_required_prefix, reused directly
    rather than duplicated.

    operation='execute' is hardcoded in PermissionManager.check_granted() to
    never match a wildcard '*' grant (`operation not in ("delete", "execute")`
    in check_granted) -- this alone satisfies security requirement #3 from
    the original design (AGENTS.md 'Feature diferida'): a background process
    can never be started off a blanket wildcard grant, only an explicit
    ticket for this exact command. No new code was needed in security.py/
    permissions.py for this -- the exclusion already existed for the
    python/node/bash execute gate and applies here for free.
    """
    resource = f"spawn:{command}"
    if security.perm_manager and security.perm_manager.check_granted(resource, "execute"):
        return None
    return security.request_permission(resource, "execute")


async def sh_spawn_impl(command: str, security: SecurityValidator, manager: ShellManager,
                        spawn_manager: SpawnManager, working_dir: str | None = None,
                        shell_info: ShellInfo | None = None) -> str:
    logger.info("sh_spawn command=%.200s", sanitize_log_value(command))
    si = shell_info or manager.shell_info
    proc_kwargs = {
        "stdin": asyncio.subprocess.DEVNULL,
        "stdout": asyncio.subprocess.PIPE,
        "stderr": asyncio.subprocess.STDOUT,
    }
    if working_dir:
        proc_kwargs["cwd"] = working_dir
    process = await run_subprocess(
        [si.executable, *si.command_args, command], **proc_kwargs,
    )
    spawn_id = str(uuid.uuid4())
    spawned = SpawnedProcess(spawn_id, command, process)
    spawned._reader_task = asyncio.create_task(spawned._reader())
    spawn_manager.register(spawned, working_dir)
    return json.dumps({
        "spawn_id": spawn_id,
        "pid": process.pid,
        "message": f"Spawned {spawn_id[:8]}... (pid={process.pid}). "
                   f"Use sh_spawn_read to poll output, sh_spawn_kill to stop it.",
    })


async def sh_spawn_read_impl(spawn_id: str, spawn_manager: SpawnManager, n: int = 100) -> str:
    spawned = spawn_manager.get(spawn_id)
    if not spawned:
        return (f"Spawn not found: {spawn_id[:8]}... (may belong to a different "
                f"personal-mcp process -- check sh_spawn_list)")
    lines = spawned.read_recent(n)
    header = f"[status: {spawned.status}, pid={spawned.pid}]"
    body = "\n".join(lines) if lines else "(no output yet)"
    return f"{header}\n{body}"


async def sh_spawn_kill_impl(spawn_id: str, spawn_manager: SpawnManager) -> str:
    spawned = spawn_manager.get(spawn_id)
    if not spawned:
        # M-S4 (auditoría 2026-08-11): an orphaned spawn lives in _orphans, not
        # _spawned -- sh_spawn_list says "use sh_spawn_kill to stop it", so honor
        # that instead of answering "Spawn not found".
        orphan = spawn_manager.get_orphan(spawn_id)
        if orphan:
            pid = orphan.get("pid")
            if pid and psutil.pid_exists(pid):
                await kill_process_tree(pid)
                spawn_manager.mark_killed(orphan["spawn_id"], pid, orphan.get("command", ""))
                spawn_manager._orphans[:] = [
                    o for o in spawn_manager._orphans
                    if (o.get("spawn_id") or "") != orphan.get("spawn_id")
                ]
                return f"Killed orphaned spawn {spawn_id[:8]}... (pid={pid})"
            return f"Orphaned spawn {spawn_id[:8]}... (pid={pid}) is no longer running"
        return f"Spawn not found: {spawn_id[:8]}..."
    # M-S4: kill_process_tree() swallows NoSuchProcess, so "Killed" used to be
    # reported even for a process that had already exited. Report honestly.
    if not psutil.pid_exists(spawned.pid):
        spawned.status = "exited"
        spawn_manager._spawned.pop(spawn_id, None)
        return f"Spawn {spawn_id[:8]}... (pid={spawned.pid}) had already exited"
    await kill_process_tree(spawned.pid)
    await reap_after_kill(spawned._process)
    if spawned._reader_task:
        spawned._reader_task.cancel()
    spawned.status = "killed"
    spawn_manager.mark_killed(spawn_id, spawned.pid, spawned.command)
    spawn_manager._spawned.pop(spawn_id, None)
    return f"Killed spawn {spawn_id[:8]}... (pid={spawned.pid})"


async def sh_spawn_list_impl(spawn_manager: SpawnManager) -> str:
    items = spawn_manager.list_all()
    return json.dumps(items, indent=2) if items else "No spawned processes"


async def sh_exec_impl(command: str, security: SecurityValidator, timeout: int = 30,
                       working_dir: str | None = None,
                       shell_info: ShellInfo | None = None) -> str:
    security.validate_command(command)
    logger.info("sh_exec command=%.200s shell=%s timeout=%d", sanitize_log_value(command), shell_info.name if shell_info else "default", timeout)
    proc_kwargs = {
        "stdin": asyncio.subprocess.DEVNULL,
        "stdout": asyncio.subprocess.PIPE,
        "stderr": asyncio.subprocess.PIPE,
    }
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
                stop_event = asyncio.Event()

                async def _capture():
                    out_b, out_tr = await _read_stream_capped(
                        process.stdout, MAX_CAPTURE_BYTES, stop_event)
                    err_b, err_tr = await _read_stream_capped(
                        process.stderr, MAX_CAPTURE_BYTES, stop_event)
                    return out_b, err_b, out_tr, err_tr

                capture_task = asyncio.create_task(_capture())
                wait_task = asyncio.create_task(_wait_for_exit(process))
                try:
                    await asyncio.wait(
                        {capture_task, wait_task}, timeout=timeout,
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    if not wait_task.done() and not capture_task.done():
                        raise TimeoutError
                    if wait_task.done() and not capture_task.done():
                        # Process exited but a detached grandchild still holds
                        # the pipe write-ends (e.g. Popen(close_fds=False)):
                        # EOF will never arrive -- stop waiting for it and keep
                        # whatever _read_stream_capped captured in its grace.
                        stop_event.set()
                        await asyncio.wait({capture_task}, timeout=3.0)
                        if not capture_task.done():
                            capture_task.cancel()
                    elif not wait_task.done():
                        # Pipes closed (capture got EOF) while the process is
                        # still alive -- rare; bound the wait so we can't hang
                        # here either.
                        await asyncio.wait({wait_task}, timeout=5.0)
                        if not wait_task.done():
                            wait_task.cancel()
                            await asyncio.gather(wait_task, return_exceptions=True)
                    try:
                        stdout_b, stderr_b, out_trunc, err_trunc = capture_task.result()
                    except asyncio.CancelledError:
                        stdout_b, stderr_b, out_trunc, err_trunc = b"", b"", False, False
                    # M-S5 introduced _read_stream_capped() to read stdout/stderr
                    # to EOF without buffering unboundedly, replacing
                    # process.communicate() -- but EOF on the pipes is not the
                    # same as the process being reaped: asyncio only populates
                    # .returncode after the process exits. The returncode is
                    # read directly (see _wait_for_exit) -- using
                    # process.wait() here would hang whenever a detached
                    # grandchild keeps a pipe open (scenario B, 2026-08-13).
                    out = stdout_b.decode("utf-8", errors="replace")
                    err = stderr_b.decode("utf-8", errors="replace")
                    result = f"Exit code: {process.returncode}"
                    if out.strip():
                        result += f"\n[stdout]\n{out.rstrip()}"
                    if err.strip():
                        result += f"\n[stderr]\n{err.rstrip()}"
                    if out_trunc or err_trunc:
                        result += f"\n[output truncated at {MAX_CAPTURE_BYTES:,} bytes — use a more specific command to narrow results]"
                    result = _append_secret_scan(result, out + "\n" + err, security, "sh_exec")
                    return result
                except TimeoutError:
                    capture_task.cancel()
                    wait_task.cancel()
                    await asyncio.gather(capture_task, wait_task, return_exceptions=True)
                    await kill_process_tree(process.pid)
                    await reap_after_kill(process)
                    return f"Command timed out after {timeout}s{memory_pressure_hint()} — long-running process? use sh_spawn instead"

    # Fallback: shell execution
    si = shell_info or ShellManager._default_shell()
    cmd = command
    if working_dir:
        safe_wd = _escape_workdir(working_dir, si.name)
        cmd = si.workdir_prefix.replace("{wd}", safe_wd) + command
    process = await run_subprocess(
        [si.executable, *si.command_args, cmd], **proc_kwargs,
    )
    stop_event = asyncio.Event()

    async def _capture():
        out_b, out_tr = await _read_stream_capped(
            process.stdout, MAX_CAPTURE_BYTES, stop_event)
        err_b, err_tr = await _read_stream_capped(
            process.stderr, MAX_CAPTURE_BYTES, stop_event)
        return out_b, err_b, out_tr, err_tr

    capture_task = asyncio.create_task(_capture())
    wait_task = asyncio.create_task(_wait_for_exit(process))
    try:
        await asyncio.wait(
            {capture_task, wait_task}, timeout=timeout,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if not wait_task.done() and not capture_task.done():
            raise TimeoutError
        if wait_task.done() and not capture_task.done():
            # Same scenario-B case as the native-argv path: the shell exited
            # but a detached grandchild keeps the pipe open; stop waiting for
            # EOF and keep the partial output.
            stop_event.set()
            await asyncio.wait({capture_task}, timeout=3.0)
            if not capture_task.done():
                capture_task.cancel()
        elif not wait_task.done():
            # Pipes closed while the process is still alive -- rare; bound the
            # wait so we can't hang here either.
            await asyncio.wait({wait_task}, timeout=5.0)
            if not wait_task.done():
                wait_task.cancel()
                await asyncio.gather(wait_task, return_exceptions=True)
        try:
            stdout_b, stderr_b, out_trunc, err_trunc = capture_task.result()
        except asyncio.CancelledError:
            stdout_b, stderr_b, out_trunc, err_trunc = b"", b"", False, False
        # Same M-S5 gap as the native-argv path above: EOF on the pipes doesn't
        # populate process.returncode; it is read directly after the process
        # exits (see _wait_for_exit -- process.wait() would hang on scenario B).
        out = stdout_b.decode("utf-8", errors="replace")
        err = stderr_b.decode("utf-8", errors="replace")
        result = f"Exit code: {process.returncode}"
        if out.strip():
            result += f"\n[stdout]\n{out.rstrip()}"
        if err.strip():
            result += f"\n[stderr]\n{err.rstrip()}"
        if out_trunc or err_trunc:
            result += f"\n[output truncated at {MAX_CAPTURE_BYTES:,} bytes — use a more specific command to narrow results]"
        result = _append_secret_scan(result, out + "\n" + err, security, "sh_exec")
        return result
    except TimeoutError:
        capture_task.cancel()
        wait_task.cancel()
        await asyncio.gather(capture_task, wait_task, return_exceptions=True)
        await kill_process_tree(process.pid)
        await reap_after_kill(process)
        return f"Command timed out after {timeout}s{memory_pressure_hint()} — long-running process? use sh_spawn instead"


async def sh_session_start_impl(manager: ShellManager, timeout: int | None = None,
                                shell_info: ShellInfo | None = None) -> str:
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
                               security: SecurityValidator, timeout: int = 30,
                               working_dir: str | None = None) -> str:
    security.validate_command(command)
    session = manager.get_session(session_id)
    if not session:
        return f"Session not found or expired: {session_id[:8]}..."
    if working_dir:
        safe_wd = _escape_workdir(working_dir, session.shell_info.name)
        command = session.shell_info.workdir_prefix.replace("{wd}", safe_wd) + command
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
                         working_dir: str | None = None,
                         shell_info: ShellInfo | None = None) -> str:
    readonly_ok, readonly_reason = security.config.security.commands.is_script_readonly(script)
    if not readonly_ok:
        raise CommandNotAllowedError(
            f"sh_script only allows read-only commands, validated line by line: "
            f"{readonly_reason}. Use sh_exec for commands that modify state."
        )
    logger.info("sh_script script=%.100s shell=%s timeout=%d", sanitize_log_value(script), shell_info.name if shell_info else "default", timeout)
    si = shell_info or ShellManager._default_shell()
    full_script = script
    if working_dir:
        safe_wd = _escape_workdir(working_dir, si.name)
        full_script = si.workdir_prefix.replace("{wd}", safe_wd) + script
    ext = ".ps1" if "powershell" in si.name or "pwsh" == si.name else ".bat" if si.name == "cmd" else ".sh"
    temp_file = Path(security.config.data_dir) / f"script_{uuid.uuid4().hex[:8]}{ext}"
    await asyncio.to_thread(temp_file.parent.mkdir, parents=True, exist_ok=True)
    await asyncio.to_thread(temp_file.write_text, full_script, encoding="utf-8")
    try:
        process = await run_subprocess(
            [si.executable, *si.script_args, str(temp_file)],
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
    except TimeoutError:
        await kill_process_tree(process.pid)
        await reap_after_kill(process)
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
    for p in security.extract_traversal_paths(command):
        return f"Access denied: relative/home path '{p}' is not allowed in shell commands"
    for p in security.extract_absolute_paths(command):
        if not security.is_path_allowed(p):
            return f"Access denied: path '{p}' is not in allowed directories"
    return ""


def register_shell_tools(mcp: FastMCP, security: SecurityValidator,
                         manager: ShellManager, spawn_manager: SpawnManager) -> None:

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False))
    async def sh_exec(command: str, timeout: int = 30,
                      working_dir: str | None = None,
                      shell: str | None = None) -> str:
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
        return await sh_exec_impl(command, security, timeout, working_dir, si)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False))
    async def sh_session_start(timeout: int | None = None,
                                shell: str | None = None) -> str:
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
    async def sh_session_send(session_id: str, command: str, timeout: int = 30,
                              working_dir: str | None = None) -> str:
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
        return await sh_session_send_impl(session_id, command, manager, security, timeout, working_dir)

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
                        working_dir: str | None = None,
                        shell: str | None = None) -> str:
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
        return await sh_script_impl(script, security, timeout, working_dir, si)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True))
    async def sh_history() -> str:
        return await sh_history_impl(manager)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False))
    async def sh_spawn(command: str, working_dir: str | None = None,
                       shell: str | None = None) -> str:
        if working_dir:
            err = security.validate_tool_path(working_dir)
            if err:
                return err
        err = _validate_command_paths(command, security)
        if err:
            return err
        try:
            security.validate_command(command)
        except CommandNotAllowedError as e:
            return f"Command not allowed: {e}"
        err = _check_spawn_permission(command, security)
        if err:
            return err
        try:
            si = await asyncio.to_thread(manager.resolve_shell, shell) if shell else manager.shell_info
        except ValueError as e:
            return str(e)
        return await sh_spawn_impl(command, security, manager, spawn_manager, working_dir, si)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True))
    async def sh_spawn_read(spawn_id: str, n: int = 100) -> str:
        return await sh_spawn_read_impl(spawn_id, spawn_manager, n)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True))
    async def sh_spawn_kill(spawn_id: str) -> str:
        return await sh_spawn_kill_impl(spawn_id, spawn_manager)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True))
    async def sh_spawn_list() -> str:
        return await sh_spawn_list_impl(spawn_manager)
