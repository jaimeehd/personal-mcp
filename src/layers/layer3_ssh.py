import asyncio
import json
import time
import uuid
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from src.config import AppConfig


class SSHSession:
    # M-SSH5 (auditoría 2026-08-11): sessions previously had no idle TTL -- an
    # abandoned session stayed open indefinitely. Idle beyond this (seconds) is
    # treated as dead and the session is torn down on the next ssh_exec.
    IDLE_TTL_SECONDS = 3600

    def __init__(self, session_id: str, host: str):
        self.session_id = session_id
        self.host = host
        self._process: asyncio.subprocess.Process | None = None
        self.created_at = time.time()
        self.last_activity = time.time()

    async def connect(self) -> str:
        self._process = await asyncio.create_subprocess_exec(
            "ssh", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new",
            self.host,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        return f"Connected to {self.host}"

    MAX_LINES = 10_000

    def is_idle_expired(self) -> bool:
        return (time.time() - self.last_activity) > self.IDLE_TTL_SECONDS

    async def execute(self, command: str, timeout: int = 30) -> str:
        if not self._process or not self._process.stdin:
            return "Not connected"
        self.last_activity = time.time()
        try:
            self._process.stdin.write(f"{command}\n".encode())
            await self._process.stdin.drain()
        except (BrokenPipeError, ConnectionError, OSError):
            # M-SSH4 (auditoría 2026-08-11): a dropped SSH connection surfaced as
            # a raw exception; report it as a clean "connection lost" instead.
            return "Error: SSH connection lost"
        lines = []
        try:
            while len(lines) < self.MAX_LINES:
                line = await asyncio.wait_for(
                    self._process.stdout.readline(), timeout=timeout
                )
                if not line:
                    break
                lines.append(line.decode("utf-8", errors="replace").rstrip())
        except TimeoutError:
            pass
        except (BrokenPipeError, ConnectionError, OSError):
            return "Error: SSH connection lost while reading output"
        return "\n".join(lines) if lines else "(no output)"

    async def close(self) -> None:
        if self._process:
            if self._process.stdin:
                try:
                    self._process.stdin.write(b"exit\n")
                    await self._process.stdin.drain()
                except OSError:
                    pass
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5)
            except TimeoutError:
                self._process.kill()


class SSHManager:
    def __init__(self, config: AppConfig):
        self.config = config
        self._sessions: dict[str, SSHSession] = {}

    def is_available(self) -> bool:
        if not self.config.ssh.enabled:
            return False
        ssh_config = Path.home() / ".ssh" / "config"
        return ssh_config.exists()

    def list_hosts(self) -> list:
        ssh_config = Path.home() / ".ssh" / "config"
        if not ssh_config.exists():
            return []
        hosts = []
        with open(ssh_config) as f:
            for line in f:
                line = line.strip()
                if line.lower().startswith("host ") and not line.lower().startswith("host *"):
                    hosts.append(line.split(None, 1)[1])
        return hosts


def ssh_list_hosts_impl(manager: SSHManager) -> str:
    hosts = manager.list_hosts()
    if not hosts:
        return "No SSH hosts configured in ~/.ssh/config"
    return "\n".join(f"  {h}" for h in hosts)


async def ssh_connect_impl(host: str, manager: SSHManager) -> str:
    session_id = str(uuid.uuid4())
    session = SSHSession(session_id, host)
    result = await session.connect()
    manager._sessions[session_id] = session
    return json.dumps({"session_id": session_id, "result": result})


async def ssh_exec_impl(session_id: str, command: str, manager: SSHManager, timeout: int = 30) -> str:
    session = manager._sessions.get(session_id)
    if not session:
        return "Session not found"
    # M-SSH5 (auditoría 2026-08-11): tear down sessions idle beyond their TTL.
    if session.is_idle_expired():
        await session.close()
        manager._sessions.pop(session_id, None)
        return "Session expired (idle too long); reconnect with ssh_connect"
    allowed, reason = manager.config.security.commands.is_command_allowed(command)
    if not allowed:
        return f"Command blocked: {reason}"

    # Enforce remote_allow_prefix for SSH commands
    remote_allowed_prefixes = manager.config.ssh.remote_allow_prefix
    # M-SSH1 (auditoría 2026-08-11): an empty remote whitelist used to skip this
    # validation entirely (fail-open) -- every command that passed the LOCAL
    # whitelist was forwarded to the remote host. Fail closed instead: no remote
    # whitelist means no remote commands.
    if not remote_allowed_prefixes:
        return (
            "Command blocked: SSH remote command whitelist (ssh.remote_allow_prefix) "
            "is empty — no remote commands are allowed. Add prefixes to the config "
            "to enable remote execution."
        )
    from src.shell_resolver import split_command_segments
    segments = split_command_segments(command) or [command]
    for seg in segments:
        words = seg.strip().split()
        if not words:
            continue
        first_word = words[0].lower()
        if not any(first_word == p.lower() for p in remote_allowed_prefixes):
            return f"Command blocked: Remote command '{first_word}' is not in SSH remote_allow_prefix whitelist"
        # A-4 (auditoría 2026-08-11): 'git -c'/'--config'/'--config-env' permite
        # sobreescribir la config de git (alias.x='!cmd', core.fsmonitor,
        # credential.helper, etc.) para ejecutar comandos arbitrarios en el
        # remoto, evadiendo remote_allow_prefix pese a que 'git' está permitido.
        # Bloqueo acotado a esta función a propósito -- 'git -c' LOCAL sigue
        # permitido sin cambios; is_command_allowed() no se toca.
        if first_word == "git" and any(
            w == "-c" or w.startswith(("--config-env", "--config="))
            for w in words[1:]
        ):
            return (
                "Command blocked: 'git -c'/'--config'/'--config-env' is not "
                "allowed over SSH (can override git config to execute arbitrary "
                "commands via alias.*='!cmd', core.fsmonitor, etc.)"
            )

    result = await session.execute(command, timeout=timeout)
    return (
        "[WARNING] This command passed local and remote allowlist validation, but the remote "
        "host executes with its target user privileges. Treat remote hosts as trusted targets.\n"
        + result
    )



async def ssh_disconnect_impl(session_id: str, manager: SSHManager) -> str:
    session = manager._sessions.pop(session_id, None)
    if session:
        await session.close()
        return f"Disconnected from {session.host}"
    return "Session not found"


def register_ssh_tools(mcp: FastMCP, config: AppConfig, manager: SSHManager) -> None:
    if not manager.is_available():
        return

    @mcp.tool()
    async def ssh_list_hosts() -> str:
        return ssh_list_hosts_impl(manager)

    @mcp.tool()
    async def ssh_connect(host: str) -> str:
        return await ssh_connect_impl(host, manager)

    @mcp.tool()
    async def ssh_exec(session_id: str, command: str, timeout: int = 30) -> str:
        return await ssh_exec_impl(session_id, command, manager, timeout)

    @mcp.tool()
    async def ssh_disconnect(session_id: str) -> str:
        return await ssh_disconnect_impl(session_id, manager)
