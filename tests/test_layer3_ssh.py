import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import AppConfig, CommandPolicy
from src.layers.layer3_ssh import SSHManager, ssh_exec_impl


class _FakeSession:
    """Stand-in for SSHSession that records the command it would have executed."""

    def __init__(self):
        self.last_command = None

    def is_idle_expired(self) -> bool:
        return False

    async def close(self) -> None:
        pass

    async def execute(self, command: str, timeout: int = 30) -> str:
        self.last_command = command
        return "ok"


def _manager_with_session():
    config = AppConfig()
    manager = SSHManager(config)
    fake = _FakeSession()
    manager._sessions["s1"] = fake
    return manager, fake


# --- A-4 (auditoría 2026-08-11): git config override over SSH ---


@pytest.mark.asyncio
async def test_ssh_exec_blocks_git_c_alias():
    manager, fake = _manager_with_session()
    result = await ssh_exec_impl("s1", "git -c alias.x='!whoami' x", manager)
    assert "Command blocked" in result
    assert "git -c" in result
    assert fake.last_command is None


@pytest.mark.asyncio
async def test_ssh_exec_blocks_git_c_any_config():
    manager, fake = _manager_with_session()
    result = await ssh_exec_impl("s1", "git -c user.email=x commit", manager)
    assert "Command blocked" in result
    assert fake.last_command is None


@pytest.mark.asyncio
async def test_ssh_exec_blocks_git_config_env():
    manager, fake = _manager_with_session()
    result = await ssh_exec_impl("s1", "git --config-env=foo=bar status", manager)
    assert "Command blocked" in result
    assert fake.last_command is None


@pytest.mark.asyncio
async def test_ssh_exec_blocks_git_config_equals():
    manager, fake = _manager_with_session()
    result = await ssh_exec_impl("s1", "git --config=alias.x='!rm' status", manager)
    assert "Command blocked" in result
    assert fake.last_command is None


@pytest.mark.asyncio
async def test_ssh_exec_allows_plain_git_status():
    manager, fake = _manager_with_session()
    result = await ssh_exec_impl("s1", "git status", manager)
    assert "WARNING" in result
    assert fake.last_command == "git status"


@pytest.mark.asyncio
async def test_ssh_exec_fails_closed_when_remote_whitelist_empty():
    # M-SSH1 (auditoría 2026-08-11): empty remote whitelist must fail closed,
    # not skip remote validation entirely.
    config = AppConfig()
    config.ssh.remote_allow_prefix = []
    manager = SSHManager(config)
    fake = _FakeSession()
    manager._sessions["s1"] = fake
    result = await ssh_exec_impl("s1", "ls", manager)
    assert "Command blocked" in result
    assert "whitelist" in result
    assert fake.last_command is None


def test_local_is_command_allowed_still_accepts_git_c():
    policy = CommandPolicy()
    allowed, _ = policy.is_command_allowed("git -c user.email=x commit")
    assert allowed is True


# --- M-SSH5 (auditoría 2026-08-11): idle TTL on SSH sessions ---

def test_ssh_session_idle_ttl():
    from src.layers.layer3_ssh import SSHSession

    s = SSHSession("sid", "host")
    assert s.is_idle_expired() is False
    s.last_activity = 0
    assert s.is_idle_expired() is True
