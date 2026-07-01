import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import AppConfig, SecurityConfig, ShellConfig, CommandPolicy


def test_default_config_creation(temp_home):
    config = AppConfig()
    assert config.shell.enabled is True
    assert config.ssh.enabled is False
    assert config.journal.enabled is True
    assert config.audit_max_entries == 10000


def test_config_save_load(temp_home):
    path = temp_home / ".personal-mcp" / "config.json"
    original = AppConfig(
        shell=ShellConfig(enabled=True, session_timeout_seconds=999),
    )
    original.save(path)

    loaded = AppConfig.load(path)
    assert loaded.shell.session_timeout_seconds == 999
    assert loaded.ssh.enabled is False


def test_config_custom_paths(temp_home):
    config = AppConfig(
        security=SecurityConfig(
            paths_allow=["C:\\Custom\\Path"],
        ),
    )
    assert "C:\\Custom\\Path" in config.security.paths_allow


def test_command_policy_defaults():
    policy = CommandPolicy()
    allowed, _ = policy.is_command_allowed("git push")
    assert allowed is True

    allowed, _ = policy.is_command_allowed("npm test")
    assert allowed is True


def test_command_deny_list():
    policy = CommandPolicy()
    allowed, reason = policy.is_command_allowed("shutdown /s /t 0")
    assert allowed is False
    assert "shutdown" in reason


def test_missing_config_creates_default(temp_home):
    path = temp_home / "nonexistent" / "config.json"
    config = AppConfig.load(path)
    assert path.exists()
    assert config.shell.enabled is True
