import json
import sys
import tempfile
from pathlib import Path

import pytest

# Ensure src is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import AppConfig, SecurityConfig, ShellConfig, SSHConfig, JournalConfig
from src.security import SecurityValidator


@pytest.fixture
def temp_home(tmp_path):
    """Create a temporary home directory structure for testing."""
    repos = tmp_path / "Repos"
    repos.mkdir()
    desktop = tmp_path / "Desktop"
    desktop.mkdir()
    personal_mcp = tmp_path / ".personal-mcp"
    personal_mcp.mkdir()
    (personal_mcp / "data").mkdir()
    return tmp_path


@pytest.fixture
def test_config(temp_home):
    """Create a test config pointing to temp paths."""
    config = AppConfig(
        security=SecurityConfig(
            paths_allow=[
                str(temp_home / "Repos"),
                str(temp_home / "Desktop"),
                str(temp_home / ".personal-mcp"),
            ],
            paths_deny=["**\\node_modules\\**", "**\\.git\\**"],
        ),
        shell=ShellConfig(enabled=True, session_timeout_seconds=60),
        ssh=SSHConfig(enabled=False),
        journal=JournalConfig(
            enabled=True,
            path=str(temp_home / ".personal-mcp" / "data" / "journal"),
        ),
        data_dir=str(temp_home / ".personal-mcp" / "data"),
        audit_max_entries=1000,
        config_path=str(temp_home / ".personal-mcp" / "config.json"),
    )
    return config


@pytest.fixture
def security(test_config):
    return SecurityValidator(test_config)


@pytest.fixture
def sample_file(temp_home):
    """Create a sample file in the test Repos directory."""
    file_path = temp_home / "Repos" / "test_file.txt"
    file_path.write_text("Hello, World!\nThis is a test.\n")
    return file_path


@pytest.fixture
def sample_dir(temp_home):
    """Create a sample directory structure."""
    base = temp_home / "Repos" / "sample_project"
    base.mkdir()
    (base / "src").mkdir()
    (base / "src" / "main.py").write_text("print('hello')")
    (base / "src" / "utils.py").write_text("def util():\n    pass")
    (base / "README.md").write_text("# Sample")
    (base / "app.py").write_text("def main():\n    pass")
    (base / ".git").mkdir()
    return base
