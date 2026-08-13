import sys
from pathlib import Path

import pytest

# Ensure src is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import AppConfig, JournalConfig, SecurityConfig, ShellConfig, SSHConfig
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
def linux_test_config(temp_home):
    """Create a test config with Linux-style paths."""
    config = AppConfig(
        security=SecurityConfig(
            paths_allow=[str(temp_home / "Repos"), str(temp_home / ".personal-mcp")],
            paths_deny=["**/node_modules/**", "**/.git/**"],
        ),
        shell=ShellConfig(enabled=True, session_timeout_seconds=60, default_shell="bash"),
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
def linux_security(linux_test_config):
    return SecurityValidator(linux_test_config)


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


# Platform-aware fixtures
@pytest.fixture
def default_shell_name():
    """Return the default shell for the current platform."""
    import sys
    if sys.platform == "win32":
        return "powershell"
    return "bash"


@pytest.fixture
def available_shells():
    """Return list of available shells on current platform."""
    import shutil
    import sys
    shells = []
    for shell in ["bash", "zsh", "fish", "sh", "powershell", "pwsh", "cmd"]:
        if shell in ("powershell", "pwsh", "cmd") and sys.platform != "win32":
            continue
        if shell in ("bash", "zsh", "fish", "sh") and sys.platform == "win32":
            # On Windows, only bash (via Git Bash) is likely available
            if shell != "bash":
                continue
        if shutil.which(shell) or (shell == "bash" and sys.platform == "win32"):
            shells.append(shell)
    return shells


@pytest.fixture
def skip_on_linux():
    """Decorator to skip test on Linux."""
    import sys
    if sys.platform.startswith("linux"):
        pytest.skip("Test not applicable on Linux")


@pytest.fixture
def skip_on_windows():
    """Decorator to skip test on Windows."""
    import sys
    if sys.platform == "win32":
        pytest.skip("Test not applicable on Windows")


@pytest.fixture
def skip_on_macos():
    """Decorator to skip test on macOS."""
    import sys
    if sys.platform == "darwin":
        pytest.skip("Test not applicable on macOS")