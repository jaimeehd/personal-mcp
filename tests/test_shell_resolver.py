import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.shell_resolver import ShellInfo, resolve_shell, _find_executable


def test_resolve_powershell_default():
    info = resolve_shell("powershell")
    assert info.name == "powershell"
    assert info.executable.lower().endswith("powershell.exe")
    assert "-NoProfile" in info.command_args
    assert "-Command" in info.command_args
    assert "-NoExit" in info.session_args
    assert "Set-Location" in info.workdir_prefix


def test_resolve_pwsh():
    try:
        info = resolve_shell("pwsh")
    except ValueError:
        pytest.skip("pwsh not installed on this system")
    assert info.name == "pwsh"
    assert "Set-Location" in info.workdir_prefix


def test_resolve_cmd():
    info = resolve_shell("cmd")
    assert info.name == "cmd"
    assert info.executable.lower().endswith("cmd.exe")
    assert info.session_args == []
    assert info.workdir_prefix.startswith("cd")


def test_resolve_unknown():
    with pytest.raises(ValueError, match="Unknown shell"):
        resolve_shell("nonexistent_shell")


def test_resolve_with_shell_map():
    info = resolve_shell("powershell", shell_map={"powershell": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"})
    assert info.executable.lower().endswith("powershell.exe")


def test_find_executable_powershell():
    path = _find_executable("powershell")
    assert path is not None
    assert path.lower().endswith("powershell.exe")


def test_find_executable_unknown():
    path = _find_executable("nonexistent_tool_xyz")
    assert path is None



