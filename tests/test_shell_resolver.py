import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.shell_resolver import (
    _find_executable,
    has_shell_operators,
    resolve_shell,
    tokenize_command,
)


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


# --- tokenize_command tests ---

def test_tokenize_simple():
    assert tokenize_command("git log --oneline") == ["git", "log", "--oneline"]


def test_tokenize_with_quotes():
    assert tokenize_command('echo "hello world"') == ["echo", "hello world"]


def test_tokenize_single_quotes():
    assert tokenize_command("echo 'hello world'") == ["echo", "hello world"]


def test_tokenize_mixed_quotes():
    assert tokenize_command('git -m "my message"') == ["git", "-m", "my message"]


def test_tokenize_path_with_spaces():
    assert tokenize_command('notepad "C:\\Program Files\\readme.txt"') == ["notepad", "C:\\Program Files\\readme.txt"]


def test_tokenize_empty():
    assert tokenize_command("") == []


def test_tokenize_whitespace():
    assert tokenize_command("   ") == []


def test_tokenize_multiple_spaces():
    assert tokenize_command("git   log    --oneline") == ["git", "log", "--oneline"]


# --- has_shell_operators tests ---

def test_no_operators():
    assert has_shell_operators("git log --oneline") is False


def test_pipe_operator():
    assert has_shell_operators("git log | grep foo") is True


def test_semicolon_operator():
    assert has_shell_operators("cd dir; ls") is True


def test_redirect_operator():
    assert has_shell_operators("echo hello > file.txt") is True


def test_and_operator():
    assert has_shell_operators("cd dir && ls") is True


def test_subshell_operator():
    assert has_shell_operators("echo $(pwd)") is True


def test_operators_inside_quotes_ignored():
    assert has_shell_operators('echo "hello | world"') is False


def test_operators_single_quotes_ignored():
    assert has_shell_operators("echo 'hello > world'") is False



