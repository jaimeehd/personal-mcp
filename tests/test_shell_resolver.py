import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.shell_resolver import (
    _find_executable,
    has_shell_operators,
    has_unsafe_substitution,
    resolve_shell,
    shell_subprocess_env,
    tokenize_command,
)


@pytest.mark.usefixtures("skip_on_linux")
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


@pytest.mark.usefixtures("skip_on_linux")
def test_resolve_cmd():
    info = resolve_shell("cmd")
    assert info.name == "cmd"
    assert info.executable.lower().endswith("cmd.exe")
    assert info.session_args == []
    assert info.workdir_prefix.startswith("cd")


def test_resolve_unknown():
    with pytest.raises(ValueError, match="Unknown shell"):
        resolve_shell("nonexistent_shell")


@pytest.mark.usefixtures("skip_on_linux")
def test_resolve_with_shell_map():
    info = resolve_shell("powershell", shell_map={"powershell": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"})
    assert info.executable.lower().endswith("powershell.exe")


@pytest.mark.usefixtures("skip_on_linux")
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


# --- shell_subprocess_env() (2026-08-08 fix) ---
# Root cause of the PowerShell/git resolution bug tracked in
# this server's own process can inherit
# an environment where PATHEXT is missing or lacks .EXE (observed live on
# this machine: PATHEXT ends up as just ".CPL"). Without .EXE in that list,
# PowerShell's own command resolution (Get-Command) cannot recognize an
# external .exe as runnable by bare name -- even though the file exists and
# its directory is genuinely in PATH. shutil.which() does not depend on
# PATHEXT the same way, which is why the native-argv path in sh_exec_impl
# never showed this bug -- only the shell-fallback/session/script/spawn
# paths that actually invoke powershell.exe -Command do.

@pytest.mark.usefixtures("skip_on_linux")
def test_shell_subprocess_env_fixes_missing_pathext(monkeypatch):
    monkeypatch.delenv("PATHEXT", raising=False)
    env = shell_subprocess_env()
    assert env is not None
    assert ".EXE" in env["PATHEXT"].upper()


@pytest.mark.usefixtures("skip_on_linux")
def test_shell_subprocess_env_fixes_broken_pathext(monkeypatch):
    # The exact broken value observed live on this machine.
    monkeypatch.setenv("PATHEXT", ".CPL")
    env = shell_subprocess_env()
    assert env is not None
    assert ".EXE" in env["PATHEXT"].upper()


@pytest.mark.usefixtures("skip_on_linux")
def test_shell_subprocess_env_leaves_valid_pathext_untouched(monkeypatch):
    monkeypatch.setenv("PATHEXT", ".COM;.EXE;.BAT;.CUSTOM")
    env = shell_subprocess_env()
    assert env is not None
    assert env["PATHEXT"] == ".COM;.EXE;.BAT;.CUSTOM"


def test_shell_subprocess_env_none_on_non_windows(monkeypatch):
    monkeypatch.setattr("src.shell_resolver.sys.platform", "linux")
    assert shell_subprocess_env() is None


# --- C-2 (auditoría 2026-08-11): has_unsafe_substitution ---

def test_unsafe_substitution_dollar_paren_in_double_quotes():
    assert has_unsafe_substitution('echo "$(whoami)"') is True


def test_unsafe_substitution_backtick_in_double_quotes():
    assert has_unsafe_substitution('echo "`whoami`"') is True


def test_unsafe_substitution_single_quotes_are_literal():
    assert has_unsafe_substitution("echo '$(whoami)'") is False


def test_unsafe_substitution_no_quotes_is_not_flagged():
    # Outside quotes the operator splitter handles it separately; this function
    # only targets the inside-double-quotes gap.
    assert has_unsafe_substitution("echo hello") is False


def test_unsafe_substitution_bare_dollar_is_not_flagged():
    assert has_unsafe_substitution('echo "price is $5"') is False


def test_unsafe_substitution_empty_string():
    assert has_unsafe_substitution("") is False


