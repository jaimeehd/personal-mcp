import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import AppConfig, CommandPolicy, SecurityConfig, ShellConfig


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


# --- C-2 (auditoría 2026-08-11): command substitution inside double quotes ---

def test_command_allowed_rejects_substitution_in_double_quotes():
    policy = CommandPolicy()
    allowed, reason = policy.is_command_allowed('echo "$(whoami)"')
    assert allowed is False
    assert "substitution" in reason.lower()


def test_command_allowed_rejects_backtick_in_double_quotes():
    policy = CommandPolicy()
    allowed, _ = policy.is_command_allowed('echo "`whoami`"')
    assert allowed is False


def test_command_allowed_still_allows_plain_echo():
    policy = CommandPolicy()
    allowed, _ = policy.is_command_allowed("echo hello")
    assert allowed is True


# --- C-1 (auditoría 2026-08-11): sh_script inline-operator bypass ---

def test_script_readonly_rejects_inline_operator():
    policy = CommandPolicy()
    ok, reason = policy.is_script_readonly("echo hi; Remove-Item -Recurse C:\\")
    assert ok is False
    assert "read-only" in reason or "whitelist" in reason


def test_script_readonly_rejects_pipe_to_non_readonly():
    policy = CommandPolicy()
    ok, _ = policy.is_script_readonly("echo hi | Remove-Item C:\\temp")
    assert ok is False


def test_script_readonly_rejects_substitution_in_double_quotes():
    policy = CommandPolicy()
    ok, _ = policy.is_script_readonly('echo "$(whoami)"')
    assert ok is False


def test_script_readonly_allows_legitimate_multi_line():
    policy = CommandPolicy()
    ok, _ = policy.is_script_readonly("echo hello\necho world")
    assert ok is True


def test_script_readonly_allows_comment_and_blank_lines():
    policy = CommandPolicy()
    ok, _ = policy.is_script_readonly("# a comment\n\necho hi")
    assert ok is True


# --- A-6 (auditoría 2026-08-11): AppData deny default must be recursive ---

def test_default_paths_deny_appdata_wildcard():
    import sys

    from src.config import _default_paths_deny

    patterns = _default_paths_deny()
    if sys.platform == "win32":
        # Must be a wildcard pattern, never a bare exact path.
        assert any("AppData" in p and "*" in p for p in patterns)
        assert not any(p.rstrip("\\/").endswith("AppData") for p in patterns)


# --- B-4 (auditoría 2026-08-11): invalid UTF-8 in config.json no longer crashes ---

def test_config_load_tolerates_invalid_utf8(temp_home):
    path = temp_home / ".personal-mcp" / "config.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b'{"security": {"paths_allow": ["/tmp/\xff\xfeRepo"]}}')

    cfg = AppConfig.load(path)
    assert "Repo" in cfg.security.paths_allow[0]
