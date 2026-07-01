import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.security import SecurityValidator, PathNotAllowedError, CommandNotAllowedError
from src.config import AppConfig, SecurityConfig, CommandPolicy


@pytest.fixture
def strict_config(temp_home):
    config = AppConfig(
        security=SecurityConfig(
            paths_allow=[str(temp_home / "Repos")],
            paths_deny=["**\\node_modules\\**", "**\\.git\\**"],
        ),
        config_path=str(temp_home / ".personal-mcp" / "config.json"),
    )
    return config


@pytest.fixture
def strict_security(strict_config):
    return SecurityValidator(strict_config)


def test_path_allowed(strict_security, temp_home):
    path = strict_security.resolve_and_validate(str(temp_home / "Repos" / "file.txt"))
    assert path == (temp_home / "Repos" / "file.txt").resolve()


def test_path_denied_outside(strict_security, temp_home):
    with pytest.raises(PathNotAllowedError):
        strict_security.resolve_and_validate(str(temp_home / "Windows" / "system32" / "config"))


def test_path_denied_pattern(strict_security, temp_home):
    denied_path = temp_home / "Repos" / "project" / "node_modules" / "lib" / "index.js"
    denied_path.parent.mkdir(parents=True, exist_ok=True)
    denied_path.write_text("test")
    with pytest.raises(PathNotAllowedError):
        strict_security.resolve_and_validate(str(denied_path))


def test_path_relative_rejected(strict_security, temp_home):
    with pytest.raises(PathNotAllowedError):
        strict_security.resolve_and_validate("Repos/file.txt")


def test_command_allowed(strict_security):
    strict_security.validate_command("git status")
    strict_security.validate_command("npm install")
    strict_security.validate_command("dir C:\\Repos")


def test_command_denied(strict_security):
    with pytest.raises(CommandNotAllowedError):
        strict_security.validate_command("shutdown /s /t 0")


def test_command_prefix_allow_when_unrestricted(strict_security):
    strict_security.validate_command("curl http://example.com")
    strict_security.validate_command("Write-Host hello")


def test_command_prefix_enforced_when_set(temp_home):
    config = AppConfig(
        security=SecurityConfig(
            paths_allow=[str(temp_home / "Repos")],
            commands=CommandPolicy(
                allow_prefix=["git", "npm"],
            ),
        ),
    )
    sec = SecurityValidator(config)
    sec.validate_command("git status")
    sec.validate_command("npm install")
    with pytest.raises(CommandNotAllowedError):
        sec.validate_command("curl http://evil.com")


def test_command_prefix_not_in_allowlist(strict_security):
    strict_security.validate_command("curl http://example.com")
    strict_security.validate_command("wget http://example.com")

    strict_security.validate_command("Write-Host hello")
    strict_security.validate_command("foreach")


def test_require_flag_approval():
    policy = CommandPolicy()
    allowed, _ = policy.is_command_allowed("git status")
    assert allowed is True


def test_file_count_limit(strict_security):
    strict_security.validate_file_count(50)
    with pytest.raises(ValueError):
        strict_security.validate_file_count(500)


def test_is_subpath(strict_security, temp_home):
    parent = (temp_home / "Repos").resolve()
    child = (temp_home / "Repos" / "project" / "file.txt").resolve()
    assert SecurityValidator._is_subpath(child, parent)
    outside = (temp_home / "Desktop" / "file.txt").resolve()
    assert not SecurityValidator._is_subpath(outside, parent)


def test_multiple_allowed_paths(temp_home):
    config = AppConfig(
        security=SecurityConfig(
            paths_allow=[
                str(temp_home / "Repos"),
                str(temp_home / "Desktop"),
            ],
        ),
    )
    security = SecurityValidator(config)
    security.resolve_and_validate(str(temp_home / "Repos" / "a.txt"))
    security.resolve_and_validate(str(temp_home / "Desktop" / "b.txt"))
    with pytest.raises(PathNotAllowedError):
        security.resolve_and_validate(str(temp_home / "Downloads" / "c.txt"))


def test_is_path_allowed(strict_security, temp_home):
    assert strict_security.is_path_allowed(str(temp_home / "Repos" / "file.txt")) is True
    assert strict_security.is_path_allowed(str(temp_home / "Windows" / "system.ini")) is False


def test_extract_absolute_paths():
    text = "Look at C:\\Windows\\system.ini and D:\\data\\file.txt"
    paths = SecurityValidator.extract_absolute_paths(text)
    assert "C:\\Windows\\system.ini" in paths
    assert "D:\\data\\file.txt" in paths


def test_request_permission_no_manager(strict_security, temp_home):
    result = strict_security.request_permission(str(temp_home / "secret.txt"))
    assert "permission_required" in result


def test_request_permission_with_manager(strict_security, temp_home):
    from src.permissions import PermissionManager
    pm = PermissionManager(strict_security.config)
    strict_security.perm_manager = pm
    result = strict_security.request_permission(str(temp_home / "secret.txt"))
    assert "permission_required" in result
    assert "ticket" in result
