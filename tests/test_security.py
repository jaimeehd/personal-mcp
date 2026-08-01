import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import AppConfig, CommandPolicy, SecurityConfig
from src.permissions import GrantLevel, PermissionManager
from src.security import CommandNotAllowedError, PathNotAllowedError, SecurityValidator


@pytest.fixture
def strict_config(temp_home):
    config = AppConfig(
        security=SecurityConfig(
            paths_allow=[str(temp_home / "Repos")],
            paths_deny=["**/node_modules/**", "**/.git/**"],
        ),
        data_dir=str(temp_home / ".personal-mcp" / "data"),
        config_path=str(temp_home / ".personal-mcp" / "config.json"),
    )
    return config


@pytest.fixture
def strict_security(strict_config):
    validator = SecurityValidator(strict_config)
    validator.perm_manager = PermissionManager(strict_config)
    # Grant session-wide access to temp_home for security tests
    # Note: strict_config.security.paths_allow[0] is usually temp_home / "Repos"
    # We grant access to the root of paths_allow for simplicity in tests
    for path in strict_config.security.paths_allow:
        validator.perm_manager.grant_direct(path, "*", GrantLevel.SESSION)
    return validator


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


# --- paths_deny_exceptions: build-artifact read exception ---

@pytest.fixture
def exception_config(temp_home):
    config = AppConfig(
        security=SecurityConfig(
            paths_allow=[str(temp_home / "Repos")],
            paths_deny=["**/node_modules/**", "**/.git/**", "**/bin/**", "**/obj/**"],
            paths_deny_exceptions=[
                # Dos patrones por la misma razon documentada en
                # _deny_exception_applies: fnmatch's "**" no tiene semantica
                # recursiva real (es solo "*" duplicado), asi que "proyecto\**\bin\**"
                # exige al menos una subcarpeta intermedia entre el proyecto y bin\ --
                # no matchea "proyecto\bin\..." directamente. Se necesita un segundo
                # patron explicito para el caso "bin\ justo bajo la raiz del proyecto".
                str(temp_home / "Repos" / "MyProj" / "**" / "bin" / "**"),
                str(temp_home / "Repos" / "MyProj" / "bin" / "**"),
            ],
            paths_deny_exception_extensions=[".dll", ".exe", ".pdb"],
        ),
        data_dir=str(temp_home / ".personal-mcp" / "data"),
        config_path=str(temp_home / ".personal-mcp" / "config.json"),
    )
    return config


@pytest.fixture
def exception_security(exception_config):
    validator = SecurityValidator(exception_config)
    validator.perm_manager = PermissionManager(exception_config)
    for path in exception_config.security.paths_allow:
        validator.perm_manager.grant_direct(path, "*", GrantLevel.SESSION)
    return validator


def test_deny_exception_allows_matching_dll_read_nested(exception_security, temp_home):
    # bin\ bajo una subcarpeta intermedia (ej. src\MyProj\bin\..., el caso real
    # en HikBioAccess) -- matchea el patron con "**\bin\**".
    dll_path = temp_home / "Repos" / "MyProj" / "src" / "bin" / "Release" / "MyProj.dll"
    dll_path.parent.mkdir(parents=True, exist_ok=True)
    dll_path.write_bytes(b"fake dll content")
    result = exception_security.resolve_and_validate(str(dll_path))
    assert result == dll_path.resolve()


def test_deny_exception_allows_matching_dll_read_direct(exception_security, temp_home):
    # bin\ directamente bajo la raiz del proyecto, sin subcarpeta intermedia --
    # requiere el segundo patron explicito ("proyecto\bin\**").
    dll_path = temp_home / "Repos" / "MyProj" / "bin" / "Release" / "MyProj.dll"
    dll_path.parent.mkdir(parents=True, exist_ok=True)
    dll_path.write_bytes(b"fake dll content")
    result = exception_security.resolve_and_validate(str(dll_path))
    assert result == dll_path.resolve()


def test_deny_exception_still_blocks_non_matching_extension(exception_security, temp_home):
    txt_path = temp_home / "Repos" / "MyProj" / "bin" / "Release" / "notes.txt"
    txt_path.parent.mkdir(parents=True, exist_ok=True)
    txt_path.write_text("no deberia poder leerse")
    # .txt no esta en paths_deny_exception_extensions -- el bloqueo de bin\ sigue aplicando.
    with pytest.raises(PathNotAllowedError, match="Path denied by pattern"):
        exception_security.resolve_and_validate(str(txt_path))


def test_deny_exception_still_blocks_non_matching_pattern(exception_security, temp_home):
    # Mismo nombre de archivo/extension, pero bajo un proyecto que NO esta en
    # paths_deny_exceptions -- debe seguir bloqueado (la excepcion es por proyecto,
    # no una apertura general de **\bin\**).
    dll_path = temp_home / "Repos" / "OtroProyecto" / "bin" / "Release" / "Otro.dll"
    dll_path.parent.mkdir(parents=True, exist_ok=True)
    dll_path.write_bytes(b"fake dll content")
    with pytest.raises(PathNotAllowedError, match="Path denied by pattern"):
        exception_security.resolve_and_validate(str(dll_path))


def test_deny_exception_allows_listing_matching_directory(exception_security, temp_home):
    # Bug real encontrado 2026-07-19: fs_find/fs_list/fs_tree validan el
    # DIRECTORIO de busqueda, no cada archivo encontrado adentro -- un directorio
    # no tiene extension, asi que el chequeo de extension solo nunca dejaba pasar
    # nada. Para un directorio que matchea el patron de excepcion, alcanza con
    # el match de patron (esto solo revela nombres/tamanos/fechas, no contenido).
    bin_dir = temp_home / "Repos" / "MyProj" / "bin" / "Release"
    bin_dir.mkdir(parents=True, exist_ok=True)
    result = exception_security.resolve_and_validate(str(bin_dir))
    assert result == bin_dir.resolve()


def test_deny_exception_directory_listing_does_not_unblock_file_read(exception_security, temp_home):
    # El listado de la carpeta esta permitido (test anterior), pero eso NO debe
    # habilitar la lectura de CONTENIDO de un archivo que no sea .dll/.exe/.pdb
    # dentro de esa misma carpeta -- el gate de extension sigue vigente por archivo.
    txt_path = temp_home / "Repos" / "MyProj" / "bin" / "Release" / "secret.txt"
    txt_path.parent.mkdir(parents=True, exist_ok=True)
    txt_path.write_text("no deberia poder leerse aunque la carpeta si se pueda listar")
    with pytest.raises(PathNotAllowedError, match="Path denied by pattern"):
        exception_security.resolve_and_validate(str(txt_path))


def test_deny_exception_never_applies_to_write(exception_security, temp_home):
    dll_path = temp_home / "Repos" / "MyProj" / "bin" / "Release" / "MyProj.dll"
    dll_path.parent.mkdir(parents=True, exist_ok=True)
    dll_path.write_bytes(b"fake dll content")
    # Aunque extension y patron coincidan, la excepcion es SOLO para operation="read".
    with pytest.raises(PathNotAllowedError, match="Path denied by pattern"):
        exception_security.resolve_and_validate(str(dll_path), operation="write")


def test_path_relative_rejected(strict_security, temp_home):
    with pytest.raises(PathNotAllowedError):
        strict_security.resolve_and_validate("Repos/file.txt")


def test_command_allowed(strict_security):
    strict_security.validate_command("git status")
    strict_security.validate_command("npm install")
    strict_security.validate_command("python main.py")


def test_command_denied(strict_security):
    with pytest.raises(CommandNotAllowedError):
        strict_security.validate_command("shutdown /s /t 0")


def test_command_prefix_allow_when_unrestricted(strict_security):
    strict_security.validate_command("git status")
    strict_security.validate_command("echo hello")


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
    with pytest.raises(CommandNotAllowedError):
        strict_security.validate_command("curl http://example.com")
    with pytest.raises(CommandNotAllowedError):
        strict_security.validate_command("wget http://example.com")

    with pytest.raises(CommandNotAllowedError):
        strict_security.validate_command("Write-Host hello")
    with pytest.raises(CommandNotAllowedError):
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
        data_dir=str(temp_home / ".personal-mcp" / "data"),
    )
    security = SecurityValidator(config)
    security.perm_manager = PermissionManager(config)
    security.perm_manager.grant_direct(str(temp_home), "*", GrantLevel.SESSION)
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


# --- #2/#3: Symlink escape tests ---

def _can_create_symlinks() -> bool:
    """Check if the test environment can create symlinks."""
    import os
    import tempfile
    try:
        tmp = tempfile.mkdtemp()
        target = Path(tmp) / "real_target"
        target.mkdir()
        link = Path(tmp) / "mylink"
        os.symlink(str(target), str(link), target_is_directory=True)
        ok = link.exists()
        link.unlink()
        target.rmdir()
        os.rmdir(tmp)
        return ok
    except (OSError, NotImplementedError):
        return False


def test_symlink_read_escape_blocked(strict_security, temp_home):
    if not _can_create_symlinks():
        pytest.skip("Cannot create symlinks on this system (need admin/developer mode)")
    import os
    legit_dir = temp_home / "Repos" / "legit"
    legit_dir.mkdir(parents=True, exist_ok=True)
    outside_dir = temp_home / "Outside" / "secrets"
    outside_dir.mkdir(parents=True, exist_ok=True)
    link_path = legit_dir / "evil_link"
    os.symlink(str(outside_dir), str(link_path), target_is_directory=True)

    secret_file = outside_dir / "password.txt"
    secret_file.write_text("admin:secret123")
    target = link_path / "password.txt"

    with pytest.raises(PathNotAllowedError, match="not in allowed directories"):
        strict_security.resolve_and_validate(str(target))


def test_symlink_write_escape_blocked(strict_security, temp_home):
    if not _can_create_symlinks():
        pytest.skip("Cannot create symlinks on this system (need admin/developer mode)")
    import os
    legit_dir = temp_home / "Repos" / "legit2"
    legit_dir.mkdir(parents=True, exist_ok=True)
    outside_dir = temp_home / "Outside2"
    outside_dir.mkdir(parents=True, exist_ok=True)
    link_path = legit_dir / "evil_link2"
    os.symlink(str(outside_dir), str(link_path), target_is_directory=True)

    target = link_path / "malicious_write.txt"
    with pytest.raises(PathNotAllowedError, match="not in allowed directories"):
        strict_security.resolve_and_validate(str(target), operation="write")


def test_symlink_inside_allowed_allowed(strict_security, temp_home):
    if not _can_create_symlinks():
        pytest.skip("Cannot create symlinks on this system (need admin/developer mode)")
    import os
    dir_a = temp_home / "Repos" / "A"
    dir_a.mkdir(parents=True, exist_ok=True)
    dir_b = temp_home / "Repos" / "B"
    dir_b.mkdir(parents=True, exist_ok=True)
    link_path = dir_a / "to_B"
    os.symlink(str(dir_b), str(link_path), target_is_directory=True)

    target = link_path / "some_file.txt"
    result = strict_security.resolve_and_validate(str(target))
    assert result == (dir_b / "some_file.txt").resolve()
