"""Tests para AuditedFastMCP — deteccion de semantic failure y BLOCKED en audit log.

Verifica que las tools destructivas que devuelven permission_required
(operacion bloqueada por tickets) se detecten correctamente como fallas
semanticas, distinguiendo BLOCKED (bloqueado por tickets) de FAILED
(fs_approve/fs_deny fallo) y OK (operacion exitosa).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.server import AuditedFastMCP


class TestSemanticFailureDetection:
    """_is_semantic_failure detecta tickets invalidos y permisos bloqueados."""

    def _make_checker(self):
        # AuditedFastMCP requiere audit_log y logger en __init__,
        # pero _is_semantic_failure y _is_permission_blocked solo usan
        # atributos de clase y el nombre/texto — podemos testear la logica
        # sin instanciar la clase accediendo a los metodos de clase via
        # una instancia minima mock.
        class _FakeAudit:
            def record(self, *a, **kw):
                pass

        class _FakeLogger:
            def warning(self, *a, **kw):
                pass

            def info(self, *a, **kw):
                pass

        return AuditedFastMCP.__new__(AuditedFastMCP)

    def test_fs_approve_fail_is_semantic_failure(self):
        checker = self._make_checker()
        assert checker._is_semantic_failure(
            "fs_approve", "Ticket not found: perm_x"
        ) is True

    def test_fs_approve_invalid_code_is_semantic_failure(self):
        checker = self._make_checker()
        assert checker._is_semantic_failure(
            "fs_approve", "Invalid or missing confirmation code."
        ) is True

    def test_fs_write_blocked_is_semantic_failure(self):
        checker = self._make_checker()
        blocked_json = (
            '{"status": "permission_required", "ticket": "perm_x", '
            '"resource": "foo.txt", "operation": "write", "level": "single", '
            '"message": "Access to foo.txt needs write permission."}'
        )
        assert checker._is_semantic_failure("fs_write", blocked_json) is True

    def test_fs_write_ok_is_not_semantic_failure(self):
        checker = self._make_checker()
        assert checker._is_semantic_failure("fs_write", "Written 100 chars") is False

    def test_fs_edit_blocked_is_semantic_failure(self):
        checker = self._make_checker()
        blocked_json = '{"status": "permission_required", "ticket": "perm_y"}'
        assert checker._is_semantic_failure("fs_edit", blocked_json) is True

    def test_fs_edit_ok_is_not_semantic_failure(self):
        checker = self._make_checker()
        assert checker._is_semantic_failure("fs_edit", "Applied edit.") is False

    def test_sh_spawn_blocked_is_semantic_failure(self):
        # M-S7 (auditoría 2026-08-11): sh_spawn requires its own execute ticket,
        # so a permission_required result must be audited as BLOCKED, not OK.
        checker = self._make_checker()
        blocked_json = '{"status": "permission_required", "ticket": "perm_z"}'
        assert checker._is_semantic_failure("sh_spawn", blocked_json) is True

    def test_non_destructive_tool_never_semantic_failure(self):
        checker = self._make_checker()
        blocked_json = '{"status": "permission_required"}'
        # fs_read no esta en _SEMANTIC_FAILURE_TOOLS
        assert checker._is_semantic_failure("fs_read", blocked_json) is False

    def test_unknown_tool_never_semantic_failure(self):
        checker = self._make_checker()
        assert checker._is_semantic_failure("health_check", "Ticket not found") is False

    def test_fs_write_error_not_semantic_failure(self):
        checker = self._make_checker()
        # "Error: not a file" es un error normal, no un bloqueo por tickets
        assert checker._is_semantic_failure(
            "fs_write", "Error: not a file or does not exist: foo.txt"
        ) is False


class TestPermissionBlockedDetection:
    """_is_permission_blocked distingue bloqueo por tickets de error normal."""

    def _make_checker(self):
        return AuditedFastMCP.__new__(AuditedFastMCP)

    def test_blocked_write_detected(self):
        checker = self._make_checker()
        blocked = '{"status": "permission_required", "ticket": "perm_1"}'
        assert checker._is_permission_blocked("fs_write", blocked) is True

    def test_blocked_delete_detected(self):
        checker = self._make_checker()
        blocked = '{"status": "permission_required", "ticket": "perm_2"}'
        assert checker._is_permission_blocked("fs_delete", blocked) is True

    def test_successful_write_not_blocked(self):
        checker = self._make_checker()
        assert checker._is_permission_blocked("fs_write", "Written 100 chars") is False

    def test_error_not_blocked(self):
        checker = self._make_checker()
        assert checker._is_permission_blocked(
            "fs_write", "Error: not a file"
        ) is False

    def test_fs_approve_never_permission_blocked(self):
        checker = self._make_checker()
        # fs_approve fallido es FAILED, no BLOCKED — aunque el texto podria
        # contener "permission_required" en otro contexto, fs_approve esta
        # excluido explicitamente de _is_permission_blocked.
        assert checker._is_permission_blocked(
            "fs_approve", "Ticket not found"
        ) is False

    def test_non_destructive_tool_never_blocked(self):
        checker = self._make_checker()
        blocked = '{"status": "permission_required"}'
        assert checker._is_permission_blocked("fs_list", blocked) is False


class TestResultTextExtraction:
    """_result_text extrae texto de los formatos de retorno de FastMCP."""

    def _make_checker(self):
        return AuditedFastMCP.__new__(AuditedFastMCP)

    def test_plain_string(self):
        checker = self._make_checker()
        assert checker._result_text("hello") == "hello"

    def test_tuple_with_text_block(self):
        checker = self._make_checker()
        # FastMCP 3.4.x devuelve (content_blocks, dict)
        class _FakeText:
            def __init__(self, text):
                self.text = text

        result = ([_FakeText("extracted")], {"result": "extracted"})
        assert checker._result_text(result) == "extracted"

    def test_none_returns_none(self):
        checker = self._make_checker()
        assert checker._result_text(None) is None


class TestAccessDeniedDetection:
    """_is_access_denied detecta rechazos duros de config ("Access denied: ...")."""

    def _make_checker(self):
        return AuditedFastMCP.__new__(AuditedFastMCP)

    def test_access_denied_detected_for_read_tool(self):
        checker = self._make_checker()
        assert checker._is_access_denied(
            "Access denied: Path denied by pattern '**/.git/**'"
        ) is True

    def test_access_denied_detected_for_shell(self):
        checker = self._make_checker()
        assert checker._is_access_denied(
            "Access denied: relative/home path '~/.ssh' is not allowed in shell commands"
        ) is True

    def test_access_denied_not_detected_for_normal_text(self):
        checker = self._make_checker()
        assert checker._is_access_denied("Written 100 chars") is False

    def test_access_denied_not_detected_for_empty(self):
        checker = self._make_checker()
        assert checker._is_access_denied(None) is False
