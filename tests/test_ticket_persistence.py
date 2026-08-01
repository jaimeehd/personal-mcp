"""Regression tests for v1.4.41: pending-ticket persistence + observability.

Covers the exact incident class that prompted this release: a batch-delete
ticket (`fs_delete_batch`) created in memory, killed silently by a server
restart, with the subsequent `fs_approve`/`fs_deny` on the stale ticket id
logged as "OK" (success even though nothing happened).

These tests lock in:
  1. PermissionManager emits PENDING / GRANTED / APPROVE_FAIL / DENY_FAIL log
     lines (no more invisible ticket lifecycle).
  2. request_batch() dedups like request() — no duplicate popups/codes.
  3. Pending tickets persist to tickets.jsonl (metadata only, never the
     confirm_code or HMAC secret) and survive a simulated restart, with a
     REGENERATED confirm_code (fresh HMAC secret per process).
  4. AuditedFastMCP flags fs_approve/fs_deny semantic failures as FAILED in
     both the log and the audit record, instead of a false "OK".
"""
import io
import json
import logging
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.audit import AuditLog
from src.config import AppConfig, SecurityConfig
from src.permissions import GrantLevel, PermissionManager
from src.server import AuditedFastMCP


def _make_config(tmp_path):
    data = tmp_path / ".personal-mcp" / "data"
    data.mkdir(parents=True, exist_ok=True)
    return AppConfig(
        security=SecurityConfig(paths_allow=[str(tmp_path)]),
        data_dir=str(data),
        config_path=str(tmp_path / "config.json"),
    )


@pytest.fixture
def perm(tmp_path):
    return PermissionManager(_make_config(tmp_path))


# ===================================================================
# 1 — Logging (ticket lifecycle must be visible)
# ===================================================================

def test_permission_manager_logs_lifecycle(perm):
    logger = logging.getLogger("personal-mcp.permissions")
    logger.handlers.clear()
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    ticket = perm.request_batch(["C:\\tmp\\a.txt"], "delete")
    perm.approve(ticket.id, confirm_code=ticket.confirm_code)
    perm.request("C:\\tmp\\other.txt", "write")
    perm.approve("perm_nonexistent", confirm_code="123456")

    text = stream.getvalue()
    assert f"PENDING ticket={ticket.id} op=delete resources=1" in text
    assert f"GRANTED ticket={ticket.id} level=single" in text
    assert "APPROVE_FAIL ticket=perm_nonexistent reason=not_found" in text


# ===================================================================
# 2 — request_batch() dedup
# ===================================================================

def test_request_batch_creates_ticket(perm):
    paths = ["C:\\tmp\\a.txt", "C:\\tmp\\b.txt"]
    ticket = perm.request_batch(paths, "delete")
    assert ticket.id.startswith("perm_")
    assert ticket.status == "pending"
    assert ticket.resources == paths
    assert ticket.confirm_code is not None
    assert len(perm.pending()) == 1


def test_request_batch_dedup_reuses_ticket(perm):
    paths = ["C:\\tmp\\a.txt", "C:\\tmp\\b.txt"]
    t1 = perm.request_batch(paths, "delete")
    t2 = perm.request_batch(list(reversed(paths)), "delete")
    assert t1.id == t2.id
    assert len(perm.pending()) == 1


def test_request_batch_dedup_respects_operation_and_list(perm):
    t1 = perm.request_batch(["C:\\tmp\\a.txt"], "delete")
    t2 = perm.request_batch(["C:\\tmp\\a.txt"], "write")
    t3 = perm.request_batch(["C:\\tmp\\a.txt", "C:\\tmp\\b.txt"], "delete")
    assert len({t1.id, t2.id, t3.id}) == 3


# ===================================================================
# 3 — Persistence across a simulated restart
# ===================================================================

def test_pending_batch_ticket_survives_restart(perm, tmp_path):
    paths = ["C:\\tmp\\a.txt", "C:\\tmp\\b.txt"]
    ticket = perm.request_batch(paths, "delete")
    new_perm = PermissionManager(_make_config(tmp_path))
    restored = new_perm._tickets.get(ticket.id)
    assert restored is not None
    assert restored.status == "pending"
    assert restored.resources == paths
    assert restored.restored is True


def test_pending_single_ticket_survives_restart(perm, tmp_path):
    ticket = perm.request("C:\\tmp\\a.txt", "write")
    new_perm = PermissionManager(_make_config(tmp_path))
    restored = new_perm._tickets.get(ticket.id)
    assert restored is not None
    assert restored.restored is True


def test_restored_ticket_has_new_code(perm, tmp_path):
    ticket = perm.request_batch(["C:\\tmp\\a.txt"], "delete")
    old_code = ticket.confirm_code
    new_perm = PermissionManager(_make_config(tmp_path))
    restored = new_perm._tickets[ticket.id]
    assert restored.confirm_code != old_code


def test_restored_ticket_approvable_with_new_code(perm, tmp_path):
    paths = ["C:\\tmp\\a.txt"]
    ticket = perm.request_batch(paths, "delete")
    new_perm = PermissionManager(_make_config(tmp_path))
    restored = new_perm._tickets[ticket.id]
    # Stale pre-restart code is rejected (and its popup would be re-shown)...
    ok, msg = new_perm.approve(ticket.id, confirm_code=ticket.confirm_code)
    assert ok is False
    assert "Invalid" in msg
    # ...but the regenerated code works, and delete stays single-use.
    ok, _ = new_perm.approve(ticket.id, GrantLevel.SINGLE, confirm_code=restored.confirm_code)
    assert ok is True
    resolved = new_perm._resolve(paths[0])
    assert new_perm._single_grants.get(resolved, {}).get("delete") == 1


def test_approved_ticket_not_restored(perm, tmp_path):
    ticket = perm.request_batch(["C:\\tmp\\a.txt"], "delete")
    perm.approve(ticket.id, confirm_code=ticket.confirm_code)
    new_perm = PermissionManager(_make_config(tmp_path))
    assert ticket.id not in new_perm._tickets


def test_denied_ticket_not_restored(perm, tmp_path):
    ticket = perm.request_batch(["C:\\tmp\\a.txt"], "delete")
    perm.deny(ticket.id)
    new_perm = PermissionManager(_make_config(tmp_path))
    assert ticket.id not in new_perm._tickets


def test_expired_persisted_ticket_not_restored(perm, tmp_path):
    path = perm._tickets_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps({
            "id": "perm_deadbeef",
            "resource": "1 files",
            "resources": ["C:\\tmp\\a.txt"],
            "operation": "delete",
            "level": "single",
            "created_at": time.time() - 400,
            "expires_at": time.time() - 100,
            "status": "pending",
        }) + "\n")
    new_perm = PermissionManager(_make_config(tmp_path))
    assert "perm_deadbeef" not in new_perm._tickets


def test_persistence_never_writes_secret_or_code(perm, tmp_path):
    ticket = perm.request_batch(["C:\\tmp\\a.txt"], "delete")
    lines = Path(perm._tickets_path()).read_text(encoding="utf-8").strip().splitlines()
    raw = "\n".join(lines)
    assert ticket.confirm_code not in raw
    assert "confirm_code" not in raw
    assert "secret" not in raw


def test_force_single_for_delete_batch(perm):
    paths = ["C:\\tmp\\a.txt", "C:\\tmp\\b.txt"]
    ticket = perm.request_batch(paths, "delete")
    ok, msg = perm.approve(ticket.id, GrantLevel.SESSION, confirm_code=ticket.confirm_code)
    assert ok is True
    assert "delete is always single-use" in msg
    for p in paths:
        resolved = perm._resolve(p)
        assert resolved not in perm._session_grants
        assert perm._single_grants.get(resolved, {}).get("delete") == 1


# ===================================================================
# 4 — AuditedFastMCP semantic-failure detection
# ===================================================================

def _make_app():
    audit_log = AuditLog(max_entries=100)
    logger = logging.getLogger("test-audited-mcp")
    logger.handlers.clear()
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    app = AuditedFastMCP("test", audit_log=audit_log, logger=logger)

    @app.tool()
    def fs_approve(ticket_id: str, confirm_code: str, level: str = "single") -> str:
        return f"Ticket not found: {ticket_id}"

    @app.tool()
    def fs_deny(ticket_id: str) -> str:
        return f"Denied access to {ticket_id}"

    @app.tool()
    def fs_info(path: str) -> str:
        return "path: " + path

    return app, audit_log, stream


def test_semantic_failure_detection():
    app, _, _ = _make_app()
    assert app._is_semantic_failure("fs_approve", "Ticket not found: perm_x")
    assert app._is_semantic_failure("fs_deny", "Ticket expired: perm_x")
    assert app._is_semantic_failure("fs_approve", "Ticket already approved: perm_x")
    assert app._is_semantic_failure("fs_deny", "Invalid or missing confirmation code.")
    assert app._is_semantic_failure("fs_approve", "Invalid level 'bogus'. Use: single, session")
    assert app._is_semantic_failure("fs_deny", "Permanent grants are disabled from tool calls.")
    assert not app._is_semantic_failure("fs_approve", "Granted single access to 1 files")
    assert not app._is_semantic_failure("fs_delete_batch", "Error: path does not exist")
    assert not app._is_semantic_failure("fs_approve", None)


async def test_call_tool_flags_semantic_failure():
    app, audit_log, stream = _make_app()
    result = await app.call_tool(
        "fs_approve",
        {"ticket_id": "perm_x", "confirm_code": "000000", "level": "single"},
    )
    assert app._result_text(result) == "Ticket not found: perm_x"
    entry = audit_log.recent(1)[0]
    assert entry["tool"] == "fs_approve"
    assert entry["success"] is False
    assert "FAILED fs_approve" in stream.getvalue()
    assert "Ticket not found: perm_x" in stream.getvalue()


async def test_call_tool_ok_on_normal_result():
    app, audit_log, stream = _make_app()
    result = await app.call_tool("fs_deny", {"ticket_id": "perm_y"})
    assert app._result_text(result) == "Denied access to perm_y"
    assert audit_log.recent(1)[0]["success"] is True
    assert "OK   fs_deny" in stream.getvalue()


async def test_call_tool_ignores_business_errors_of_other_tools():
    app, audit_log, _ = _make_app()
    result = await app.call_tool("fs_info", {"path": "C:\\tmp\\a.txt"})
    assert app._result_text(result) == "path: C:\\tmp\\a.txt"
    assert audit_log.recent(1)[0]["success"] is True
