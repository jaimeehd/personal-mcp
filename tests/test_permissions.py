import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import AppConfig, SecurityConfig
from src.permissions import GrantLevel, PermissionManager
from src.security import SecurityValidator


@pytest.fixture
def perm(temp_home):
    config = AppConfig(
        security=SecurityConfig(
            paths_allow=[str(temp_home / "Repos")],
            # Explicit deny: pytest's tmp_path lives under AppData\Local\Temp, so the
            # default `**/AppData/**` (correct since A-6) would match it here.
            paths_deny=["**/node_modules/**", "**/.git/**"],
        ),
        data_dir=str(temp_home / ".personal-mcp" / "data"),
        config_path=str(temp_home / ".personal-mcp" / "config.json"),
    )
    return PermissionManager(config)


@pytest.fixture
def wired_perm(test_config):
    """Return a (perm_manager, security) tuple wired together."""
    pm = PermissionManager(test_config)
    sec = SecurityValidator(test_config)
    sec.perm_manager = pm
    return pm, sec


def test_ticket_create(perm):
    ticket = perm.request("C:\\Windows\\system.ini", "read")
    assert ticket.id.startswith("perm_")
    assert ticket.status == "pending"
    assert ticket.resource == "C:\\Windows\\system.ini"
    assert ticket.operation == "read"


def test_approve_single(perm):
    ticket = perm.request("C:\\Windows\\system.ini", "read")
    ok, _msg = perm.approve(ticket.id, confirm_code=ticket.confirm_code)
    assert ok is True
    assert ticket.status == "approved"


def test_approve_session(perm):
    ticket = perm.request("C:\\Windows\\system.ini", "read", GrantLevel.SESSION)
    ok, _msg = perm.approve(ticket.id, confirm_code=ticket.confirm_code)
    assert ok is True
    assert perm.check_granted("C:\\Windows\\system.ini", "read") is True


def test_approve_permanent(perm, temp_home):
    rsrc = str(temp_home / "outside.txt")
    ticket = perm.request(rsrc, "read", GrantLevel.PERMANENT)
    ok, _msg = perm.approve(ticket.id, confirm_code=ticket.confirm_code)
    assert ok is True
    assert rsrc in perm.config.security.paths_allow


def test_deny(perm):
    ticket = perm.request("C:\\Windows\\system.ini", "read")
    ok, _msg = perm.deny(ticket.id)
    assert ok is True
    assert ticket.status == "denied"


def test_approve_unknown_ticket(perm):
    ok, msg = perm.approve("perm_nonexistent")
    assert ok is False
    assert "not found" in msg


def test_approve_without_confirm_code(perm):
    """approve() sin confirm_code debe fallar — el codigo es obligatorio."""
    ticket = perm.request("C:\\Windows\\system.ini", "read")
    ok, msg = perm.approve(ticket.id)
    assert ok is False
    assert ticket.status == "pending"
    assert "Invalid or missing confirmation code" in msg


def test_approve_with_empty_confirm_code(perm):
    """approve() con confirm_code vacio debe fallar igual que None."""
    ticket = perm.request("C:\\Windows\\system.ini", "read")
    ok, msg = perm.approve(ticket.id, confirm_code="")
    assert ok is False
    assert ticket.status == "pending"
    assert "Invalid or missing confirmation code" in msg


def test_approve_rate_locks_after_max_attempts(perm):
    """Tras _MAX_APPROVE_ATTEMPTS intentos fallidos, el ticket se auto-deniega."""
    ticket = perm.request("C:\\Windows\\system.ini", "read")
    for _ in range(PermissionManager._MAX_APPROVE_ATTEMPTS - 1):
        ok, _msg = perm.approve(ticket.id, confirm_code="000000")
        assert ok is False
        assert ticket.status == "pending"
    # El intento numero _MAX_APPROVE_ATTEMPTS bloquea el ticket.
    ok, msg = perm.approve(ticket.id, confirm_code="000000")
    assert ok is False
    assert ticket.status == "denied"
    assert "locked" in msg.lower() or "failed attempts" in msg.lower()
    # Un ticket denegado no puede aprobarse ni con el codigo correcto.
    ok, _msg = perm.approve(ticket.id, confirm_code=ticket.confirm_code)
    assert ok is False
    assert "already" in _msg


def test_pending_list(perm):
    t1 = perm.request("C:\\Windows\\system.ini", "read")
    t2 = perm.request("C:\\Windows\\win.ini", "read")
    pending = perm.pending()
    assert len(pending) == 2
    ids = [p["id"] for p in pending]
    assert t1.id in ids
    assert t2.id in ids


def test_pending_after_approve(perm):
    t1 = perm.request("C:\\Windows\\system.ini", "read")
    t2 = perm.request("C:\\Windows\\win.ini", "read")
    perm.approve(t1.id, confirm_code=t1.confirm_code)
    pending = perm.pending()
    assert len(pending) == 1
    assert pending[0]["id"] == t2.id


def test_revoke(perm):
    ticket = perm.request("C:\\Windows\\system.ini", "read", GrantLevel.SESSION)
    perm.approve(ticket.id, confirm_code=ticket.confirm_code)
    assert perm.check_granted("C:\\Windows\\system.ini", "read") is True
    perm.revoke("C:\\Windows\\system.ini")
    assert perm.check_granted("C:\\Windows\\system.ini", "read") is False


def test_grant_direct(perm):
    ticket = perm.grant_direct("C:\\Temp", "read", GrantLevel.SESSION)
    assert ticket.status == "approved"
    assert perm.check_granted("C:\\Temp", "read") is True


def test_stats(perm):
    perm.request("C:\\Windows\\a.ini", "read")
    perm.request("C:\\Windows\\b.ini", "read")
    t3 = perm.request("C:\\Windows\\c.ini", "read")
    perm.approve(t3.id, confirm_code=t3.confirm_code)
    stats = perm.stats()
    assert stats["total_tickets"] == 3
    assert stats["pending"] == 2
    assert stats["approved"] == 1


def test_reuse_pending_ticket(perm):
    t1 = perm.request("C:\\Windows\\system.ini", "read")
    t2 = perm.request("C:\\Windows\\system.ini", "read")
    assert t1.id == t2.id


def test_duplicate_request_for_different_ops(perm):
    t1 = perm.request("C:\\Windows\\system.ini", "read")
    t2 = perm.request("C:\\Windows\\system.ini", "write")
    assert t1.id != t2.id


def test_ticket_to_dict(perm):
    ticket = perm.request("C:\\Windows\\system.ini", "read")
    d = ticket.to_dict()
    assert d["id"] == ticket.id
    assert d["status"] == "pending"
    assert d["resource"] == "C:\\Windows\\system.ini"


def test_revoke_ticket(perm):
    t = perm.request("C:\\Windows\\system.ini", "read", GrantLevel.SESSION)
    # Debe aprobarse con el confirm_code valido — approve() sin codigo falla
    # y el test pasaria por razon equivocada (el grant nunca se hubiera creado).
    ok_approve, _msg = perm.approve(t.id, confirm_code=t.confirm_code)
    assert ok_approve is True, f"approve con codigo valido debe succeed, got: {_msg}"
    assert perm.check_granted("C:\\Windows\\system.ini", "read") is True
    ok, _msg = perm.revoke_ticket(t.id)
    assert ok is True
    assert perm.check_granted("C:\\Windows\\system.ini", "read") is False


# --- revoke()/revoke_ticket() batch-resource fix (2026-08-08) ---
# Regression for a bug found via external audit: both methods used to key off
# ticket.resource (the summary string "N files" for a batch ticket), which
# never matches a real resolved path -- so revoking a batch ticket left the
# underlying per-file grants fully active while claiming success.

def test_revoke_batch_ticket_syncs_status(perm, temp_home):
    f1 = str(temp_home / "Repos" / "a.txt")
    f2 = str(temp_home / "Repos" / "b.txt")
    ticket = perm.request_batch([f1, f2], "write", GrantLevel.SESSION)
    ok, _msg = perm.approve(ticket.id, confirm_code=ticket.confirm_code)
    assert ok is True
    assert perm.check_granted(f1, "write") is True
    assert perm.check_granted(f2, "write") is True

    revoked = perm.revoke(f1, "write")
    assert revoked is True
    assert perm.check_granted(f1, "write") is False
    # The bug: ticket.status stayed "approved" forever for batch tickets,
    # because the sync loop compared ticket.resource ("2 files") == f1.
    assert ticket.status == "revoked"


def test_revoke_ticket_removes_all_batch_grants(perm, temp_home):
    f1 = str(temp_home / "Repos" / "c.txt")
    f2 = str(temp_home / "Repos" / "d.txt")
    f3 = str(temp_home / "Repos" / "e.txt")
    ticket = perm.request_batch([f1, f2, f3], "write", GrantLevel.SESSION)
    ok, _msg = perm.approve(ticket.id, confirm_code=ticket.confirm_code)
    assert ok is True
    for f in (f1, f2, f3):
        assert perm.check_granted(f, "write") is True

    ok, _msg = perm.revoke_ticket(ticket.id)
    assert ok is True
    # The bug: only a bogus resolved-"3 files" key was ever touched, so all
    # three real per-file grants stayed active despite revoke_ticket()
    # reporting success.
    for f in (f1, f2, f3):
        assert perm.check_granted(f, "write") is False


def test_grant_level_enum_values():
    assert GrantLevel.SINGLE.value == "single"
    assert GrantLevel.SESSION.value == "session"
    assert GrantLevel.PERMANENT.value == "permanent"


# --- M-C2 (auditoría 2026-08-11): revoking a specific op drops a "*" grant ---

def test_revoke_specific_op_removes_wildcard_grant(perm, temp_home):
    rsrc = str(temp_home / "Repos" / "wild.txt")
    perm.grant_direct(rsrc, "*", GrantLevel.SESSION)
    assert perm.check_granted(rsrc, "write") is True

    revoked = perm.revoke(rsrc, "write")
    assert revoked is True
    assert perm.check_granted(rsrc, "write") is False


def test_revoke_specific_op_keeps_other_op_grant(perm, temp_home):
    rsrc = str(temp_home / "Repos" / "mixed.txt")
    perm.grant_direct(rsrc, "write", GrantLevel.SESSION)
    perm.grant_direct(rsrc, "read", GrantLevel.SESSION)

    revoked = perm.revoke(rsrc, "write")
    assert revoked is True
    assert perm.check_granted(rsrc, "write") is False
    assert perm.check_granted(rsrc, "read") is True


# --- M-C5 (auditoría 2026-08-11): tickets.jsonl compaction ---

def test_compact_tickets_removes_resolved(perm, temp_home):
    from src.permissions import PermissionManager

    for i in range(3):
        t = perm.request(str(temp_home / "Repos" / f"f{i}.txt"), "write")
        perm.deny(t.id)

    perm._compact_tickets()
    path = Path(perm.config.data_dir) / PermissionManager.TICKETS_FILE
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    assert lines == []


def test_compact_tickets_keeps_pending(perm, temp_home):
    from src.permissions import PermissionManager

    perm.request(str(temp_home / "Repos" / "keep.txt"), "write")
    perm._compact_tickets()
    path = Path(perm.config.data_dir) / PermissionManager.TICKETS_FILE
    assert "keep.txt" in path.read_text(encoding="utf-8")


# --- M-F10 (auditoría 2026-08-11): permanent grant invalidates security cache ---

def test_permanent_grant_clears_security_cache(temp_home):
    config = AppConfig(
        security=SecurityConfig(
            paths_allow=[str(temp_home / "Repos")],
            paths_deny=["**/node_modules/**", "**/.git/**"],
        ),
        data_dir=str(temp_home / ".personal-mcp" / "data"),
        config_path=str(temp_home / ".personal-mcp" / "config.json"),
    )
    pm = PermissionManager(config)
    sec = SecurityValidator(config)
    sec.perm_manager = pm
    pm.security = sec

    # Populate the cache with just [Repos].
    sec.resolve_and_validate(str(temp_home / "Repos" / "x.txt"))

    new_path = str(temp_home / "NewPerm")
    pm.grant_direct(new_path, "read", GrantLevel.PERMANENT)

    # Cache was invalidated -> the new permanent path now resolves.
    assert sec.resolve_and_validate(new_path) == Path(new_path).resolve()


def test_session_grant_validates(wired_perm, temp_home):
    """Session grant makes validate_tool_path allow the path."""
    pm, security = wired_perm
    rsrc = str(temp_home / "Repos" / "granted.txt")
    pm.grant_direct(rsrc, "read", GrantLevel.SESSION)
    err = security.validate_tool_path(rsrc, "read")
    assert err is None, f"Expected None (allowed), got: {err}"


def test_single_grant_consumed(wired_perm, temp_home):
    """Single grant consumed on write; second write is denied (read auto-allowed)."""
    pm, security = wired_perm
    rsrc = str(temp_home / "Repos" / "single.txt")
    pm.grant_direct(rsrc, "write", GrantLevel.SINGLE)
    # First write — allowed
    assert security.validate_tool_path(rsrc, "write") is None
    # Second write — consumed
    err = security.validate_tool_path(rsrc, "write")
    assert err is not None
    assert "permission_required" in err


def test_single_grant_wildcard_consumed(wired_perm, temp_home):
    """Single wildcard grant consumed by write; second write denied."""
    pm, security = wired_perm
    rsrc = str(temp_home / "Repos" / "wild.txt")
    pm.grant_direct(rsrc, "*", GrantLevel.SINGLE)
    # First write — allowed (matches via wildcard "*")
    assert security.validate_tool_path(rsrc, "write") is None
    # Second write — consumed
    err = security.validate_tool_path(rsrc, "write")
    assert err is not None
    assert "permission_required" in err


def test_deny_still_wins_over_grant(wired_perm):
    """Deny pattern overrides any grant level."""
    pm, security = wired_perm
    # Grant session access to a path inside a deny pattern
    pm.grant_direct("C:\\Users\\usuario\\Repos\\project\\node_modules\\lib\\index.js", "read", GrantLevel.SESSION)
    err = security.validate_tool_path("C:\\Users\\usuario\\Repos\\project\\node_modules\\lib\\index.js", "read")
    assert err is not None
    assert "Access denied" in err


def test_permanent_grant_unaffected(perm, temp_home):
    """Permanent grant still adds to paths_allow (regression check)."""
    rsrc = str(temp_home / "permanent_test.txt")
    perm.grant_direct(rsrc, "read", GrantLevel.PERMANENT)
    assert rsrc in perm.config.security.paths_allow


def test_validate_tool_path_with_perm_manager(wired_perm, temp_home):
    """validate_tool_path respects session grants via perm_manager."""
    pm, security = wired_perm
    rsrc = str(temp_home / "Repos" / "pm_test.txt")
    pm.grant_direct(rsrc, "write", GrantLevel.SESSION)
    assert security.validate_tool_path(rsrc, "write") is None
    # Read auto-allowed in paths_allow, write still needs explicit grant
    # Path outside paths_allow without grant should still be denied
    outside = str(temp_home / "Downloads" / "outside.txt")
    err = security.validate_tool_path(outside, "read")
    assert err is not None
    assert "Access denied" in err


def test_check_granted_safety_net(perm):
    """check_granted does not crash on malformed _single_grants data."""
    resolved = perm._resolve("C:\\Temp\\corrupt.txt")
    perm._single_grants[resolved] = None
    assert perm.check_granted("C:\\Temp\\corrupt.txt", "read") is False
