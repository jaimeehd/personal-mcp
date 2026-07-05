import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.permissions import PermissionManager, GrantLevel, PermissionTicket
from src.config import AppConfig, SecurityConfig
from src.security import SecurityValidator


@pytest.fixture
def perm(temp_home):
    config = AppConfig(
        security=SecurityConfig(
            paths_allow=[str(temp_home / "Repos")],
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
    ok, msg = perm.approve(ticket.id)
    assert ok is True
    assert ticket.status == "approved"


def test_approve_session(perm):
    ticket = perm.request("C:\\Windows\\system.ini", "read", GrantLevel.SESSION)
    ok, msg = perm.approve(ticket.id)
    assert ok is True
    assert perm.check_granted("C:\\Windows\\system.ini", "read") is True


def test_approve_permanent(perm, temp_home):
    rsrc = str(temp_home / "outside.txt")
    ticket = perm.request(rsrc, "read", GrantLevel.PERMANENT)
    ok, msg = perm.approve(ticket.id)
    assert ok is True
    assert rsrc in perm.config.security.paths_allow


def test_deny(perm):
    ticket = perm.request("C:\\Windows\\system.ini", "read")
    ok, msg = perm.deny(ticket.id)
    assert ok is True
    assert ticket.status == "denied"


def test_approve_unknown_ticket(perm):
    ok, msg = perm.approve("perm_nonexistent")
    assert ok is False
    assert "not found" in msg


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
    perm.approve(t1.id)
    pending = perm.pending()
    assert len(pending) == 1
    assert pending[0]["id"] == t2.id


def test_revoke(perm):
    ticket = perm.request("C:\\Windows\\system.ini", "read", GrantLevel.SESSION)
    perm.approve(ticket.id)
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
    perm.approve(t3.id)
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
    perm.approve(t.id)
    ok, msg = perm.revoke_ticket(t.id)
    assert ok is True
    assert perm.check_granted("C:\\Windows\\system.ini", "read") is False


def test_grant_level_enum_values():
    assert GrantLevel.SINGLE.value == "single"
    assert GrantLevel.SESSION.value == "session"
    assert GrantLevel.PERMANENT.value == "permanent"


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
    pm.grant_direct("C:\\Repos\\project\\node_modules\\lib\\index.js", "read", GrantLevel.SESSION)
    err = security.validate_tool_path("C:\\Repos\\project\\node_modules\\lib\\index.js", "read")
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
