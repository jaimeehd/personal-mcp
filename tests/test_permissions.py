import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.permissions import PermissionManager, GrantLevel, PermissionTicket
from src.config import AppConfig, SecurityConfig


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
