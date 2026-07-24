import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.audit import AuditLog


@pytest.fixture
def audit_log(tmp_path):
    log = AuditLog(max_entries=100, persist_path=tmp_path / "audit.json")
    for i in range(10):
        log.record(f"tool_{i}", {"arg": i}, i % 2 == 0, float(i * 10))
    return log


def test_record(audit_log):
    entry = audit_log.record("test_tool", {"key": "value"}, True, 5.0)
    assert entry.tool == "test_tool"
    assert entry.success is True
    assert entry.duration_ms == 5.0


def test_recent(audit_log):
    recent = audit_log.recent(5)
    assert len(recent) == 5


def test_stats(audit_log):
    stats = audit_log.stats()
    assert stats["total_entries"] == 10
    assert stats["succeeded"] == 5
    assert stats["failed"] == 5


def test_max_entries(tmp_path):
    log = AuditLog(max_entries=5, persist_path=tmp_path / "audit2.json")
    for i in range(20):
        log.record(f"tool_{i}", {}, True, 0)
    assert len(log._entries) == 5
    assert log._entries[-1].tool == "tool_19"


def test_persistence(tmp_path):
    path = tmp_path / "audit_persist.json"
    log1 = AuditLog(max_entries=100, persist_path=path)
    log1.record("persist_test", {}, True, 1.0)
    log1._flush()

    log2 = AuditLog.load(max_entries=100, persist_path=path)
    assert len(log2._entries) == 1
    assert log2._entries[0].tool == "persist_test"


def test_sensitive_args_redacted(audit_log):
    entry = audit_log.record("login", {"username": "admin", "password": "secret123"}, True, 1.0)
    assert entry.args.get("password") == "***"
    assert entry.args.get("username") == "admin"
