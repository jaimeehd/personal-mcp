import os
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


# --- content-based secret scan in _sanitize (2026-08-08 fix) ---
# Regression for a bug found via external audit: only the ARG KEY NAME was
# checked (password, token, etc.) -- a secret inside a value under an
# unremarkable key (e.g. fs_write(content="API_KEY=...")) was persisted
# verbatim, even though secretscanner.py (already used for fs_read/sh_exec
# output) would have caught it immediately.

def test_secret_in_content_value_is_redacted(audit_log):
    entry = audit_log.record(
        "fs_write",
        {"path": "C:\\Users\\usuario\\Repos\\.env", "content": "AKIAABCDEFGHIJKLMNOP"},
        True, 1.0,
    )
    assert entry.args["content"] != "AKIAABCDEFGHIJKLMNOP"
    assert "REDACTED" in entry.args["content"]
    assert entry.args["path"] == "C:\\Users\\usuario\\Repos\\.env"


def test_plain_content_value_not_touched(audit_log):
    entry = audit_log.record(
        "fs_write",
        {"path": "C:\\Users\\usuario\\Repos\\readme.md", "content": "just some normal text"},
        True, 1.0,
    )
    assert entry.args["content"] == "just some normal text"



# --- load() per-item recovery (2026-08-08 fix) ---

def test_load_skips_corrupt_line_keeps_rest(tmp_path):
    path = tmp_path / "audit_corrupt.json"
    good1 = '{"timestamp": 1.0, "tool": "before", "args": {}, "success": true, "duration_ms": 1.0, "error": null}'
    bad = "not valid json at all {{{"
    good2 = '{"timestamp": 2.0, "tool": "after", "args": {}, "success": true, "duration_ms": 1.0, "error": null}'
    path.write_text(good1 + "\n" + bad + "\n" + good2 + "\n", encoding="utf-8")

    log = AuditLog.load(max_entries=100, persist_path=path)
    tools = [e.tool for e in log._entries]
    assert tools == ["before", "after"]


def test_load_skips_entry_missing_required_key(tmp_path):
    path = tmp_path / "audit_missing_key.json"
    good = '{"timestamp": 1.0, "tool": "ok", "args": {}, "success": true, "duration_ms": 1.0, "error": null}'
    missing_success = '{"timestamp": 2.0, "tool": "broken", "args": {}, "duration_ms": 1.0, "error": null}'
    path.write_text(good + "\n" + missing_success + "\n", encoding="utf-8")

    log = AuditLog.load(max_entries=100, persist_path=path)
    tools = [e.tool for e in log._entries]
    assert tools == ["ok"]


# --- M-C3 (auditoría 2026-08-11): nested dict/list redaction ---

def test_nested_dict_secret_is_redacted(audit_log):
    entry = audit_log.record(
        "fs_edit_advanced",
        {"edits": [{"oldText": "a", "newText": "AKIAABCDEFGHIJKLMNOP"}]},
        True, 1.0,
    )
    new_text = entry.args["edits"][0]["newText"]
    assert new_text != "AKIAABCDEFGHIJKLMNOP"
    assert "REDACTED" in new_text


def test_nested_list_secret_is_redacted(audit_log):
    entry = audit_log.record(
        "fs_write",
        {"batch": ["normal", "AKIAABCDEFGHIJKLMNOP"]},
        True, 1.0,
    )
    assert "AKIAABCDEFGHIJKLMNOP" not in str(entry.args)
    assert "REDACTED" in entry.args["batch"][1]


# --- M-C4 (auditoría 2026-08-11): invalid UTF-8 byte no longer wipes history ---

def test_load_invalid_utf8_byte_keeps_valid_lines(tmp_path):
    path = tmp_path / "audit_bad_utf8.json"
    good1 = '{"timestamp": 1.0, "tool": "first", "args": {}, "success": true, "duration_ms": 1.0, "error": null}'
    good2 = '{"timestamp": 2.0, "tool": "second", "args": {}, "success": true, "duration_ms": 1.0, "error": null}'
    raw = (good1 + "\n").encode() + b"\xff\xfe\xfd\n" + (good2 + "\n").encode()
    path.write_bytes(raw)

    log = AuditLog.load(max_entries=100, persist_path=path)
    tools = [e.tool for e in log._entries]
    assert tools == ["first", "second"]


# --- 1.4.71: hybrid legacy-array + JSONL recovery ---
# Real files (from the 2026-07 v1.3.0 era) are a closed JSON array written by
# the old whole-file `_flush`, followed by JSONL records appended by the
# current `_append_to_disk`. json.loads() on the whole content fails with
# "Extra data", and the old load() then returned an EMPTY log -- every server
# restart silently dropped the entire audit history.

def test_load_hybrid_legacy_array_plus_jsonl(tmp_path):
    path = tmp_path / "audit_hybrid.json"
    rec = ('{{"timestamp": {t}.0, "tool": "tool_{t}", "args": {{}}, '
           '"success": true, "duration_ms": 1.0, "error": null}}')
    legacy_array = "[" + ",".join(rec.format(t=i) for i in range(3)) + "]"
    jsonl_tail = "\n".join(rec.format(t=i) for i in range(3, 5)) + "\n"
    path.write_text(legacy_array + "\n" + jsonl_tail, encoding="utf-8")

    log = AuditLog.load(max_entries=100, persist_path=path)
    tools = [e.tool for e in log._entries]
    assert tools == ["tool_0", "tool_1", "tool_2", "tool_3", "tool_4"]


def test_load_hybrid_array_with_trailing_comma_then_jsonl(tmp_path):
    path = tmp_path / "audit_hybrid_comma.json"
    rec = ('{{"timestamp": {t}.0, "tool": "tool_{t}", "args": {{}}, '
           '"success": true, "duration_ms": 1.0, "error": null}}')
    legacy_array = "[" + ",".join(rec.format(t=i) for i in range(2)) + "],"
    path.write_text(legacy_array + "\n" + rec.format(t=2) + "\n", encoding="utf-8")

    log = AuditLog.load(max_entries=100, persist_path=path)
    assert [e.tool for e in log._entries] == ["tool_0", "tool_1", "tool_2"]


def test_load_unclosed_legacy_array_keeps_following_jsonl(tmp_path):
    path = tmp_path / "audit_unclosed.json"
    rec = ('{{"timestamp": {t}.0, "tool": "tool_{t}", "args": {{}}, '
           '"success": true, "duration_ms": 1.0, "error": null}}')
    unclosed = "[" + ",".join(rec.format(t=i) for i in range(2))  # crash mid-flush
    path.write_text(unclosed + "\n" + rec.format(t=2) + "\n", encoding="utf-8")

    log = AuditLog.load(max_entries=100, persist_path=path)
    # Complete records inside the unclosed array are recovered too (raw_decode
    # never needs the closing "]"); only a truncated record would be dropped.
    assert [e.tool for e in log._entries] == ["tool_0", "tool_1", "tool_2"]


def test_load_truncated_last_record_keeps_following_jsonl(tmp_path):
    path = tmp_path / "audit_truncated.json"
    rec = ('{{"timestamp": {t}.0, "tool": "tool_{t}", "args": {{}}, '
           '"success": true, "duration_ms": 1.0, "error": null}}')
    truncated = "[" + rec.format(t=0)[:40]
    path.write_text(truncated + "\n" + rec.format(t=2) + "\n", encoding="utf-8")

    log = AuditLog.load(max_entries=100, persist_path=path)
    assert [e.tool for e in log._entries] == ["tool_2"]


def test_load_legacy_empty_array(tmp_path):
    path = tmp_path / "audit_empty_array.json"
    path.write_text("[]\n", encoding="utf-8")

    log = AuditLog.load(max_entries=100, persist_path=path)
    assert len(log._entries) == 0


# --- 1.4.72: pid del proceso en cada registro ---
# audit.json es compartido por varios procesos del servidor (sesiones reales
# de Claude Desktop y servidores efimeros que arrancan los smoke tests). El
# pid del proceso que ejecuto la tool permite separar la actividad real de
# la de pruebas al analizar el archivo.

def test_record_captures_pid(tmp_path):
    path = tmp_path / "audit_pid.json"
    log = AuditLog(max_entries=100, persist_path=path)
    log.record("fs_read", {"path": "C:\\Users\\usuario\\Repos"}, True, 1.0)

    assert log._entries[-1].pid == os.getpid()
    persisted = path.read_text(encoding="utf-8")
    assert '"pid":' in persisted


def test_load_preserves_persisted_pid(tmp_path):
    path = tmp_path / "audit_pid_roundtrip.json"
    path.write_text(
        '{"timestamp": 1.0, "tool": "fs_read", "args": {}, "success": true, '
        '"duration_ms": 1.0, "error": null, "pid": 12345}\n',
        encoding="utf-8",
    )

    log = AuditLog.load(max_entries=100, persist_path=path)
    assert log._entries[0].pid == 12345


def test_legacy_record_without_pid_loads_none(tmp_path):
    path = tmp_path / "audit_pid_legacy.json"
    path.write_text(
        '{"timestamp": 1.0, "tool": "fs_read", "args": {}, "success": true, '
        '"duration_ms": 1.0, "error": null}\n',
        encoding="utf-8",
    )

    log = AuditLog.load(max_entries=100, persist_path=path)
    assert log._entries[0].pid is None

