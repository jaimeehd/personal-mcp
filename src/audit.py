import json
import os
import time
from collections import deque
from pathlib import Path
from typing import Any

from src.secretscanner import scan_text

# Cap on how much of a single string arg value gets content-scanned for
# secrets (2026-08-08 fix). Bounds worst-case cost on every tool call for a
# huge payload (e.g. fs_write of a multi-MB file) -- same order of magnitude
# as MAX_CAPTURE_BYTES in layer2_shell.py. A leaked credential in realistic
# tool args (env assignments, config headers, command strings) overwhelmingly
# appears well within this window; this is a cost/coverage trade-off, not a
# guarantee of catching every possible position.
_AUDIT_SCAN_CHAR_CAP = 100_000


class AuditEntry:
    def __init__(self, tool: str, args: dict[str, Any], success: bool,
                 duration_ms: float, error: str | None = None):
        self.timestamp = time.time()
        self.tool = tool
        self.args = self._sanitize(args)
        self.success = success
        self.duration_ms = round(duration_ms, 2)
        self.error = error
        # PID of the process that executed the tool. Several server processes
        # (Claude Desktop sessions, ephemeral smoke-test servers) append to
        # the same audit.json; the pid is the only reliable way to tell real
        # sessions apart from test processes when analyzing the file (1.4.72).
        self.pid = os.getpid()

    @staticmethod
    def _sanitize(args: dict[str, Any]) -> dict[str, Any]:
        """Redact sensitive data before persisting to the audit trail.

        Two independent layers, deliberately fail-closed (2026-08-08 fix,
        found via external audit): the original version only redacted by KEY
        NAME (password, token, etc.), so e.g. fs_write(content="API_KEY=sk-
        ...") persisted the full secret verbatim under the unremarkable key
        "content" -- the project's own secretscanner.py (already used for
        fs_read/sh_exec OUTPUT) existed the whole time but was never applied
        here. Now both layers run: key-name redaction first (cheap, catches
        the common case without needing the regex scanner at all), then a
        content scan on every remaining string value.

        Whole-value redaction rather than precise in-place splicing (scan_text
        gives per-match line/column, which would let a caller reconstruct a
        tighter redaction): correctness of positional redaction across
        multi-line values is easy to get subtly wrong, and this is a security
        boundary -- over-redacting an entire field is a safe failure mode, a
        partially-leaked secret from an off-by-one splice is not.

        Recursion (M-C3, auditoría 2026-08-11): nested dicts/lists are walked
        too, matching log.py::scrub_sensitive_data(). Before this, an argument
        like {"edits": [{"newText": "API_KEY=sk-..."}]} was persisted verbatim
        because only top-level string values were scanned.
        """
        return AuditEntry._redact(args)

    @staticmethod
    def _redact(value: Any) -> Any:
        sensitive_keys = {"password", "secret", "token", "key", "passphrase", "private"}
        if isinstance(value, dict):
            result: dict[str, Any] = {}
            for k, v in value.items():
                if any(s in str(k).lower() for s in sensitive_keys):
                    result[k] = "***"
                    continue
                result[k] = AuditEntry._redact(v)
            return result
        if isinstance(value, list):
            return [AuditEntry._redact(item) for item in value]
        if isinstance(value, str) and value:
            findings = scan_text(value[:_AUDIT_SCAN_CHAR_CAP])
            if findings:
                types = ", ".join(sorted({f.secret_type for f in findings}))
                return f"[REDACTED: {len(findings)} potential secret(s) - {types}]"
        return value

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "tool": self.tool,
            "args": self.args,
            "success": self.success,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "pid": self.pid,
        }


class AuditLog:
    def __init__(self, max_entries: int = 10000, persist_path: Path | None = None):
        self.max_entries = max_entries
        self.persist_path = persist_path
        self._entries: deque = deque(maxlen=max_entries)

    def record(self, tool: str, args: dict[str, Any], success: bool,
               duration_ms: float, error: str | None = None) -> AuditEntry:
        entry = AuditEntry(tool, args, success, duration_ms, error)
        self._entries.append(entry)
        if self.persist_path:
            self._append_to_disk(entry)
        return entry

    def recent(self, n: int = 50) -> list:
        return [e.to_dict() for e in list(self._entries)[-n:]]

    def stats(self) -> dict:
        total = len(self._entries)
        succeeded = sum(1 for e in self._entries if e.success)
        failed = total - succeeded
        by_tool: dict[str, int] = {}
        for e in self._entries:
            by_tool[e.tool] = by_tool.get(e.tool, 0) + 1
        return {
            "total_entries": total,
            "succeeded": succeeded,
            "failed": failed,
            "by_tool": by_tool,
            "max_entries": self.max_entries,
        }

    def _flush(self) -> None:
        """Deprecated flush helper kept for test compatibility. Entries are now flushed instantly via _append_to_disk."""

    def _append_to_disk(self, entry: AuditEntry) -> None:
        if not self.persist_path:
            return
        try:
            self.persist_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.persist_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")
        except Exception:
            pass


    @staticmethod
    def _entry_from_dict(item: dict) -> "AuditEntry | None":
        """Build an AuditEntry from a persisted dict, or None if malformed.

        Isolated per-item so one corrupt entry can be skipped without losing
        the rest of the file -- see load()'s docstring note (2026-08-08 fix).
        """
        try:
            entry = AuditEntry(
                tool=item["tool"],
                args=item.get("args", {}),
                success=item["success"],
                duration_ms=item["duration_ms"],
                error=item.get("error"),
            )
            entry.timestamp = item["timestamp"]
            # Records written before 1.4.72 have no "pid" field; None means
            # "written by an older version", never a real process id.
            entry.pid = item.get("pid")
            return entry
        except (KeyError, TypeError):
            return None

    @classmethod
    def load(cls, max_entries: int = 10000,
             persist_path: Path | None = None) -> "AuditLog":
        """Restore entries from disk (legacy array, current JSONL, or hybrid).

        Per-item recovery (2026-08-08 fix, found via external audit): the
        previous version wrapped the ENTIRE parse+load loop in one try/except,
        so a single malformed line silently dropped every entry after it (and,
        for the JSONL branch, the list-comprehension parse step failing meant
        NO entries loaded at all, not even the ones before the bad line) --
        undermining the whole point of an audit trail. Same per-line recovery
        idiom as PermissionManager._load_pending_tickets. No explicit
        [-max_entries:] slicing needed here: self._entries is a
        deque(maxlen=max_entries), which already retains only the most recent
        max_entries appended.

        Format handling (1.4.71): the file can be pure JSONL (one object per
        line, current `_append_to_disk`), a single legacy JSON array (v1.3.0
        `_flush` overwrote the whole file as one array), or -- the actual
        shape of real files -- a HYBRID: a closed legacy array followed by
        JSONL records appended after the format switch. The old code branched
        on content.startswith("[") and called json.loads() on the WHOLE
        content, which fails with "Extra data" on the first appended line and
        fell back to data=[] -- silently dropping the ENTIRE history on every
        server restart. Now every line is parsed as a sequence of raw_decode
        values: a line may hold one object, several comma-separated objects,
        or a complete legacy array (a leading "[" is stripped, a trailing "]"
        simply stops the scan). A line that fails to parse is skipped, never
        killing the records after it.
        """
        log = cls(max_entries=max_entries, persist_path=persist_path)
        if not persist_path or not persist_path.exists():
            return log
        try:
            # errors="replace" (M-C4, auditoría 2026-08-11): a single invalid UTF-8
            # byte (disk corruption, crash mid-write) used to raise UnicodeDecodeError,
            # which the blanket `except Exception` below turned into "lose the ENTIRE
            # history". Replace the bad byte and keep the rest of the lines parseable.
            content = persist_path.read_text(encoding="utf-8", errors="replace").strip()
        except Exception:
            return log
        decoder = json.JSONDecoder()
        for line in content.splitlines():
            text = line.strip().lstrip("[")
            if not text:
                continue
            pos = 0
            while True:
                while pos < len(text) and (text[pos].isspace() or text[pos] == ","):
                    pos += 1
                if pos >= len(text):
                    break
                try:
                    value, pos = decoder.raw_decode(text, pos)
                except ValueError:
                    break
                items = value if isinstance(value, list) else [value]
                for item in items:
                    entry = cls._entry_from_dict(item)
                    if entry:
                        log._entries.append(entry)
        return log

