import json
import time
from collections import deque
from pathlib import Path
from typing import Any, Dict, Optional


class AuditEntry:
    def __init__(self, tool: str, args: Dict[str, Any], success: bool,
                 duration_ms: float, error: Optional[str] = None):
        self.timestamp = time.time()
        self.tool = tool
        self.args = self._sanitize(args)
        self.success = success
        self.duration_ms = round(duration_ms, 2)
        self.error = error

    @staticmethod
    def _sanitize(args: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = dict(args)
        sensitive_keys = {"password", "secret", "token", "key", "passphrase", "private"}
        for k in list(sanitized.keys()):
            if any(s in k.lower() for s in sensitive_keys):
                sanitized[k] = "***"
        return sanitized

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "tool": self.tool,
            "args": self.args,
            "success": self.success,
            "duration_ms": self.duration_ms,
            "error": self.error,
        }


class AuditLog:
    def __init__(self, max_entries: int = 10000, persist_path: Optional[Path] = None):
        self.max_entries = max_entries
        self.persist_path = persist_path
        self._entries: deque = deque(maxlen=max_entries)

    def record(self, tool: str, args: Dict[str, Any], success: bool,
               duration_ms: float, error: Optional[str] = None) -> AuditEntry:
        entry = AuditEntry(tool, args, success, duration_ms, error)
        self._entries.append(entry)
        if self.persist_path and len(self._entries) % 10 == 0:
            self._flush()
        return entry

    def recent(self, n: int = 50) -> list:
        return [e.to_dict() for e in list(self._entries)[-n:]]

    def stats(self) -> dict:
        total = len(self._entries)
        succeeded = sum(1 for e in self._entries if e.success)
        failed = total - succeeded
        by_tool: Dict[str, int] = {}
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
        if not self.persist_path:
            return
        self.persist_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.persist_path, "w", encoding="utf-8") as f:
            json.dump([e.to_dict() for e in self._entries], f, ensure_ascii=False)

    @classmethod
    def load(cls, max_entries: int = 10000,
             persist_path: Optional[Path] = None) -> "AuditLog":
        log = cls(max_entries=max_entries, persist_path=persist_path)
        if persist_path and persist_path.exists():
            try:
                with open(persist_path, encoding="utf-8") as f:
                    data = json.load(f)
                for item in data[-max_entries:]:
                    entry = AuditEntry(
                        tool=item["tool"],
                        args=item.get("args", {}),
                        success=item["success"],
                        duration_ms=item["duration_ms"],
                        error=item.get("error"),
                    )
                    entry.timestamp = item["timestamp"]
                    log._entries.append(entry)
            except (json.JSONDecodeError, KeyError):
                pass
        return log
