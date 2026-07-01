import fnmatch
import json
import os
import re
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

from src.config import AppConfig

if TYPE_CHECKING:
    from src.permissions import PermissionManager, GrantLevel


class PathNotAllowedError(PermissionError):
    pass


class CommandNotAllowedError(PermissionError):
    pass


class SecurityValidator:
    def __init__(self, config: AppConfig):
        self.config = config
        self._resolved_allowed: Optional[List[Path]] = None
        self.perm_manager: Optional["PermissionManager"] = None

    def clear_cache(self) -> None:
        self._resolved_allowed = None

    def _resolve_allowed(self) -> List[Path]:
        if self._resolved_allowed is not None:
            return self._resolved_allowed
        self._resolved_allowed = [
            Path(p).resolve() for p in self.config.security.paths_allow
        ]
        return self._resolved_allowed

    def _matched_deny_pattern(self, resolved: Path) -> Optional[str]:
        """Return the first paths_deny pattern that matches, or None."""
        candidate = str(resolved)
        for pattern in self.config.security.paths_deny:
            if fnmatch.fnmatch(candidate, pattern) or fnmatch.fnmatch(candidate, pattern.replace("\\", "\\\\")):
                return pattern
        return None

    def resolve_and_validate(self, raw_path: str) -> Path:
        given = Path(raw_path)
        if not given.is_absolute():
            raise PathNotAllowedError(f"Path must be absolute: {raw_path}")
        resolved = given.resolve()

        # Deny always wins over allow, so check it first regardless of allowlist membership.
        denied = self._matched_deny_pattern(resolved)
        if denied:
            raise PathNotAllowedError(f"Path denied by pattern '{denied}': {resolved}")

        allowed = self._resolve_allowed()
        if not any(self._is_subpath(resolved, allow) for allow in allowed):
            raise PathNotAllowedError(f"Path not in allowed directories: {resolved}")
        return resolved

    def validate_command(self, command: str) -> str:
        allowed, reason = self.config.security.commands.is_command_allowed(command)
        if not allowed:
            raise CommandNotAllowedError(reason)
        return command

    def validate_file_count(self, count: int) -> int:
        limit = self.config.security.rate_limit_files_per_operation
        if count > limit:
            raise ValueError(f"Exceeds max files per operation ({limit}): {count}")
        return count

    def is_path_allowed(self, raw_path: str) -> bool:
        try:
            self.resolve_and_validate(raw_path)
            return True
        except PathNotAllowedError:
            return False

    def validate_tool_path(self, raw_path: str, operation: str = "read") -> Optional[str]:
        """Validate a path for a tool call.

        Returns None when access is allowed (path is in paths_allow).
        Returns an error string when access is denied (no ticket flow).
        """
        try:
            self.resolve_and_validate(raw_path)
            return None
        except PathNotAllowedError as e:
            return f"Access denied: {e}"

    def request_permission(self, raw_path: str, operation: str = "read",
                           level: Optional["GrantLevel"] = None) -> str:
        if self.perm_manager:
            from src.permissions import GrantLevel
            ticket = self.perm_manager.request(raw_path, operation,
                                                level or GrantLevel.SINGLE)
            return json.dumps({
                "status": "permission_required",
                "ticket": ticket.id,
                "resource": raw_path,
                "operation": operation,
                "level": ticket.level.value,
                "message": (
                    f"Access to '{raw_path}' needs {operation} permission. "
                    f"Use fs_approve(ticket_id='{ticket.id}', level='single') "
                    f"for one-time, or level='session' for this session."
                ),
            })
        return json.dumps({
            "status": "permission_required",
            "resource": raw_path,
            "operation": operation,
            "message": f"Access to '{raw_path}' denied. No PermissionManager configured.",
        })

    # Matches Windows absolute paths using either separator (PowerShell accepts both
    # "C:\foo\bar" and "C:/foo/bar"); a backslash-only regex let forward-slash paths
    # bypass the shell command path scan entirely.
    PATH_RE = re.compile(r'(?<![\\/])([A-Za-z]:[\\/](?:[^\\/:*?"<>\s|\r\n]+[\\/])*[^\\/:*?"<>\s|\r\n]*)')

    @classmethod
    def extract_absolute_paths(cls, text: str) -> List[str]:
        return cls.PATH_RE.findall(text)

    @staticmethod
    def _is_subpath(child: Path, parent: Path) -> bool:
        try:
            child.relative_to(parent)
            return True
        except ValueError:
            return False
