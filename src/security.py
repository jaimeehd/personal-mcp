import fnmatch
import json
import os
import re
import shutil
import time
from collections import deque
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from src.config import AppConfig

if TYPE_CHECKING:
    from src.permissions import GrantLevel, PermissionManager


class PathNotAllowedError(PermissionError):
    pass


class PermissionRequiredError(PathNotAllowedError):
    def __init__(self, path: str, operation: str):
        self.path = path
        self.operation = operation
        super().__init__(f"Access to '{path}' needs {operation} permission")


class CommandNotAllowedError(PermissionError):
    pass


class RateLimitError(Exception):
    pass


class SecurityValidator:
    def __init__(self, config: AppConfig):
        self.config = config
        self._resolved_allowed: list[Path] | None = None
        self.perm_manager: PermissionManager | None = None
        self._rate_limiters: dict[str, deque] = {}

    def _check_rate_limit(self, operation: str) -> None:
        limit = self.config.security.rate_limit_commands_per_minute
        if limit <= 0:
            return
        if operation not in self._rate_limiters:
            self._rate_limiters[operation] = deque()
        limiter = self._rate_limiters[operation]
        now = time.time()
        cutoff = now - 60
        while limiter and limiter[0] < cutoff:
            limiter.popleft()
        if len(limiter) >= limit:
            raise RateLimitError(f"Rate limit exceeded: {limit} {operation} operations per minute")
        limiter.append(now)

    def clear_cache(self) -> None:
        self._resolved_allowed = None

    def _resolve_allowed(self) -> list[Path]:
        if self._resolved_allowed is not None:
            return self._resolved_allowed
        self._resolved_allowed = [
            Path(p).resolve() for p in self.config.security.paths_allow
        ]
        return self._resolved_allowed

    def _matched_deny_pattern(self, resolved: Path) -> str | None:
        """Return the first paths_deny pattern that matches, or None."""
        candidate = str(resolved).replace("\\", "/")
        for pattern in self.config.security.paths_deny:
            normalized = pattern.replace("\\", "/")
            if fnmatch.fnmatch(candidate, normalized):
                return pattern
        return None

    def _deny_exception_applies(self, resolved: Path, operation: str) -> bool:
        """Narrow, explicit exception to a paths_deny match (e.g. **\\bin\\**),
        for legitimate needs like verifying a project's build output (.NET, etc.)
        without opening bin/obj in general -- that stays blocked for everything
        else (node_modules, vendored binaries, etc.).

        Only ever applies to read operations (fs_find/fs_read/fs_list/fs_tree),
        never to write/delete/execute. Both paths_deny_exceptions (patterns) and
        paths_deny_exception_extensions default to a safe, narrow set -- see
        SecurityConfig in config.py.

        Directories vs. files (fixed 2026-07-19): fs_find/fs_list/fs_tree validate
        the SEARCH DIRECTORY itself (e.g. "...\\bin\\Release"), not each file found
        inside it -- a directory has no file extension, so an extension-only check
        could never let those tools traverse into an excepted bin/obj folder in the
        first place. For a directory, matching an exceptions pattern is enough
        (this only reveals names/sizes/dates, not file content). For a file, the
        extension check still applies -- fs_read on anything other than
        .dll/.exe/.pdb inside that same folder stays blocked.
        """
        if operation != "read":
            return False
        if not resolved.is_dir() and resolved.suffix.lower() not in self.config.security.paths_deny_exception_extensions:
            return False
        candidate = str(resolved).replace("\\", "/")
        for pattern in self.config.security.paths_deny_exceptions:
            normalized = pattern.replace("\\", "/")
            if fnmatch.fnmatch(candidate, normalized):
                return True
        return False

    def resolve_and_validate(self, raw_path: str, operation: str = "read",
                             deny_operation: str | None = None) -> Path:
        given = Path(raw_path)
        if not given.is_absolute():
            raise PathNotAllowedError(f"Path must be absolute: {raw_path}")
        resolved = given.resolve()
        allowed = self._resolve_allowed()
        data_dir_resolved = Path(self.config.data_dir).resolve()

        # Resolve symlinks/junctions to their real target
        real_str = os.path.realpath(str(resolved))
        real_path = Path(real_str)
        if str(real_path) != str(resolved):
            in_allowed = any(self._is_subpath(real_path, allow) for allow in allowed)
            in_data = self._is_subpath(real_path, data_dir_resolved)
            if not (in_allowed or in_data):
                raise PathNotAllowedError(
                    f"Symlink target not in allowed directories: {real_path}"
                )
            resolved = real_path

        # Deny always wins, even over session/permanent grants -- except for the
        # narrow, explicit read-only build-artifact exception (see
        # _deny_exception_applies). deny_operation lets callers run the deny check
        # under the REAL operation while keeping the grant resolution at "read"
        # (A-5, auditoría 2026-08-11): the read-only deny exception must never
        # apply to a destructive operation like delete.
        deny_op = deny_operation if deny_operation is not None else operation
        denied = self._matched_deny_pattern(resolved)
        if denied and not self._deny_exception_applies(resolved, deny_op):
            raise PathNotAllowedError(f"Path denied by pattern '{denied}': {resolved}")

        # Check static allowlist: MUST be inside paths_allow or data_dir
        in_allowed_paths = any(self._is_subpath(resolved, allow) for allow in allowed)
        in_data_dir = self._is_subpath(resolved, data_dir_resolved)

        if not (in_allowed_paths or in_data_dir):
            raise PathNotAllowedError(f"Path not in allowed directories: {resolved}")

        # If inside data_dir, always allow without tickets (internal state)
        if in_data_dir:
            return resolved

        # Otherwise, inside paths_allow.
        # Read operations allowed directly (no tickets on hot path for reads).
        # Write operations require explicit grant via perm_manager.
        if operation == "read":
            return resolved
        if self.perm_manager and self.perm_manager.check_granted(str(resolved), operation):
            return resolved

        raise PermissionRequiredError(str(resolved), operation)

    def validate_command(self, command: str) -> str:
        allowed, reason = self.config.security.commands.is_command_allowed(command)
        if not allowed:
            raise CommandNotAllowedError(reason)
        # M-S6 (auditoría 2026-08-11): rate_limit_commands_per_minute existed in
        # config but was only ever enforced via check_granted(), so sh_exec /
        # sh_session_send / sh_spawn could fire unlimited commands per minute.
        # Enforce it here (the shared whitelist gate for those three tools).
        try:
            self._check_rate_limit("shell")
        except RateLimitError as e:
            raise CommandNotAllowedError(str(e))
        return command

    def validate_shell_execution(self, command: str) -> str | None:
        """Gate general-purpose interpreters (config.security.commands.approval_required_prefix)
        behind an explicit execute ticket, on top of the existing allow_prefix whitelist.
        Also scans Python script targets using AST to warn against network/destructive IO risks.

        Returns None when execution is allowed. Returns a ticket JSON string (same
        contract as validate_tool_path) when an interpreter segment needs approval.
        Empty approval_required_prefix (the default) makes this a no-op.
        """
        prefixes = self.config.security.commands.approval_required_prefix
        if not prefixes:
            return None
        from src.script_analyzer import analyze_javascript_script, analyze_python_script
        from src.shell_resolver import split_command_segments
        prefixes_lower = {p.lower() for p in prefixes}
        for segment in (split_command_segments(command) or [command]):
            words = segment.strip().split()
            if not words:
                continue
            first_word_clean = Path(words[0]).stem.lower()
            if first_word_clean not in prefixes_lower:
                continue
            exe_path = shutil.which(words[0]) or words[0]

            # If target is python or node and a script path is provided, analyze the script
            if len(words) > 1:
                script_path = Path(words[1].strip('"\''))
                if script_path.exists():
                    ext = script_path.suffix.lower()
                    findings = []
                    if first_word_clean == "python" and ext == ".py":
                        try:
                            code = script_path.read_text(encoding="utf-8", errors="replace")
                            findings = analyze_python_script(code)
                        except Exception:
                            pass
                    elif first_word_clean == "node" and ext in (".js", ".ts", ".mjs", ".cjs"):
                        try:
                            code = script_path.read_text(encoding="utf-8", errors="replace")
                            findings = analyze_javascript_script(code)
                        except Exception:
                            pass

                    if findings:
                        risk_summary = "; ".join(f"[{f.category}] L{f.line}: {f.description}" for f in findings)
                        if self.perm_manager and self.perm_manager.check_granted(exe_path, "execute"):
                            continue
                        ticket = self.request_permission(exe_path, "execute")
                        # Fix 2026-08-08: the ticket's resource MUST be the clean
                        # exe_path — approve() resolves it as the grant key, and
                        # every check_granted() call afterward looks up the clean
                        # path. A ticket created for an annotated string like
                        # "C:\...\python.exe (Script Risks Detected: ...)" would
                        # resolve to a bogus, never-matching path: check_granted()
                        # would never find that grant again, so approving a risky
                        # script permanently would never actually grant access
                        # (previously undiscovered — found via external audit).
                        # The risk summary is surfaced in a separate warning field
                        # instead of mangling the resource key.
                        try:
                            payload = json.loads(ticket)
                            payload["script_risk_warning"] = risk_summary
                            return json.dumps(payload)
                        except (ValueError, TypeError):
                            return ticket


            if self.perm_manager and self.perm_manager.check_granted(exe_path, "execute"):
                continue
            return self.request_permission(exe_path, "execute")
        return None


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

    def validate_tool_path(self, raw_path: str, operation: str = "read") -> str | None:
        """Validate a path for a tool call.

        Returns None when access is allowed.
        Returns a ticket JSON string if access needs approval.
        Returns an error string when access is strictly denied.
        """
        try:
            self._check_rate_limit(operation)
        except RateLimitError as e:
            return str(e)
        try:
            self.resolve_and_validate(raw_path, operation)
            return None
        except PermissionRequiredError as e:
            return self.request_permission(e.path, e.operation)
        except PathNotAllowedError as e:
            return f"Access denied: {e}"

    def validate_tool_paths_batch(self, raw_paths: list[str], operation: str = "delete") -> str | None:
        """Batch counterpart to validate_tool_path (2026-07-19, for fs_delete_batch).

        Validates every path in one pass; if any of them still needs a grant,
        requests ONE ticket/confirm_code covering the whole list instead of one
        per path (PermissionManager.request_batch). No cap on len(raw_paths) -
        see request_batch()'s docstring for why that's intentional here.

        Returns None when every path already has a grant (or the operation is
        "read", which never needs one - same rule as resolve_and_validate).
        Returns an error string on the first path that's hard-denied (deny
        pattern match, or outside paths_allow/data_dir) - that's a config-level
        rejection, not something a ticket can fix, so it short-circuits the
        whole batch rather than silently dropping just that one path.
        Returns a ticket JSON string if a batch grant is needed.
        """
        try:
            self._check_rate_limit(operation)
        except RateLimitError as e:
            return str(e)

        resolved_paths: list[str] = []
        for raw_path in raw_paths:
            try:
                # operation="read" keeps the grant resolution read-only (no single
                # grant is consumed here -- the batch peek/consume below owns that),
                # while deny_operation=<real op> makes the read-only deny exception
                # NOT apply to destructive ops (A-5, auditoría 2026-08-11).
                resolved = self.resolve_and_validate(raw_path, "read", deny_operation=operation)
            except PathNotAllowedError as e:
                return f"Access denied: {e}"
            resolved_paths.append(str(resolved))

        if operation == "read":
            return None

        if self.perm_manager:
            # Peek first (consume=False) across the WHOLE set before consuming
            # anything - if path 3 of 5 lacks a grant, we must not have already
            # burned the single-use grants on paths 1-2 just from checking them.
            all_granted = all(
                self.perm_manager.check_granted(p, operation, consume=False)
                for p in resolved_paths
            )
            if all_granted:
                for p in resolved_paths:
                    self.perm_manager.check_granted(p, operation, consume=True)
                return None

        if not self.perm_manager:
            return json.dumps({
                "status": "permission_required",
                "resource": f"{len(resolved_paths)} files",
                "operation": operation,
                "message": "Access denied. No PermissionManager configured.",
            })

        from src.permissions import GrantLevel
        ticket = self.perm_manager.request_batch(resolved_paths, operation, GrantLevel.SINGLE)
        return json.dumps({
            "status": "permission_required",
            "ticket": ticket.id,
            "resource": f"{len(resolved_paths)} files",
            "resources": resolved_paths,
            "operation": operation,
            "level": ticket.level.value,
            "message": (
                f"Access to {len(resolved_paths)} files needs {operation} permission. "
                f"A confirmation code was shown on your screen - it is NOT visible to "
                f"this agent. Use fs_approve(ticket_id='{ticket.id}', "
                f"confirm_code='<code from the popup>', level='single') to authorize "
                f"all of them at once."
            ),
        })

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
                    f"A confirmation code was shown on your screen - it is NOT visible "
                    f"to this agent. Use fs_approve(ticket_id='{ticket.id}', "
                    f"confirm_code='<code from the popup>', level='single') "
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
    def extract_absolute_paths(cls, text: str) -> list[str]:
        return cls.PATH_RE.findall(text)

    _TRAVERSAL_RE = re.compile(r'(?:\.\.[\\/]|~[\\/])[^\s|;&<>`"\']*')

    @classmethod
    def extract_traversal_paths(cls, text: str) -> list[str]:
        """Detect relative path-traversal (`..\\x`/`../x`) and home-relative
        (`~/x`) tokens in a shell command.

        `extract_absolute_paths()` only catches drive-letter paths, so a command
        could reach a denied location with a relative path (A-3, auditoría
        2026-08-11). These can't be reliably resolved to an absolute path here
        (the shell's actual cwd isn't knowable at validation time), so they are
        detected and rejected rather than silently allowed. `git log ..HEAD` and
        `git log HEAD~1` are NOT flagged: the regex only matches `..`/`~` when
        followed by a path separator, not by a ref name or digit.
        """
        return cls._TRAVERSAL_RE.findall(text)

    @staticmethod
    def _is_subpath(child: Path, parent: Path) -> bool:
        try:
            child.relative_to(parent)
            return True
        except ValueError:
            return False
