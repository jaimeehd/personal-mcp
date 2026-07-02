import json
import time
import uuid
import fnmatch
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set

from src.config import AppConfig


class GrantLevel(str, Enum):
    SINGLE = "single"
    SESSION = "session"
    PERMANENT = "permanent"


class PermissionTicket:
    def __init__(self, resource: str, operation: str,
                 level: GrantLevel = GrantLevel.SINGLE,
                 ttl_seconds: int = 300):
        self.id = f"perm_{uuid.uuid4().hex[:8]}"
        self.resource = resource
        self.operation = operation
        self.level = level
        self.created_at = time.time()
        self.expires_at = time.time() + ttl_seconds
        self.status = "pending"
        self.resolved_path: Optional[str] = None

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def to_dict(self) -> dict:
        remaining = max(0, int(self.expires_at - time.time()))
        return {
            "id": self.id,
            "resource": self.resource,
            "operation": self.operation,
            "level": self.level.value,
            "status": self.status,
            "expires_in_seconds": remaining,
            "created_seconds_ago": int(time.time() - self.created_at),
        }


class PermissionManager:
    def __init__(self, config: AppConfig):
        self.config = config
        self._tickets: Dict[str, PermissionTicket] = {}
        self._session_grants: Dict[str, Set[str]] = {}
        self._single_grants: Dict[str, Dict[str, int]] = {}

    def request(self, resource: str, operation: str,
                level: GrantLevel = GrantLevel.SINGLE) -> PermissionTicket:
        for existing in self._tickets.values():
            if (existing.resource == resource
                    and existing.operation == operation
                    and existing.status == "pending"
                    and not existing.is_expired):
                return existing
        ticket = PermissionTicket(resource, operation, level)
        self._tickets[ticket.id] = ticket
        return ticket

    def approve(self, ticket_id: str,
                level: Optional[GrantLevel] = None) -> tuple[bool, str]:
        ticket = self._tickets.get(ticket_id)
        if not ticket:
            return False, f"Ticket not found: {ticket_id}"
        if ticket.is_expired:
            ticket.status = "expired"
            return False, f"Ticket expired: {ticket_id}"
        if ticket.status != "pending":
            return False, f"Ticket already {ticket.status}: {ticket_id}"

        ticket.status = "approved"
        grant_level = level or ticket.level

        if grant_level == GrantLevel.SESSION:
            resolved = self._resolve(ticket.resource)
            ops = self._session_grants.setdefault(resolved, set())
            ops.add(ticket.operation)
        elif grant_level == GrantLevel.SINGLE:
            resolved = self._resolve(ticket.resource)
            ops = self._single_grants.setdefault(resolved, {})
            ops[ticket.operation] = 1
        elif grant_level == GrantLevel.PERMANENT:
            self._add_permanent_grant(self._resolve(ticket.resource))

        return True, f"Granted {grant_level.value} access to {ticket.resource}"

    def deny(self, ticket_id: str) -> tuple[bool, str]:
        ticket = self._tickets.get(ticket_id)
        if not ticket:
            return False, f"Ticket not found: {ticket_id}"
        ticket.status = "denied"
        return True, f"Denied access to {ticket.resource}"

    def _resolve(self, resource: str) -> str:
        return str(Path(resource).resolve())

    def grant_direct(self, resource: str, operation: str = "read",
                     level: GrantLevel = GrantLevel.SESSION) -> PermissionTicket:
        ticket = PermissionTicket(resource, operation, level, ttl_seconds=86400)
        ticket.status = "approved"
        self._tickets[ticket.id] = ticket
        resolved = self._resolve(resource)
        if level == GrantLevel.SESSION:
            ops = self._session_grants.setdefault(resolved, set())
            ops.add(operation)
        elif level == GrantLevel.SINGLE:
            ops = self._single_grants.setdefault(resolved, {})
            ops[operation] = 1
        elif level == GrantLevel.PERMANENT:
            self._add_permanent_grant(resolved)
        return ticket

    def check_granted(self, resource: str, operation: str, consume: bool = True) -> bool:
        resolved = self._resolve(resource)
        # A deny pattern always wins, even over an existing session/permanent grant
        # or a resource that happens to live under data_dir/paths_allow.
        for pattern in self.config.security.paths_deny:
            if fnmatch.fnmatch(resolved, pattern) or fnmatch.fnmatch(resolved, pattern.replace("\\", "\\\\")):
                return False
        # Recursive check for session grants
        current = Path(resolved)
        while True:
            res_str = str(current)
            if res_str in self._session_grants:
                ops = self._session_grants[res_str]
                if operation in ops or "*" in ops:
                    return True
            if current == current.parent:
                break
            current = current.parent
        # Single grant: consumed on first use
        if resolved in self._single_grants:
            try:
                ops = self._single_grants[resolved]
                if operation in ops or "*" in ops:
                    if not consume:
                        return True
                    actual_op = operation if operation in ops else "*"
                    remaining = ops[actual_op] - 1
                    if remaining <= 0:
                        del ops[actual_op]
                        if not ops:
                            del self._single_grants[resolved]
                    else:
                        ops[actual_op] = remaining
                    return True
            except Exception:
                return False
        try:
            Path(resolved).relative_to(Path(self.config.data_dir).resolve())
            return True
        except ValueError:
            pass
        return False

    def pending(self) -> List[dict]:
        now = time.time()
        valid = []
        for ticket in self._tickets.values():
            if ticket.status == "pending" and not ticket.is_expired:
                valid.append(ticket.to_dict())
        return valid

    def revoke(self, resource: str) -> bool:
        resolved = self._resolve(resource)
        found = False
        if resolved in self._session_grants:
            del self._session_grants[resolved]
            found = True
        if resolved in self._single_grants:
            del self._single_grants[resolved]
            found = True
        if found:
            for ticket in self._tickets.values():
                if ticket.resource == resource and ticket.status == "approved":
                    ticket.status = "revoked"
            return True
        return False

    def revoke_ticket(self, ticket_id: str) -> tuple[bool, str]:
        ticket = self._tickets.get(ticket_id)
        if not ticket:
            return False, f"Ticket not found: {ticket_id}"
        ticket.status = "revoked"
        resolved = self._resolve(ticket.resource)
        self._session_grants.pop(resolved, None)
        self._single_grants.pop(resolved, None)
        return True, f"Revoked: {ticket.resource}"

    def _add_permanent_grant(self, resource: str) -> None:
        resolved = str(Path(resource).resolve())
        if resolved not in self.config.security.paths_allow:
            self.config.security.paths_allow.append(resolved)
            self.config.save()

    def _cleanup_expired(self) -> None:
        expired = [tid for tid, t in self._tickets.items() if t.is_expired and t.status == "pending"]
        for tid in expired:
            self._tickets[tid].status = "expired"

    def stats(self) -> dict:
        total = len(self._tickets)
        pending = sum(1 for t in self._tickets.values() if t.status == "pending" and not t.is_expired)
        approved = sum(1 for t in self._tickets.values() if t.status == "approved")
        denied = sum(1 for t in self._tickets.values() if t.status == "denied")
        session_grants = len(self._session_grants)
        return {
            "total_tickets": total,
            "pending": pending,
            "approved": approved,
            "denied": denied,
            "session_grants": session_grants,
        }
