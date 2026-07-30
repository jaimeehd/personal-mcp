import fnmatch
import hashlib
import hmac
import secrets
import time
import uuid
from enum import Enum
from pathlib import Path

from src.config import AppConfig
from src.confirm_popup import show_confirmation_code, show_confirmation_code_batch


class GrantLevel(str, Enum):
    SINGLE = "single"
    SESSION = "session"
    PERMANENT = "permanent"


class PermissionTicket:
    def __init__(self, resource: str, operation: str,
                 level: GrantLevel = GrantLevel.SINGLE,
                 ttl_seconds: int = 300,
                 resources: list[str] | None = None):
        self.id = f"perm_{uuid.uuid4().hex[:8]}"
        self.resource = resource
        # Batch ticket: resources is the real, complete list this ticket is bound
        # to. `resource` above stays a human-readable summary ("N files") for
        # to_dict()/logging - approve()/check_granted() always operate on
        # `resources` when it is set, never on the summary string.
        self.resources = resources
        self.operation = operation
        self.level = level
        self.created_at = time.time()
        self.expires_at = time.time() + ttl_seconds
        self.status = "pending"
        self.resolved_path: str | None = None
        # Generado por PermissionManager al crear el ticket; nunca se expone
        # en to_dict() ni en ningun tool MCP. Ver src/confirm_popup.py.
        self.confirm_code: str | None = None

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def to_dict(self) -> dict:
        remaining = max(0, int(self.expires_at - time.time()))
        d = {
            "id": self.id,
            "resource": self.resource,
            "operation": self.operation,
            "level": self.level.value,
            "status": self.status,
            "expires_in_seconds": remaining,
            "created_seconds_ago": int(time.time() - self.created_at),
        }
        if self.resources is not None:
            d["resources"] = self.resources
        return d


class PermissionManager:
    def __init__(self, config: AppConfig):
        self.config = config
        self._tickets: dict[str, PermissionTicket] = {}
        self._session_grants: dict[str, set[str]] = {}
        self._single_grants: dict[str, dict[str, int]] = {}
        # Clave HMAC en memoria, generada al arrancar el proceso. Nunca se
        # persiste a disco ni se expone via ningun tool: es lo que impide
        # que un agente adivine o derive el confirm_code de un ticket.
        self._confirm_secret: bytes = secrets.token_bytes(32)

    def _generate_confirm_code(self, ticket_id: str) -> str:
        digest = hmac.new(self._confirm_secret, ticket_id.encode(), hashlib.sha256).hexdigest()
        return str(int(digest[:8], 16) % 1_000_000).zfill(6)

    def request(self, resource: str, operation: str,
                level: GrantLevel = GrantLevel.SINGLE) -> PermissionTicket:
        for existing in self._tickets.values():
            if (existing.resource == resource
                    and existing.operation == operation
                    and existing.status == "pending"
                    and not existing.is_expired):
                show_confirmation_code(existing.resource, existing.operation, existing.confirm_code)
                return existing
        ticket = PermissionTicket(resource, operation, level)
        ticket.confirm_code = self._generate_confirm_code(ticket.id)
        self._tickets[ticket.id] = ticket
        show_confirmation_code(ticket.resource, ticket.operation, ticket.confirm_code)
        return ticket

    def request_batch(self, resources: list[str], operation: str,
                       level: GrantLevel = GrantLevel.SINGLE) -> PermissionTicket:
        """Same contract as request(), for a call that needs to touch several
        enumerated resources under one ticket/one confirm_code - e.g. fs_delete_batch.

        No cap on len(resources) here by design (2026-07-19, explicit requirement):
        the previous incarnation of this used rate_limit_files_per_operation (100)
        to chunk into multiple tickets, which meant multiple confirm_codes for a
        single logical delete. The actual problem that caused was the popup
        growing unreadable with N, which show_confirmation_code_batch already
        solves independently of N (bounded preview). So there is nothing left for
        a file-count cap to protect here - it would just be friction.
        """
        summary = f"{len(resources)} files"
        ticket = PermissionTicket(summary, operation, level, resources=resources)
        ticket.confirm_code = self._generate_confirm_code(ticket.id)
        self._tickets[ticket.id] = ticket
        show_confirmation_code_batch(resources, operation, ticket.confirm_code)
        return ticket

    def approve(self, ticket_id: str,
                level: GrantLevel | None = None,
                confirm_code: str | None = None) -> tuple[bool, str]:
        ticket = self._tickets.get(ticket_id)
        if not ticket:
            return False, f"Ticket not found: {ticket_id}"
        if ticket.is_expired:
            ticket.status = "expired"
            return False, f"Ticket expired: {ticket_id}"
        if ticket.status != "pending":
            return False, f"Ticket already {ticket.status}: {ticket_id}"
        if not confirm_code or not hmac.compare_digest(confirm_code, ticket.confirm_code):
            return False, "Invalid or missing confirmation code."

        ticket.status = "approved"
        grant_level = level or ticket.level
        forced_single = ticket.operation == "delete" and grant_level != GrantLevel.SINGLE
        if forced_single:
            grant_level = GrantLevel.SINGLE

        targets = ticket.resources if ticket.resources is not None else [ticket.resource]
        for target in targets:
            if grant_level == GrantLevel.SESSION:
                resolved = self._resolve(target)
                ops = self._session_grants.setdefault(resolved, set())
                ops.add(ticket.operation)
            elif grant_level == GrantLevel.SINGLE:
                resolved = self._resolve(target)
                ops = self._single_grants.setdefault(resolved, {})
                ops[ticket.operation] = 1
            elif grant_level == GrantLevel.PERMANENT:
                self._add_permanent_grant(self._resolve(target))

        msg = f"Granted {grant_level.value} access to {ticket.resource}"
        if forced_single:
            msg += " (delete is always single-use; session/permanent not allowed)"
        return True, msg

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
        resolved_norm = resolved.replace("\\", "/")
        for pattern in self.config.security.paths_deny:
            if fnmatch.fnmatch(resolved_norm, pattern.replace("\\", "/")):
                return False
        # Recursive check for session grants
        current = Path(resolved)
        while True:
            res_str = str(current)
            if res_str in self._session_grants:
                ops = self._session_grants[res_str]
                if operation in ops or (operation not in ("delete", "execute") and "*" in ops):
                    return True
            if current == current.parent:
                break
            current = current.parent
        # Single grant: consumed on first use
        if resolved in self._single_grants:
            try:
                ops = self._single_grants[resolved]
                if operation in ops or (operation not in ("delete", "execute") and "*" in ops):
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

    def pending(self) -> list[dict]:
        time.time()
        valid = []
        for ticket in self._tickets.values():
            if ticket.status == "pending" and not ticket.is_expired:
                valid.append(ticket.to_dict())
        return valid

    def revoke(self, resource: str, operation: str | None = None) -> bool:
        """Revoke grants for a resource.

        If operation is specified, only that operation is revoked (e.g. "write").
        If operation is None, ALL operations for the resource are revoked.
        security_revoke tool passes the operation from the ticket so a revoke
        call never silently drops unrelated grants on the same path.
        """
        resolved = self._resolve(resource)
        found = False
        if resolved in self._session_grants:
            if operation:
                ops = self._session_grants[resolved]
                if operation in ops:
                    ops.discard(operation)
                    if not ops:
                        del self._session_grants[resolved]
                    found = True
            else:
                del self._session_grants[resolved]
                found = True
        if resolved in self._single_grants:
            if operation:
                ops = self._single_grants[resolved]
                if operation in ops:
                    del ops[operation]
                    if not ops:
                        del self._single_grants[resolved]
                    found = True
            else:
                del self._single_grants[resolved]
                found = True
        if found:
            for ticket in self._tickets.values():
                if (ticket.resource == resource and ticket.status == "approved"
                        and (not operation or ticket.operation == operation)):
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