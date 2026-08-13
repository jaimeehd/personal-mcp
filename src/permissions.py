import fnmatch
import hashlib
import hmac
import json
import secrets
import time
import uuid
from enum import Enum
from pathlib import Path

from src.config import AppConfig
from src.confirm_popup import show_confirmation_code, show_confirmation_code_batch
from src.log import get_logger

logger = get_logger("permissions")


class GrantLevel(str, Enum):
    SINGLE = "single"
    SESSION = "session"
    PERMANENT = "permanent"


class PermissionTicket:
    def __init__(self, resource: str, operation: str,
                 level: GrantLevel = GrantLevel.SINGLE,
                 ttl_seconds: int = 300,
                 resources: list[str] | None = None,
                 restored: bool = False):
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
        # True cuando el ticket fue reconstruido desde tickets.jsonl tras un
        # reinicio (v1.4.41). Su confirm_code fue regenerado con un secret HMAC
        # nuevo, distinto del proceso anterior: approve() re-muestra el popup si
        # recibe el codigo viejo pre-reinicio, en vez de dejar el ticket muerto.
        self.restored = restored

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
    # Nombre del journal de persistencia de tickets pendientes (en data_dir).
    # Solo metadatos no sensibles: id, resources, operation, level, expiracion.
    # NUNCA confirm_code ni el secret HMAC - ambos son locales al proceso (ver
    # _load_pending_tickets). Append-only JSONL, como audit.json.
    TICKETS_FILE = "tickets.jsonl"

    # Limite de intentos fallidos de confirm_code antes de auto-denegar el
    # ticket. Mitiga fuerza bruta sobre el codigo de 6 digitos (~1M
    # combinaciones): con TTL de 300s, un agente tendria tiempo para intentar
    # ~300k codigos si no hubiera limite. Con limite=10, eso baja a 10.
    # Contador es por-proceso (cada proceso tiene su propio secret HMAC, asi
    # que el codigo cambia entre procesos y el ataque no se acumula).
    _MAX_APPROVE_ATTEMPTS = 10

    def __init__(self, config: AppConfig):
        self.config = config
        # Back-reference al SecurityValidator (opcional, seteado por server.py y
        # los fixtures wired). Se usa para invalidar su cache de paths_allow
        # cuando un grant permanente agrega una ruta (M-F10, auditoría 2026-08-11).
        self.security = None
        self._tickets: dict[str, PermissionTicket] = {}
        self._session_grants: dict[str, set[str]] = {}
        self._single_grants: dict[str, dict[str, int]] = {}
        # Contador de intentos fallidos de confirm_code por ticket. No se
        # persiste: cada proceso tiene su propio secret HMAC (y por tanto su
        # propio confirm_code), asi que el conteo no es transferible.
        self._failed_approve_attempts: dict[str, int] = {}
        # Clave HMAC en memoria, generada al arrancar el proceso. Nunca se
        # persiste a disco ni se expone via ningun tool: es lo que impide
        # que un agente adivine o derive el confirm_code de un ticket.
        self._confirm_secret: bytes = secrets.token_bytes(32)
        self._load_pending_tickets()

    def _tickets_path(self) -> Path:
        return Path(self.config.data_dir) / self.TICKETS_FILE

    # M-C5 (auditoría 2026-08-11): tickets.jsonl grew unbounded — every status
    # transition appended a line and nothing ever removed resolved/expired
    # tickets. Rewrite the file (keeping only still-pending, non-expired tickets)
    # once it grows past this size.
    _TICKETS_COMPACT_BYTES = 1_000_000

    def _compact_tickets(self) -> None:
        """Rewrite tickets.jsonl keeping only still-relevant pending tickets."""
        path = self._tickets_path()
        if not path.exists():
            return
        latest: dict[str, dict] = {}
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                    except ValueError:
                        continue
                    if item.get("id"):
                        latest[item["id"]] = item
        except Exception:
            return
        now = time.time()
        keep = [
            item for item in latest.values()
            if item.get("status") == "pending"
            and now <= float(item.get("expires_at") or 0)
        ]
        try:
            with open(path, "w", encoding="utf-8") as f:
                for item in keep:
                    f.write(json.dumps(item, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def _persist_ticket(self, ticket: PermissionTicket, status: str | None = None) -> None:
        """Append ticket metadata to tickets.jsonl (append-only JSONL).

        Never writes confirm_code or the HMAC secret. The loader keeps the LAST
        line per ticket id, so a later resolution line (approved/denied/expired/
        revoked) supersedes the creation line. A write failure is tolerated:
        persistence is best-effort and must never break the in-memory flow.
        """
        try:
            path = self._tickets_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "id": ticket.id,
                    "resource": ticket.resource,
                    "resources": ticket.resources,
                    "operation": ticket.operation,
                    "level": ticket.level.value,
                    "created_at": ticket.created_at,
                    "expires_at": ticket.expires_at,
                    "status": status or ticket.status,
                }, ensure_ascii=False) + "\n")
            if path.stat().st_size > self._TICKETS_COMPACT_BYTES:
                self._compact_tickets()
        except Exception:
            pass

    def _load_pending_tickets(self) -> None:
        """Restore still-valid pending tickets from the previous process.

        Only tickets whose last recorded status is "pending" and that are not yet
        expired are restored. Each restored ticket gets a confirm_code regenerated
        from the FRESH process-local HMAC secret - so its code differs from the
        pre-restart one, and the human must read it from a re-shown popup (HITL
        preserved: codes never leave the process). The ticket is marked restored
        so approve() re-shows the popup when given the stale pre-restart code
        instead of dead-ending the ticket (v1.4.41).
        """
        path = self._tickets_path()
        if not path.exists():
            return
        latest: dict[str, dict] = {}
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                    except ValueError:
                        continue
                    if item.get("id"):
                        latest[item["id"]] = item
        except Exception:
            return
        now = time.time()
        for item in latest.values():
            if item.get("status") != "pending":
                continue
            expires_at = float(item.get("expires_at") or 0)
            if now > expires_at:
                continue
            ticket = self._restore_ticket(item, now, expires_at)
            if ticket is None:
                continue
            self._tickets[ticket.id] = ticket
            logger.warning(
                "RESTORED pending ticket=%s op=%s resources=%s (confirm code regenerated; popup re-shown on next use)",
                ticket.id, ticket.operation, len(ticket.resources) if ticket.resources else 0,
            )

    def _restore_ticket(self, item: dict, now: float,
                        expires_at: float) -> PermissionTicket | None:
        """Reconstruye un ticket pending desde un registro persistido.

        Devuelve None si el registro no es valido (p.ej. nivel desconocido,
        recursos corruptos): un registro basura no debe tumbar el arranque
        ni re-crear un ticket erroneo. El `confirm_code` se regenera con el
        secreto fresco de este proceso y NUNCA se lee del disco.
        """
        try:
            resources = item.get("resources")
            level = GrantLevel(item.get("level", "single"))
            ticket = PermissionTicket(
                resource=item.get("resource", f"{len(resources or [])} files"),
                operation=item.get("operation", "read"),
                level=level,
                ttl_seconds=max(1, int(expires_at - now)),
                resources=resources,
                restored=True,
            )
        except Exception:
            return None
        ticket.id = item["id"]
        ticket.created_at = float(item.get("created_at") or now)
        ticket.expires_at = expires_at
        ticket.confirm_code = self._generate_confirm_code(ticket.id)
        return ticket

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
                logger.info("PENDING ticket=%s op=%s resource=%s (reused)", existing.id, operation, resource)
                return existing
        ticket = PermissionTicket(resource, operation, level)
        ticket.confirm_code = self._generate_confirm_code(ticket.id)
        self._tickets[ticket.id] = ticket
        self._persist_ticket(ticket)
        show_confirmation_code(ticket.resource, ticket.operation, ticket.confirm_code)
        logger.info("PENDING ticket=%s op=%s resource=%s", ticket.id, operation, resource)
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

        Reuses an existing pending ticket for the SAME operation + same exact
        resource list (order-insensitive), mirroring request()'s dedup (v1.4.41).
        This also recovers a ticket restored from tickets.jsonl after a restart:
        re-issuing the same batch re-shows the popup with the regenerated code.
        """
        for existing in self._tickets.values():
            if (existing.operation == operation
                    and existing.status == "pending"
                    and not existing.is_expired
                    and existing.resources is not None
                    and sorted(existing.resources) == sorted(resources)):
                show_confirmation_code_batch(existing.resources, operation, existing.confirm_code)
                logger.info("PENDING ticket=%s op=%s resources=%d (reused)", existing.id, operation, len(resources))
                return existing
        summary = f"{len(resources)} files"
        ticket = PermissionTicket(summary, operation, level, resources=resources)
        ticket.confirm_code = self._generate_confirm_code(ticket.id)
        self._tickets[ticket.id] = ticket
        self._persist_ticket(ticket)
        show_confirmation_code_batch(resources, operation, ticket.confirm_code)
        logger.info("PENDING ticket=%s op=%s resources=%d", ticket.id, operation, len(resources))
        return ticket

    def approve(self, ticket_id: str,
                level: GrantLevel | None = None,
                confirm_code: str | None = None) -> tuple[bool, str]:
        ticket = self._tickets.get(ticket_id)
        if not ticket:
            logger.warning("APPROVE_FAIL ticket=%s reason=not_found", ticket_id)
            return False, f"Ticket not found: {ticket_id}"
        if ticket.is_expired:
            ticket.status = "expired"
            self._persist_ticket(ticket, status="expired")
            logger.warning("APPROVE_FAIL ticket=%s reason=expired", ticket_id)
            return False, f"Ticket expired: {ticket_id}"
        if ticket.status != "pending":
            logger.warning("APPROVE_FAIL ticket=%s reason=status_%s", ticket_id, ticket.status)
            return False, f"Ticket already {ticket.status}: {ticket_id}"
        if not confirm_code or not hmac.compare_digest(confirm_code, ticket.confirm_code):
            # Rate-limiting: acumular intentos fallidos y auto-denegar el
            # ticket al exceder el limite. Sin esto, un agente podria hacer
            # fuerza bruta sobre el codigo de 6 digitos dentro del TTL.
            attempts = self._failed_approve_attempts.get(ticket_id, 0) + 1
            self._failed_approve_attempts[ticket_id] = attempts
            if attempts >= self._MAX_APPROVE_ATTEMPTS:
                ticket.status = "denied"
                self._persist_ticket(ticket, status="denied")
                logger.warning("APPROVE_LOCKED ticket=%s reason=max_attempts (%d/%d)",
                               ticket_id, attempts, self._MAX_APPROVE_ATTEMPTS)
                return False, (f"Ticket locked after {attempts} failed attempts. "
                               f"Create a new request to try again.")
            if ticket.restored:
                # Un reinicio regenera el secret HMAC, asi que un ticket restaurado
                # tiene un confirm_code nuevo. Re-mostrar el popup para que el humano
                # lea el codigo actual en vez del viejo pre-reinicio (v1.4.41).
                if ticket.resources is not None:
                    show_confirmation_code_batch(ticket.resources, ticket.operation, ticket.confirm_code)
                else:
                    show_confirmation_code(ticket.resource, ticket.operation, ticket.confirm_code)
            logger.warning("APPROVE_FAIL ticket=%s reason=invalid_code attempt=%d/%d%s",
                           ticket_id, attempts, self._MAX_APPROVE_ATTEMPTS,
                           " (restored; popup re-shown)" if ticket.restored else "")
            return False, "Invalid or missing confirmation code."

        ticket.status = "approved"
        # Limpiar contador de intentos fallidos: el ticket ya fue aprobado.
        self._failed_approve_attempts.pop(ticket_id, None)
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

        self._persist_ticket(ticket, status="approved")
        msg = f"Granted {grant_level.value} access to {ticket.resource}"
        if forced_single:
            msg += " (delete is always single-use; session/permanent not allowed)"
        logger.info("GRANTED ticket=%s level=%s resource=%s", ticket_id, grant_level.value, ticket.resource)
        return True, msg

    def deny(self, ticket_id: str) -> tuple[bool, str]:
        ticket = self._tickets.get(ticket_id)
        if not ticket:
            logger.warning("DENY_FAIL ticket=%s reason=not_found", ticket_id)
            return False, f"Ticket not found: {ticket_id}"
        ticket.status = "denied"
        self._failed_approve_attempts.pop(ticket_id, None)
        self._persist_ticket(ticket, status="denied")
        logger.info("DENIED ticket=%s resource=%s", ticket_id, ticket.resource)
        return True, f"Denied access to {ticket.resource}"

    def _resolve(self, resource: str) -> str:
        return str(Path(resource).resolve())

    def grant_direct(self, resource: str, operation: str = "read",
                     level: GrantLevel = GrantLevel.SESSION) -> PermissionTicket:
        ticket = PermissionTicket(resource, operation, level, ttl_seconds=86400)
        ticket.status = "approved"
        self._tickets[ticket.id] = ticket
        self._persist_ticket(ticket, status="approved")
        resolved = self._resolve(resource)
        if level == GrantLevel.SESSION:
            ops = self._session_grants.setdefault(resolved, set())
            ops.add(operation)
        elif level == GrantLevel.SINGLE:
            ops = self._single_grants.setdefault(resolved, {})
            ops[operation] = 1
        elif level == GrantLevel.PERMANENT:
            self._add_permanent_grant(resolved)
        logger.info("GRANT_DIRECT resource=%s op=%s level=%s", resource, operation, level.value)
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
        self._cleanup_expired()
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
                # M-C2 (auditoría 2026-08-11): a wildcard "*" grant covers every
                # operation, so revoking a specific operation must also drop it --
                # otherwise `security_revoke(path, "write")` silently left a "*"
                # grant active and reported "No active grants found".
                if operation in ops or "*" in ops:
                    ops.discard(operation)
                    ops.discard("*")
                    if not ops:
                        del self._session_grants[resolved]
                    found = True
            else:
                del self._session_grants[resolved]
                found = True
        if resolved in self._single_grants:
            if operation:
                ops = self._single_grants[resolved]
                if operation in ops or "*" in ops:
                    ops.pop(operation, None)
                    ops.pop("*", None)
                    if not ops:
                        del self._single_grants[resolved]
                    found = True
            else:
                del self._single_grants[resolved]
                found = True
        if found:
            for ticket in self._tickets.values():
                if ticket.status != "approved":
                    continue
                if operation and ticket.operation != operation:
                    continue
                # 2026-08-08 fix (found via external audit): comparing
                # `ticket.resource == resource` only worked for single-resource
                # tickets. For a batch ticket (fs_delete_batch etc.), .resource
                # is a human-readable summary like "10 files", never a real path
                # -- it could never equal the resolved `resource` passed in here,
                # so the ticket's status was never synced to "revoked" even
                # though its grants just got removed above. Now resolves each
                # real target (ticket.resources for batch, [ticket.resource]
                # otherwise -- same pattern as approve()) and matches on that.
                targets = ticket.resources if ticket.resources is not None else [ticket.resource]
                if any(self._resolve(t) == resolved for t in targets):
                    ticket.status = "revoked"
                    self._persist_ticket(ticket, status="revoked")
            return True
        return False

    def revoke_ticket(self, ticket_id: str) -> tuple[bool, str]:
        ticket = self._tickets.get(ticket_id)
        if not ticket:
            logger.warning("DENY_FAIL ticket=%s reason=not_found", ticket_id)
            return False, f"Ticket not found: {ticket_id}"
        ticket.status = "revoked"
        self._persist_ticket(ticket, status="revoked")
        # 2026-08-08 fix (found via external audit): used to resolve only
        # ticket.resource, which for a batch ticket is the summary string
        # ("10 files"), not a real path -- resolving it produced a bogus key
        # that never matched any actual grant, so the underlying per-file
        # grants from a batch approval stayed fully active while the ticket
        # itself showed "revoked". Same targets pattern as approve()/revoke().
        targets = ticket.resources if ticket.resources is not None else [ticket.resource]
        for target in targets:
            resolved = self._resolve(target)
            self._session_grants.pop(resolved, None)
            self._single_grants.pop(resolved, None)
        return True, f"Revoked: {ticket.resource}"

    def _add_permanent_grant(self, resource: str) -> None:
        resolved = str(Path(resource).resolve())
        if resolved not in self.config.security.paths_allow:
            self.config.security.paths_allow.append(resolved)
            self.config.save()
            # M-F10 (auditoría 2026-08-11): SecurityValidator._resolved_allowed
            # cacheaba paths_allow, así que el nuevo grant no surtía efecto hasta
            # reiniciar. Invalidar la cache para que aplique de inmediato.
            if self.security is not None:
                self.security.clear_cache()

    def _cleanup_expired(self) -> None:
        expired = [tid for tid, t in self._tickets.items() if t.is_expired and t.status == "pending"]
        for tid in expired:
            self._tickets[tid].status = "expired"
            self._persist_ticket(self._tickets[tid], status="expired")
        if expired:
            logger.info("EXPIRED %d tickets", len(expired))

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