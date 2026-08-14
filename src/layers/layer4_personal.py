import asyncio
import json
import os
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from src.config import AppConfig
from src.log import get_logger
from src.secretscanner import scan_and_warn
from src.security import PathNotAllowedError, SecurityValidator

logger = get_logger("layer4_personal")


def _scan_warning(content: str, config: AppConfig) -> str:
    """Return the secret-scan warning for `content` (empty if clean).

    M-P1 (auditoría 2026-08-11): the previous `_scan_and_append` ran the scan
    AFTER journal.add()/note write had already persisted the content, so a crash
    between the write and the scan could leave a secret on disk with no warning
    ever emitted. The warning must be computed BEFORE the write.
    """
    return scan_and_warn(content, enabled=config.security.secret_scanning_enabled)



class Journal:
    def __init__(self, path: Path):
        self.path = path
        self.path.mkdir(parents=True, exist_ok=True)
        self._file = path / "journal.jsonl"

    def add(self, content: str, tags: list[str] | None = None,
            category: str = "general") -> dict:
        tags = tags or []
        entry = {
            "id": int(time.time() * 1000),
            "timestamp": datetime.now().isoformat(),
            "content": content,
            "tags": tags,
            "category": category,
        }
        with open(self._file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def list(self, limit: int = 20, offset: int = 0,
             tag: str | None = None,
             category: str | None = None) -> list:
        entries = self._load_all()
        if tag:
            entries = [e for e in entries if tag in e.get("tags", [])]
        if category:
            entries = [e for e in entries if e.get("category") == category]
        entries.reverse()
        return entries[offset:offset + limit]

    def search(self, query: str) -> list:
        entries = self._load_all()
        pattern = re.compile(re.escape(query), re.IGNORECASE)
        return [e for e in entries if pattern.search(e.get("content", ""))]

    def stats(self) -> dict:
        entries = self._load_all()
        tags = {}
        categories = {}
        for e in entries:
            for t in e.get("tags", []):
                tags[t] = tags.get(t, 0) + 1
            cat = e.get("category", "general")
            categories[cat] = categories.get(cat, 0) + 1
        return {
            "total_entries": len(entries),
            "tags": dict(sorted(tags.items(), key=lambda x: -x[1])[:20]),
            "categories": categories,
            "file_size": self._file.stat().st_size if self._file.exists() else 0,
        }

    def export(self, fmt: str = "json") -> str:
        entries = self._load_all()
        if fmt == "json":
            return json.dumps(entries, indent=2, ensure_ascii=False)
        lines = []
        for e in entries:
            lines.append(f"# {e['timestamp']}")
            if e.get("tags"):
                lines.append(f"Tags: {', '.join(e['tags'])}")
            lines.append(e["content"])
            lines.append("")
        return "\n".join(lines)

    def _load_all(self) -> list:
        if not self._file.exists():
            return []
        entries = []
        with open(self._file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return entries


def journal_add_impl(content: str, journal: Journal, config: AppConfig, tags: str | None = None,
                     category: str = "general") -> str:
    tag_list = [t.strip() for t in (tags or "").split(",") if t.strip()]
    warning = _scan_warning(content, config)
    entry = journal.add(content, tag_list or None, category)
    result = f"Entry {entry['id']} saved at {entry['timestamp']}"
    return result + warning if warning else result


def journal_list_impl(journal: Journal, limit: int = 20, offset: int = 0,
                      tag: str | None = None,
                      category: str | None = None) -> str:
    entries = journal.list(limit=limit, offset=offset, tag=tag, category=category)
    if not entries:
        return "No journal entries found"
    lines = []
    for e in entries:
        tags_str = f"[{', '.join(e.get('tags', []))}]" if e.get("tags") else ""
        lines.append(f"{e['id']} | {e['timestamp'][:19]} | {tags_str}")
        lines.append(f"    {e['content'][:200]}")
    return "\n".join(lines)


def journal_search_impl(query: str, journal: Journal) -> str:
    entries = journal.search(query)
    if not entries:
        return f"No entries matching '{query}'"
    lines = []
    for e in entries[:20]:
        lines.append(f"{e['id']} | {e['timestamp'][:19]} | {e['content'][:200]}")
    return "\n".join(lines)


def journal_stats_impl(journal: Journal) -> str:
    return json.dumps(journal.stats(), indent=2, ensure_ascii=False)


def journal_export_impl(journal: Journal, fmt: str = "json") -> str:
    return journal.export(fmt=fmt)


def note_quick_impl(content: str, config: AppConfig) -> str:
    warning = _scan_warning(content, config)
    inbox = Path(config.data_dir) / "inbox.md"
    inbox.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    with open(inbox, "a", encoding="utf-8") as f:
        f.write(f"- [{timestamp}] {content}\n")
    result = f"Quick note saved to {inbox}"
    return result + warning if warning else result


def _default_project_root(security: SecurityValidator) -> str:
    """Default search root for project_scan/project_find when no path is given.

    Uses the first entry in paths_allow (the real source of truth for what this
    server can access) instead of a hardcoded Path.home()/"Repos" literal, which
    silently drifted from the live config once paths_allow was narrowed to a
    single custom directory (e.g. C:\\Users\\usuario\\Repos). Falls back to Path.home()/"Repos"
    only if paths_allow is empty — a misconfigured-server case where no default
    could be correct anyway; resolve_and_validate() will reject it with the same
    clear error it already produces today.
    """
    allowed = security.config.security.paths_allow
    if allowed:
        return allowed[0]
    return str(Path.home() / "Repos")


def _git_project_info(entry: Path) -> dict:
    """Gather branch/status/ahead-behind for one project dir via subprocess.run() (blocking).

    Must be called through asyncio.to_thread() — subprocess.run() is synchronous,
    and project_scan_impl/project_find_impl are async functions that FastMCP runs
    on the single shared event loop. Calling this directly would block every other
    concurrent tool call for as long as git takes to respond, once per project
    under the scanned directory.

    stdin=subprocess.DEVNULL on all three calls (added 2026-08-07): without it,
    the child inherits this server's stdin, which on a stdio-based MCP server is
    the JSON-RPC transport pipe to the client. That handle inheritance is what
    actually caused the multi-minute hangs previously attributed to "scanning
    many repos sequentially" (CHANGELOG 1.4.11/1.4.43) — reproduced live with a
    SINGLE known repo, and confirmed by every other subprocess spawn in
    layer2_shell.py already setting stdin=DEVNULL/PIPE explicitly, which this
    function had missed. See CHANGELOG 1.4.48 update. Sequential-per-repo calls
    (below, project_git_status_impl) are still parallelized as a real but
    secondary improvement — it was not the root cause.

    ahead/behind added 2026-08-01 for project_git_status: None (not 0) means no
    upstream is configured for the current branch (common for repos never pushed,
    or a branch with no tracking set) — distinct from "0 ahead/behind", which
    means there IS an upstream and it's fully in sync.
    """
    info = {"project": entry.name, "path": str(entry)}
    git_dir = entry / ".git"
    if not git_dir.exists():
        info["branch"] = "(no git)"
        return info
    try:
        r = subprocess.run(
            ["git", "-C", str(entry), "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL
        )
        # M-P4 (auditoría 2026-08-11): rev-parse/status return codes were never
        # checked, so a corrupt/non-repo .git reported an empty branch and zero
        # changes as if healthy. Surface the failure instead.
        info["branch"] = r.stdout.strip() if r.returncode == 0 else "(error)"
        r2 = subprocess.run(
            ["git", "-C", str(entry), "status", "--porcelain"],
            capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL
        )
        changes = len([l for l in r2.stdout.splitlines() if l.strip()]) if r2.returncode == 0 else 0
        info["uncommitted_changes"] = changes
        r3 = subprocess.run(
            ["git", "-C", str(entry), "rev-list", "--left-right", "--count", "@{u}...HEAD"],
            capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL
        )
        if r3.returncode == 0 and r3.stdout.strip():
            behind_str, ahead_str = r3.stdout.strip().split()
            info["ahead"] = int(ahead_str)
            info["behind"] = int(behind_str)
        else:
            info["ahead"] = None
            info["behind"] = None
    except (subprocess.TimeoutExpired, OSError, ValueError):
        info["branch"] = "error"
    return info


_REPO_DISCOVERY_SKIP_DIRS = {
    "node_modules", "bin", "obj", ".venv", "__pycache__",
    "AppData", "$Recycle.Bin", "Windows", "Program Files", "Program Files (x86)",
}


def _is_filesystem_root(p: Path) -> bool:
    """True for a drive/filesystem root (C:\\, /, ...), where os.walk has no
    natural scope boundary. Generic check (a root is its own parent) rather
    than a hardcoded string list, so it holds for any OS or drive letter.
    Used only to guard project_git_status's unbounded default scan (see
    CHANGELOG 1.4.43 / README warning) — not a general-purpose path utility.
    """
    return p.parent == p


def _discover_git_repos_sync(roots: list[str]) -> list[Path]:
    """Walk each given root looking for .git directories (2026-08-01
    design decision: automatic discovery over a fixed repo list, accepted
    trade-off being slower scans when the scanned roots are broad — e.g.
    the whole "C:\\" drive on this machine's real config). `roots` is taken
    explicitly rather than read from security.config directly, so callers
    can pass either the full paths_allow list (default project_git_status
    behavior) or a single caller-supplied, already-validated path (scoped
    project_git_status(path=...) call) through the same code path.

    Uses os.walk() with in-place dirnames pruning rather than Path.rglob(),
    since rglob has no way to skip descending into a directory once it
    decides to look inside it — os.walk lets us drop known-noisy trees
    (node_modules, .venv, AppData, ...) from the traversal entirely, same
    exclusion set already used by _find_files_sync() for project_find.
    No cap on the number of repos returned or the number of roots scanned —
    same reasoning as fs_find_duplicates (2026-07-31): the real cost driver
    is how much of the tree has to be walked, which a result-count limit
    would not meaningfully bound anyway.
    """
    found: set[Path] = set()
    for root_str in roots:
        root = Path(root_str)
        if not root.exists() or not root.is_dir():
            continue
        for dirpath, dirnames, _filenames in os.walk(root, topdown=True):
            dirnames[:] = [d for d in dirnames if d not in _REPO_DISCOVERY_SKIP_DIRS]
            if ".git" in dirnames:
                found.add(Path(dirpath))
                dirnames.remove(".git")
    return sorted(found)


async def project_git_status_impl(security: SecurityValidator, path: str | None = None) -> str:
    if path is not None:
        base = Path(security.resolve_and_validate(path))
        if not base.is_dir():
            return f"Directory not found: {base}"
        roots = [str(base)]
    else:
        unbounded = [r for r in security.config.security.paths_allow if _is_filesystem_root(Path(r))]
        if unbounded:
            return (
                "paths_allow incluye una raiz de disco completa "
                f"({', '.join(unbounded)}) - recorrerla puede tardar varios minutos "
                "y agotar el timeout del cliente MCP.\n"
                "Pasa un path puntual dentro de las rutas permitidas, ej.: "
                "project_git_status(path=\"C:\\\\Repos\")."
            )
        roots = security.config.security.paths_allow

    repos = await asyncio.to_thread(_discover_git_repos_sync, roots)
    if not repos:
        scope = roots[0] if path is not None else "paths_allow"
        return f"No git repositories found under {scope}"

    # Parallelize across repos (each repo's own 3 git calls stay sequential
    # inside _git_project_info, but repos run concurrently now via the
    # asyncio.to_thread default ThreadPoolExecutor). Confirmed live 2026-08-07:
    # the previous sequential list comprehension hung 8+ minutes scanning a
    # SINGLE known repo (this one, personal-mcp itself — its own test fixtures
    # create nested .git dirs), not just the originally-reported "paths_allow
    # = whole disk" case. The path= guard alone (added earlier in 1.4.48) was
    # not sufficient; this is the actual bottleneck. project_scan_impl below
    # has the identical sequential pattern and the identical exposure — not
    # changed here, flagged as a separate finding (see CHANGELOG).
    results = await asyncio.gather(*(asyncio.to_thread(_git_project_info, r) for r in repos))

    dirty = []
    clean = []
    for r in results:
        has_pending = (
            r.get("uncommitted_changes", 0) > 0
            or (r.get("ahead") or 0) > 0
            or (r.get("behind") or 0) > 0
        )
        (dirty if has_pending else clean).append(r)

    lines = []
    if dirty:
        lines.append(f"{len(dirty)} repo(s) con cambios pendientes:")
        for r in dirty:
            parts = []
            if r.get("uncommitted_changes"):
                parts.append(f"{r['uncommitted_changes']} sin commitear")
            if r.get("ahead"):
                parts.append(f"{r['ahead']} sin pushear")
            if r.get("behind"):
                parts.append(f"{r['behind']} atras del remoto")
            branch = r.get("branch", "?")
            lines.append(f"  {r['project']:30s} [{branch}]  {', '.join(parts)}")
    if clean:
        if lines:
            lines.append("")
        names = ", ".join(r["project"] for r in clean)
        lines.append(f"{len(clean)} repo(s) sin cambios pendientes: {names}")
    return "\n".join(lines)


_PROJECT_SCAN_CACHE: dict = {}
_PROJECT_SCAN_CACHE_TTL: float = 30.0


async def project_scan_impl(security: SecurityValidator, path: str | None = None) -> str:
    resolved_path = str(security.resolve_and_validate(path or _default_project_root(security)))
    now = time.time()
    if resolved_path in _PROJECT_SCAN_CACHE:
        cached_time, cached_result = _PROJECT_SCAN_CACHE[resolved_path]
        if now - cached_time < _PROJECT_SCAN_CACHE_TTL:
            return cached_result + "\n\n(cached result - TTL 30s)"

    base = Path(resolved_path)
    if not base.is_dir():
        return f"Directory not found: {base}"
    entries = [e for e in sorted(base.iterdir()) if e.is_dir() and not e.name.startswith(".")]
    # M-P6 (auditoría 2026-08-11): was a sequential list-comprehension of awaited
    # to_thread calls; project_git_status_impl already parallelized with gather.
    results = await asyncio.gather(*(asyncio.to_thread(_git_project_info, e) for e in entries))
    lines = [f"{r['project']:30s} branch: {r.get('branch', '?'):20s} changes: {r.get('uncommitted_changes', 0)}"
             for r in results]
    output = "\n".join(lines)
    _PROJECT_SCAN_CACHE[resolved_path] = (now, output)
    return output



def _find_files_sync(base: Path, filename: str) -> list[str]:
    """Walk base for filename (blocking I/O) — must run via asyncio.to_thread().

    M-P5 (auditoría 2026-08-11): previously used base.rglob(filename), which
    descends into node_modules/.venv/etc. before the exclusion filter could even
    apply. Now os.walk() with in-place dirnames pruning (same exclusion set as
    _discover_git_repos_sync) skips those whole subtrees instead of walking them.
    """
    results = []
    for dirpath, dirnames, _filenames in os.walk(base, topdown=True):
        dirnames[:] = [
            d for d in dirnames
            if d not in _REPO_DISCOVERY_SKIP_DIRS and d != ".git"
        ]
        for name in _filenames:
            if name == filename:
                results.append(str(Path(dirpath) / name))
                if len(results) >= 50:
                    return results
    return results


async def project_find_impl(filename: str, security: SecurityValidator,
                            path: str | None = None) -> str:
    base = Path(security.resolve_and_validate(path or _default_project_root(security)))
    if not base.is_dir():
        return f"Directory not found: {base}"
    results = await asyncio.to_thread(_find_files_sync, base, filename)
    return "\n".join(results) if results else f"No files named '{filename}' found"


def register_personal_tools(mcp: FastMCP, config: AppConfig,
                            security: SecurityValidator) -> None:
    if not config.journal.enabled:
        return

    # M-P3 (auditoría 2026-08-11): journal.path and data_dir are written without
    # resolve_and_validate (the _impls only take `config`, not `security`). Validate
    # the configured paths up front and warn loudly if the owner pointed them
    # outside the allowed set — they're owner-controlled config, so a warning is
    # the right severity (not a hard failure that could brick a misconfigured
    # server on startup).
    for configured in (config.journal.path, config.data_dir):
        try:
            security.resolve_and_validate(configured)
        except PathNotAllowedError as e:
            logger.warning("personal tool path not in allowed dirs: %s", e)

    journal = Journal(Path(config.journal.path))

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False))
    async def journal_add(content: str, tags: str | None = None,
                          category: str = "general") -> str:
        return journal_add_impl(content, journal, config, tags, category)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True))
    async def journal_list(limit: int = 20, offset: int = 0,
                           tag: str | None = None,
                           category: str | None = None) -> str:
        return journal_list_impl(journal, limit, offset, tag, category)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True))
    async def journal_search(query: str) -> str:
        return journal_search_impl(query, journal)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True))
    async def journal_stats() -> str:
        return journal_stats_impl(journal)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True))
    async def journal_export(format: str = "json") -> str:
        return journal_export_impl(journal, format)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False))
    async def note_quick(content: str) -> str:
        return note_quick_impl(content, config)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True))
    async def project_scan(path: str | None = None) -> str:
        return await project_scan_impl(security, path)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True))
    async def project_find(filename: str, path: str | None = None) -> str:
        return await project_find_impl(filename, security, path)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True))
    async def project_git_status(path: str | None = None) -> str:
        """Estado de git multi-repo: cambios sin commitear, commits sin pushear y
        commits del remoto sin traer.

        path (recomendado siempre): ruta puntual validada contra paths_allow,
        ej. path="C:\\Users\\usuario\\Repos". Sin path solo funciona si
        paths_allow está acotado. Si paths_allow incluye una raiz de disco
        completa (ej. C:\\), la tool devuelve el mensaje del guard pidiendo un
        path puntual — es el comportamiento esperado, no un error.
        """
        return await project_git_status_impl(security, path)
