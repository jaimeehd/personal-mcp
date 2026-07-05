import json
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from mcp.server.fastmcp import FastMCP

from src.config import AppConfig
from src.security import SecurityValidator
from src.secretscanner import scan_text, format_findings


def _scan_and_append(content: str, config: AppConfig, result: str) -> str:
    if not config.security.secret_scanning_enabled or not content.strip():
        return result
    findings = scan_text(content)
    if findings:
        result += format_findings(findings)
    return result


class Journal:
    def __init__(self, path: Path):
        self.path = path
        self.path.mkdir(parents=True, exist_ok=True)
        self._file = path / "journal.jsonl"

    def add(self, content: str, tags: Optional[List[str]] = None,
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
             tag: Optional[str] = None,
             category: Optional[str] = None) -> list:
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


def journal_add_impl(content: str, journal: Journal, config: AppConfig, tags: Optional[str] = None,
                     category: str = "general") -> str:
    tag_list = [t.strip() for t in (tags or "").split(",") if t.strip()]
    entry = journal.add(content, tag_list or None, category)
    result = f"Entry {entry['id']} saved at {entry['timestamp']}"
    return _scan_and_append(content, config, result)


def journal_list_impl(journal: Journal, limit: int = 20, offset: int = 0,
                      tag: Optional[str] = None,
                      category: Optional[str] = None) -> str:
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
    inbox = Path(config.data_dir) / "inbox.md"
    inbox.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    with open(inbox, "a", encoding="utf-8") as f:
        f.write(f"- [{timestamp}] {content}\n")
    result = f"Quick note saved to {inbox}"
    return _scan_and_append(content, config, result)


def _default_project_root(security: SecurityValidator) -> str:
    """Default search root for project_scan/project_find when no path is given.

    Uses the first entry in paths_allow (the real source of truth for what this
    server can access) instead of a hardcoded Path.home()/"Repos" literal, which
    silently drifted from the live config once paths_allow was narrowed to a
    single custom directory (e.g. C:\Repos). Falls back to Path.home()/"Repos"
    only if paths_allow is empty — a misconfigured-server case where no default
    could be correct anyway; resolve_and_validate() will reject it with the same
    clear error it already produces today.
    """
    allowed = security.config.security.paths_allow
    if allowed:
        return allowed[0]
    return str(Path.home() / "Repos")


async def project_scan_impl(security: SecurityValidator, path: Optional[str] = None) -> str:
    base = Path(security.resolve_and_validate(path or _default_project_root(security)))
    if not base.is_dir():
        return f"Directory not found: {base}"
    results = []
    for entry in sorted(base.iterdir()):
        if not entry.is_dir() or entry.name.startswith("."):
            continue
        git_dir = entry / ".git"
        info = {"project": entry.name}
        if git_dir.exists():
            try:
                r = subprocess.run(
                    ["git", "-C", str(entry), "rev-parse", "--abbrev-ref", "HEAD"],
                    capture_output=True, text=True, timeout=10
                )
                info["branch"] = r.stdout.strip()
                r2 = subprocess.run(
                    ["git", "-C", str(entry), "status", "--porcelain"],
                    capture_output=True, text=True, timeout=10
                )
                changes = len([l for l in r2.stdout.splitlines() if l.strip()])
                info["uncommitted_changes"] = changes
            except (subprocess.TimeoutExpired, OSError):
                info["branch"] = "error"
        else:
            info["branch"] = "(no git)"
        results.append(info)
    lines = [f"{r['project']:30s} branch: {r.get('branch', '?'):20s} changes: {r.get('uncommitted_changes', 0)}"
             for r in results]
    return "\n".join(lines)


async def project_find_impl(filename: str, security: SecurityValidator,
                            path: Optional[str] = None) -> str:
    base = Path(security.resolve_and_validate(path or _default_project_root(security)))
    if not base.is_dir():
        return f"Directory not found: {base}"
    results = []
    for entry in base.rglob(filename):
        if any(p in entry.parts for p in (".git", "node_modules", "bin", "obj")):
            continue
        results.append(str(entry))
        if len(results) >= 50:
            break
    return "\n".join(results) if results else f"No files named '{filename}' found"


def register_personal_tools(mcp: FastMCP, config: AppConfig,
                            security: SecurityValidator) -> None:
    if not config.journal.enabled:
        return

    journal = Journal(Path(config.journal.path))

    @mcp.tool()
    async def journal_add(content: str, tags: Optional[str] = None,
                          category: str = "general") -> str:
        return journal_add_impl(content, journal, config, tags, category)

    @mcp.tool()
    async def journal_list(limit: int = 20, offset: int = 0,
                           tag: Optional[str] = None,
                           category: Optional[str] = None) -> str:
        return journal_list_impl(journal, limit, offset, tag, category)

    @mcp.tool()
    async def journal_search(query: str) -> str:
        return journal_search_impl(query, journal)

    @mcp.tool()
    async def journal_stats() -> str:
        return journal_stats_impl(journal)

    @mcp.tool()
    async def journal_export(format: str = "json") -> str:
        return journal_export_impl(journal, format)

    @mcp.tool()
    async def note_quick(content: str) -> str:
        return note_quick_impl(content, config)

    @mcp.tool()
    async def project_scan(path: Optional[str] = None) -> str:
        return await project_scan_impl(security, path)

    @mcp.tool()
    async def project_find(filename: str, path: Optional[str] = None) -> str:
        return await project_find_impl(filename, security, path)
