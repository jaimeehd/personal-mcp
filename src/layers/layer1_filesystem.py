import asyncio
import base64
import concurrent.futures
import difflib
import fnmatch
import hashlib
import json
import mimetypes
import os
import re
import shutil
import subprocess
import tempfile
import time
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from src.log import get_logger, timed
from src.secretscanner import format_findings, scan_text
from src.security import (
    PathNotAllowedError,
    SecurityValidator,
    format_deny_suffix,
    is_denied_entry,
    is_denied_entry_dir,
)

logger = get_logger("layer1_filesystem")

# F4 (v1.4.84): helpers compartidos viven en src/security.py para que Layer 4
# (project_find) use los mismos sin duplicar. Alias delgados para compat de
# llamadas internas existentes.
_deny_suffix = format_deny_suffix
_is_denied = is_denied_entry


def _ensure_parent_dir_sync(rpath: Path) -> str | None:
    """mkdir parents; None on success, an 'Error: ...' string on failure."""
    try:
        rpath.parent.mkdir(parents=True, exist_ok=True)
        return None
    except OSError as e:
        return f"Error: cannot create directory {rpath.parent}: {e}"


def _write_text_sync(rpath: Path, content: str, encoding: str = "utf-8") -> str | None:
    """Write content; None on success, an 'Error: ...' string on failure.

    O2 (v1.4.86): un OSError/PermissionError de escritura debe ser un resultado
    limpio para el agente, no una excepción cruda que llega como error JSON-RPC
    y que además pierde el grant single ya consumido por el wrapper. En Windows
    un archivo con el atributo read-only falla SIEMPRE — se sugiere attrib -r.
    """
    try:
        rpath.write_text(content, encoding=encoding)
        return None
    except PermissionError:
        hint = ""
        if os.name == "nt":
            hint = (
                " — el archivo parece tener el atributo de solo-lectura; "
                f"quitarlo con: attrib -r \"{rpath}\""
            )
        return f"Error: cannot write {rpath}: Permission denied.{hint}"
    except OSError as e:
        return f"Error: cannot write {rpath}: {e}"


async def fs_read_impl(path: str, security: SecurityValidator, encoding: str = "utf-8",
                       max_size_mb: int = 0,
                       head: int | None = None, tail: int | None = None,
                       include_scan: bool = True) -> str:
    rpath = security.resolve_and_validate(path)
    exists = await asyncio.to_thread(rpath.is_file)
    if not exists:
        logger.info("fs_read not_found path=%s", path)
        return f"Error: not a file or does not exist: {rpath}"
    if head is not None and tail is not None:
        return "Error: cannot specify both head and tail"
    size = await asyncio.to_thread(lambda: rpath.stat().st_size)
    if size > 10 * 1024 * 1024:
        logger.warning("fs_read large_file path=%s size=%d", path, size)
    if max_size_mb and size > max_size_mb * 1024 * 1024:
        return f"Error: file too large ({size / 1024 / 1024:.1f}MB). Max: {max_size_mb}MB"
    try:
        content = await asyncio.to_thread(rpath.read_text, encoding=encoding)
        if head is not None:
            lines = content.splitlines()
            content = "\n".join(lines[:head])
        elif tail is not None:
            lines = content.splitlines()
            content = "\n".join(lines[-tail:])
        if include_scan and security.config.security.secret_scanning_enabled:
            # O1 (v1.4.85): el scan corre FUERA del event loop (scan_text es
            # síncrono y pesa ~850ms en un archivo de 4MB) y acotado a los
            # primeros 1MB (mismo trade-off que audit/log con su cap de 100k).
            from src.secretscanner import SCAN_MAX_CHARS
            truncated = len(content) > SCAN_MAX_CHARS
            findings = await asyncio.to_thread(scan_text, content, None, SCAN_MAX_CHARS)
            if findings:
                content += format_findings(findings)
                logger.warning("SECRET_SCAN findings=%d path=%s", len(findings), path)
            elif truncated:
                content += ("\n[secret scan limited to the first 1MB of file "
                            "content — file is larger]")
        return content
    except UnicodeDecodeError:
        h = hashlib.sha256()
        with open(rpath, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return f"[Binary file, {size:,} bytes, SHA256: {h.hexdigest()[:16]}]"


async def fs_write_impl(path: str, content: str, security: SecurityValidator, encoding: str = "utf-8",
                        max_size_mb: int = 0) -> str:
    rpath = security.resolve_and_validate(path)
    try:
        size_bytes = len(content.encode(encoding))
    except (UnicodeEncodeError, LookupError) as e:
        # encoding inválido o contenido no encodable: error limpio, no excepción.
        return f"Error: cannot encode content with '{encoding}': {e}"
    if max_size_mb and size_bytes > max_size_mb * 1024 * 1024:
        return f"Error: content too large ({size_bytes / 1024 / 1024:.1f}MB). Max: {max_size_mb}MB"
    logger.info("fs_write path=%s size=%d", str(rpath), size_bytes)
    with timed("mkdir", path=str(rpath.parent)):
        mkdir_err = await asyncio.to_thread(_ensure_parent_dir_sync, rpath)
    if mkdir_err:
        return mkdir_err
    with timed("write_text", path=str(rpath), size=size_bytes):
        write_err = await asyncio.to_thread(_write_text_sync, rpath, content, encoding)
    if write_err:
        return write_err
    return f"Written {len(content)} chars ({size_bytes:,} bytes) to {rpath}"


async def fs_edit_impl(path: str, old_str: str, new_str: str, security: SecurityValidator) -> str:
    rpath = security.resolve_and_validate(path)
    # M-F1 (auditoría 2026-08-11): editing a nonexistent file used to fall through
    # to a misleading "old_str not found" (fs_read_impl returns an error string
    # rather than raising). Report the real problem instead.
    if not await asyncio.to_thread(rpath.is_file):
        return f"Error: not a file or does not exist: {rpath}"
    # O1 (v1.4.85): leer SIN el footer de security scan — antes fs_read_impl
    # anexaba "--- Security Scan ---" al contenido y fs_edit lo escribía de
    # vuelta al archivo (corrupción). include_scan=False = lectura cruda.
    content = await fs_read_impl(path, security, include_scan=False)
    if old_str not in content:
        return f"Error: old_str not found in {path} (tip: if you used fs_read with head/tail, the string may be outside that window — read the full file)"
    # 2026-09-06: old_str duplicado (ej. "### Fixed" aparece 55 veces en
    # CHANGELOG.md) — replace(...,1) solo cambia la primera. Antes era
    # silencioso y parecía "no se aplicó" si querías otra ocurrencia.
    occurrences = content.count(old_str)
    new_content = content.replace(old_str, new_str, 1)
    # O2 (v1.4.86): fs_write_impl ahora devuelve 'Error: ...' en vez de lanzar
    # (archivo read-only/ACL/bloqueado) — propagar ese error en lugar de
    # reportar "Applied edit" falso (antes se descartaba el return).
    write_result = await fs_write_impl(path, new_content, security)
    if write_result.startswith("Error:"):
        return write_result
    diff = await _diff_or_timeout_note(content, new_content)
    if occurrences > 1:
        return f"Applied edit. Note: old_str appears {occurrences} times — only the first was replaced. Use more surrounding context to target a specific occurrence.\nDiff:\n{diff}"
    return f"Applied edit. Diff:\n{diff}"


def _fs_list_sync(rpath: Path, pattern: str | None, max_results: int | None,
                  recursive: bool, security=None) -> tuple[list[dict], dict]:
    from collections import Counter
    denied_counter: Counter[str] = Counter()
    entries = []
    if recursive:
        for root, dirs, files in os.walk(rpath, followlinks=False):
            # P0.1: podar dirs denied + no seguir symlinks
            dirs[:] = [d for d in dirs if not (Path(root) / d).is_symlink()]
            pruned = []
            for d in dirs:
                dp = _is_denied(security, Path(root) / d, "read")
                if dp:
                    denied_counter[dp] += 1
                else:
                    pruned.append(d)
            dirs[:] = pruned
            root_rel = Path(root).relative_to(rpath)
            for name in sorted(dirs + files):
                if pattern and not fnmatch.fnmatch(name, pattern):
                    continue
                full = Path(root) / name
                if full.is_symlink():
                    continue
                deny_pat = _is_denied(security, full, "read")
                if deny_pat:
                    denied_counter[deny_pat] += 1
                    continue
                is_dir = name in dirs
                info = full.stat()
                rel = str(root_rel / name) if str(root_rel) != "." else name
                entries.append({
                    "name": rel,
                    "type": "dir" if is_dir else "file",
                    "size": info.st_size if not is_dir else 0,
                    "modified": datetime.fromtimestamp(
                        info.st_mtime, tz=UTC
                    ).isoformat(),
                })
                if max_results and len(entries) >= max_results:
                    return entries, denied_counter
    else:
        with os.scandir(rpath) as it:
            scan_entries = sorted(it, key=lambda e: e.name)
            for scan_entry in scan_entries:
                if pattern and not fnmatch.fnmatch(scan_entry.name, pattern):
                    continue
                deny_pat = _is_denied(security, Path(scan_entry.path), "read")
                if deny_pat:
                    denied_counter[deny_pat] += 1
                    continue
                is_dir = scan_entry.is_dir()
                try:
                    info = scan_entry.stat()
                except (OSError, PermissionError):
                    continue
                entries.append({
                    "name": scan_entry.name,
                    "type": "dir" if is_dir else "file",
                    "size": info.st_size if not is_dir else 0,
                    "modified": datetime.fromtimestamp(
                        info.st_mtime, tz=UTC
                    ).isoformat(),
                })
                if max_results and len(entries) >= max_results:
                    return entries, denied_counter
    return entries, denied_counter


async def fs_list_impl(path: str, security: SecurityValidator, pattern: str | None = None,
                       max_results: int | None = 100, recursive: bool = False) -> str:
    rpath = security.resolve_and_validate(path)
    if not rpath.is_dir():
        return f"Error: not a directory: {rpath}"
    # M-F3 (auditoría 2026-08-11): os.walk/scandir + stat per entry was blocking I/O
    # on the event loop; move the whole walk off to a thread.
    # P0.1: filtro deny por archivo + sufijo de conteo.
    try:
        entries, denied_counter = await asyncio.to_thread(_fs_list_sync, rpath, pattern, max_results, recursive, security)
    except PermissionError as e:
        return f"Permission denied: {e}"
    lines = []
    for e in entries:
        tag = "dir" if e["type"] == "dir" else "file"
        size_str = f"{e['size']:,}B" if e["size"] < 1024 else f"{e['size']/1024:.1f}KB"
        lines.append(f"{tag:4s} {e['name']:40s} {size_str:10s} {e['modified'][:19]}")
    base = "\n".join(lines) if lines else "(empty directory)"
    return base + _deny_suffix(denied_counter)


def _fs_tree_sync(rpath: Path, max_depth: int, exclude_patterns: list[str] | None,
                  security=None) -> str:
    from collections import Counter
    denied_counter: Counter[str] = Counter()

    def _should_exclude(name: str) -> bool:
        if not exclude_patterns:
            return False
        return any(fnmatch.fnmatch(name, pat) for pat in exclude_patterns)

    def _tree(dir_path: Path, prefix: str = "", depth: int = 0) -> list[str]:
        if depth > max_depth:
            return [f"{prefix}└── ..."]
        lines = []
        try:
            entries = sorted(dir_path.iterdir())
        except (OSError, PermissionError):
            return lines
        # P0.1: filtrar denied antes de numerar (evita conectores rotos)
        visible = []
        for e in entries:
            if _should_exclude(e.name):
                continue
            if e.is_symlink():
                continue
            dp = _is_denied(security, e, "read")
            if dp:
                denied_counter[dp] += 1
                continue
            visible.append(e)
        for i, entry in enumerate(visible):
            is_last = i == len(visible) - 1
            connector = "└── " if is_last else "├── "
            lines.append(f"{prefix}{connector}{entry.name}/" if entry.is_dir() else f"{prefix}{connector}{entry.name}")
            if entry.is_dir():
                ext = "    " if is_last else "│   "
                lines.extend(_tree(entry, prefix + ext, depth + 1))
        return lines

    result = [f"{rpath.name}/"]
    result.extend(_tree(rpath))
    return "\n".join(result) + _deny_suffix(denied_counter)


async def fs_tree_impl(path: str, security: SecurityValidator, max_depth: int = 3,
                       exclude_patterns: list[str] | None = None) -> str:
    rpath = security.resolve_and_validate(path)
    if not rpath.is_dir():
        return f"Error: not a directory: {rpath}"
    # M-F3 (auditoría 2026-08-11): recursive iterdir() was blocking I/O on the
    # event loop; move the whole traversal off to a thread.
    # P0.1: filtro deny por archivo.
    return await asyncio.to_thread(_fs_tree_sync, rpath, max_depth, exclude_patterns, security)


# ReDoS mitigation: a single catastrophic regex.search() call cannot be interrupted
# mid-execution in pure Python (no external timeout-capable engine, e.g. the `regex`
# package, is a dependency of this project). Running the blocking search in a thread
# and bounding the wait with asyncio.wait_for() cannot stop the runaway thread itself,
# but it guarantees the MCP call returns to the caller instead of hanging the server
# indefinitely — the actual failure mode this fixes.
_SEARCH_TIMEOUT_SECONDS = 10.0
_SEARCH_MAX_FILE_MB = 10


# difflib.SequenceMatcher (the engine behind difflib.unified_diff) has a known
# pathological case on large files with many structurally-similar-but-not-
# identical lines -- its "junk" autodetection heuristic can miss the pattern,
# degrading the matching-block search. Confirmed live in this codebase
# (2026-08-08): editing this same file (~1300 lines, dozens of near-identical
# fs_*_impl functions) hung fs_edit for 4+ minutes, twice, blocking the whole
# server -- the exact bug class already fixed for fs_search's regex in 1.4.7,
# never applied to the diff computation itself in fs_edit/fs_edit_advanced/
# fs_diff. Run off-thread with a timeout, same pattern as fs_search.
# 2026-09-06: en máquina con poca RAM el GC/paging hace que 10s se quede
# corto — el diff se aborta aunque la edición sí se guardó, y el usuario
# lo ve como fallo esporádico. Subir a 20s y además saltar diff para
# archivos muy grandes (>500k chars) donde el diff no aporta y solo
# consume RAM (aprox 3-4× tamaño en pico).
_DIFF_TIMEOUT_SECONDS = 20.0
_DIFF_SKIP_CHARS = 500_000

# 2026-09-06: asyncio.wait_for() around asyncio.to_thread() bounds how long the
# CALLER waits, but never kills the underlying thread -- a genuinely pathological
# SequenceMatcher case (see comment above) keeps running forever in the
# background. asyncio.to_thread() always uses the process-wide DEFAULT executor,
# shared by every other to_thread call in this module (mkdir, read_text,
# write_text, etc.) -- so each leaked diff thread permanently steals one worker
# slot from that shared pool. Enough leaked diffs (confirmed live 2026-09-06:
# repeated edits to a large, repetitive file like AGENTS.md) exhaust the pool,
# and THEN unrelated calls (a plain mkdir, even a dry_run that never touches
# disk) queue behind them with no error, no timeout, no log line -- indistinguishable
# from the server being completely unresponsive. Isolating the diff computation
# in its own small dedicated executor means a leaked thread only ever costs one
# of ITS OWN slots, never the shared pool every other tool call depends on.
_diff_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=2, thread_name_prefix="diff-worker"
)


def _unified_diff_sync(content_from: str, content_to: str,
                        fromfile: str = "before", tofile: str = "after") -> str:
    return "".join(difflib.unified_diff(
        content_from.splitlines(keepends=True),
        content_to.splitlines(keepends=True),
        fromfile=fromfile, tofile=tofile,
    ))


# 2026-09-06: replaces difflib.SequenceMatcher as the primary diff engine (see
# comment above _DIFF_TIMEOUT_SECONDS for the pathological case that motivated
# this). git's own diff engine (xdiff, Myers-based) is what this project
# already trusts for large, repetitive text -- project_git_status/CHANGELOG.md
# itself (200KB, 82 versions, dozens of near-identical sections) is exactly
# the profile that hung difflib. No new dependency: git is already assumed
# present (config.py allow_prefix, layer4_personal.py's _git_project_info).
# _unified_diff_sync above is kept as the fallback for the rare case git is
# missing, fails, or times out -- never a hard failure just because git isn't
# on PATH on some machine.
def _git_diff_sync(content_from: str, content_to: str,
                    fromfile: str = "before", tofile: str = "after") -> str:
    if shutil.which("git") is None:
        return _unified_diff_sync(content_from, content_to, fromfile, tofile)
    tmp_dir = tempfile.mkdtemp(prefix="personal-mcp-diff-")
    try:
        path_a = Path(tmp_dir) / "before"
        path_b = Path(tmp_dir) / "after"
        try:
            path_a.write_text(content_from, encoding="utf-8", newline="")
            path_b.write_text(content_to, encoding="utf-8", newline="")
        except OSError:
            return _unified_diff_sync(content_from, content_to, fromfile, tofile)
        try:
            # stdin=DEVNULL is NOT optional: inheriting this server's stdin (the
            # JSON-RPC pipe to the MCP client on a stdio server) is what actually
            # caused an earlier multi-minute-hang incident blamed on something
            # else entirely (see _git_project_info in layer4_personal.py).
            result = subprocess.run(
                ["git", "diff", "--no-index", "--no-color", "--",
                 str(path_a), str(path_b)],
                capture_output=True, text=True, timeout=_DIFF_TIMEOUT_SECONDS,
                stdin=subprocess.DEVNULL,
            )
        except (subprocess.TimeoutExpired, OSError):
            return _unified_diff_sync(content_from, content_to, fromfile, tofile)
        # `git diff --no-index` exits 0 (no differences) or 1 (differences
        # found) on a NORMAL run -- both are success. 2+ means a real error
        # (bad args, git itself broken), not "no diff computed here".
        if result.returncode not in (0, 1):
            return _unified_diff_sync(content_from, content_to, fromfile, tofile)
        # stdout is a str with capture_output=True+text=True, but guard anyway:
        # a None here crashed live edits at 2026-09-07 02:46 ('NoneType' object
        # has no attribute 'replace') right after the file was already written.
        return (result.stdout or "").replace(str(path_a), fromfile).replace(str(path_b), tofile)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


async def _diff_or_timeout_note(content_from: str, content_to: str,
                                 fromfile: str = "before", tofile: str = "after") -> str:
    """The actual edit/write this diff describes has already happened by the
    time this runs (in every call site) -- a timed-out diff only means the
    response can't show a preview, never that the underlying operation failed
    or was skipped.
    """
    # En máquina limitada: si el archivo es muy grande, ni intentar el diff
    # — el pico de RAM (splitlines + SequenceMatcher) es ~3-4× tamaño y
    # además tarda. La edición ya está guardada; el diff es solo preview.
    if len(content_from) + len(content_to) > _DIFF_SKIP_CHARS:
        return (f"[diff skipped — file too large ({len(content_from):,} chars) for preview. "
                f"The operation itself completed successfully; diff preview omitted to save memory.]")
    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(_diff_executor, _git_diff_sync, content_from, content_to, fromfile, tofile),
            timeout=_DIFF_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        return (f"[diff timed out after {_DIFF_TIMEOUT_SECONDS:g}s -- this file's content made "
                f"this specific diff expensive to compute. The operation itself still "
                f"completed successfully; only this diff preview is unavailable. This diff runs "
                f"in an isolated worker pool, so a slow or hung diff cannot block other "
                f"filesystem operations.]")


def _walk_files_no_symlinks(root: Path, include_dirs: bool = False):
    """Yield entries under root without following symlinks/junctions.

    A-1 (auditoría 2026-08-11): `Path.rglob()` follows intermediate symlinks, so a
    junction placed inside a `paths_allow` directory could reach content outside it
    (e.g. `.ssh`) without ever passing through `resolve_and_validate()`'s
    paths_deny/paths_allow checks. `os.walk(followlinks=False)` does not recurse
    into symlinked directories; the extra `is_symlink()` filter covers symlinked
    files, which os.walk still lists in `filenames` regardless of `followlinks`.

    include_dirs (F1, v1.4.84): also yield directories (already pruned of
    symlinks via dirnames[:]) so callers like fs_find can match both files and
    folders, matching the pre-P0.1 `rglob` behavior. Each dir is yielded once,
    at the level where os.walk visits it.
    """
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if not (Path(dirpath) / d).is_symlink()]
        if include_dirs:
            for d in dirnames:
                yield Path(dirpath) / d
        for name in filenames:
            filepath = Path(dirpath) / name
            if filepath.is_symlink():
                continue
            yield filepath


def _walk_files_prune_denied(root: Path, security, denied_counter, include_dirs: bool = False):
    """Like _walk_files_no_symlinks but PRUNES paths_deny directories (M2).

    `**/node_modules/**` matches the dir's contents but never the dir itself
    (fnmatch has no real `**`), so plain walks descend into node_modules/.venv/
    .git and filter each file — wasted I/O on huge trees. Here each directory
    is checked with SecurityValidator.is_denied_fast_dir() (direct match OR
    pattern-core match on the bare name) and pruned wholesale from dirnames
    before descending, counting 1 per pruned dir in denied_counter. Files are
    still filtered per-entry via is_denied_entry.

    The read-only deny exception is respected: a `bin` dir under a configured
    paths_deny_exception is NOT pruned (its contents keep being filtered, and
    e.g. .dll build artifacts stay readable).
    """
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        pruned = []
        for d in dirnames:
            dp = Path(dirpath) / d
            if dp.is_symlink():
                continue
            deny_pat = is_denied_entry_dir(security, dp)
            if deny_pat:
                denied_counter[deny_pat] += 1
                continue
            pruned.append(d)
        dirnames[:] = pruned
        if include_dirs:
            for d in pruned:
                yield Path(dirpath) / d
        for name in filenames:
            f = Path(dirpath) / name
            if f.is_symlink():
                continue
            deny_pat = _is_denied(security, f, "read")
            if deny_pat:
                denied_counter[deny_pat] += 1
                continue
            yield f


def _fs_search_sync(rpath: Path, regex: "re.Pattern", glob_pattern: str | None,
                     max_results: int, exclude_patterns: list[str] | None,
                     security=None) -> str:
    from collections import Counter
    matches = []
    denied_counter: Counter[str] = Counter()
    try:
        for filepath in _walk_files_prune_denied(rpath, security, denied_counter):
            if glob_pattern and glob_pattern != "*":
                rel_glob = filepath.relative_to(rpath).as_posix()
                if not fnmatch.fnmatch(rel_glob, glob_pattern.replace("\\", "/")):
                    continue
            if exclude_patterns:
                rel = str(filepath.relative_to(rpath))
                if any(fnmatch.fnmatch(rel, pat) for pat in exclude_patterns):
                    continue
            if len(matches) >= max_results:
                break
            try:
                if filepath.stat().st_size > _SEARCH_MAX_FILE_MB * 1024 * 1024:
                    continue
                for lineno, line in enumerate(filepath.read_text("utf-8", errors="replace").splitlines(), 1):
                    if regex.search(line):
                        matches.append(f"{filepath.relative_to(rpath)}:{lineno}: {line.strip()[:120]}")
                        if len(matches) >= max_results:
                            break
            except (PermissionError, OSError):
                continue
    except PermissionError as e:
        return f"Permission denied: {e}"
    base = "\n".join(matches) if matches else "No matches found"
    return base + _deny_suffix(denied_counter)


async def fs_search_impl(path: str, pattern: str, security: SecurityValidator,
                         glob_pattern: str | None = None,
                         max_results: int | None = 50,
                         exclude_patterns: list[str] | None = None) -> str:
    rpath = security.resolve_and_validate(path)
    if not rpath.is_dir():
        return f"Error: not a directory: {rpath}"
    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        return f"Error: invalid regex pattern: {e}"
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_fs_search_sync, rpath, regex, glob_pattern, max_results, exclude_patterns, security),
            timeout=_SEARCH_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        return (f"Error: search timed out after {_SEARCH_TIMEOUT_SECONDS}s. "
                f"The pattern may be too expensive (catastrophic backtracking) or the "
                f"file set too large — try a simpler pattern or a narrower glob_pattern.")


def _fs_find_sync(rpath: Path, name: str | None, min_size: int | None,
                  max_size: int | None, days_old: int | None,
                  max_results: int | None, security=None) -> str:
    from collections import Counter
    results = []
    denied_counter: Counter[str] = Counter()
    now = time.time()
    glob_name = name or "*"
    for entry in _walk_files_no_symlinks(rpath, include_dirs=True):
        if not fnmatch.fnmatch(entry.name, glob_name):
            continue
        deny_pat = _is_denied(security, entry, "read")
        if deny_pat:
            denied_counter[deny_pat] += 1
            continue
        if max_results and len(results) >= max_results:
            break
        try:
            stat = entry.stat()
            if min_size and stat.st_size < min_size:
                continue
            if max_size and stat.st_size > max_size:
                continue
            if days_old is not None:
                age_days = (now - stat.st_mtime) / 86400
                if age_days > days_old:
                    continue
            results.append(f"{entry} ({stat.st_size:,}B, {datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M')})")
        except (PermissionError, OSError):
            continue
    base = "\n".join(results) if results else "No files found"
    return base + _deny_suffix(denied_counter)


async def fs_find_impl(path: str, security: SecurityValidator, name: str | None = None,
                       min_size: int | None = None, max_size: int | None = None,
                       days_old: int | None = None,
                       max_results: int | None = 50) -> str:
    rpath = security.resolve_and_validate(path)
    if not rpath.is_dir():
        return f"Error: not a directory: {rpath}"
    # M-F3 (auditoría 2026-08-11): rglob() traversal was blocking I/O on the event
    # loop; move the whole scan off to a thread.
    # P0.1: _walk_files_no_symlinks (no sigue symlinks, fix A-1) + filtro deny por archivo.
    return await asyncio.to_thread(
        _fs_find_sync, rpath, name, min_size, max_size, days_old, max_results, security,
    )


def _fs_info_sync(rpath: Path) -> str:
    stat = rpath.stat()
    info = {
        "path": str(rpath),
        "type": "directory" if rpath.is_dir() else "file",
        "size": stat.st_size,
        "permissions": oct(stat.st_mode & 0o777),
        "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
    }
    if rpath.is_file():
        # M-F11 (auditoría 2026-08-11): reading a huge file into memory for
        # sha256 was an OOM vector. Skip the hash for files above this threshold
        # (same reasoning as fs_read's large-file warning).
        # P2: hash por chunks (antes read_bytes() de golpe hasta 100MB).
        if stat.st_size <= 100 * 1024 * 1024:
            h = hashlib.sha256()
            with open(rpath, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            info["sha256"] = h.hexdigest()
        else:
            info["sha256"] = "(skipped: file too large to hash)"
        info["extension"] = rpath.suffix
    return "\n".join(f"{k}: {v}" for k, v in info.items())


async def fs_info_impl(path: str, security: SecurityValidator) -> str:
    rpath = security.resolve_and_validate(path)
    if not await asyncio.to_thread(rpath.exists):
        return f"Error: path does not exist: {rpath}"
    # M-F3 (auditoría 2026-08-11): stat + read_bytes (for sha256) were blocking I/O
    # on the event loop; move the whole read off to a thread.
    return await asyncio.to_thread(_fs_info_sync, rpath)


async def fs_diff_impl(path_a: str, path_b: str | None, security: SecurityValidator) -> str:
    rpath_a = security.resolve_and_validate(path_a)
    # M-F2 (auditoría 2026-08-11): a nonexistent path_a used to feed its "Error:
    # not a file..." string into the diff, fabricating a fake diff. Fail early.
    if not await asyncio.to_thread(rpath_a.is_file):
        return f"Error: not a file or does not exist: {rpath_a}"
    content_a = await fs_read_impl(path_a, security, include_scan=False)
    if path_b:
        rpath_b = security.resolve_and_validate(path_b)
        if not await asyncio.to_thread(rpath_b.is_file):
            return f"Error: not a file or does not exist: {rpath_b}"
        content_b = await fs_read_impl(path_b, security, include_scan=False)
    else:
        backup = Path(path_a).with_suffix(Path(path_a).suffix + ".bak")
        # M-F2: the backup is read through the same resolve_and_validate boundary
        # as path_a (previously it was read raw from disk without validation).
        rbackup = security.resolve_and_validate(str(backup))
        if not await asyncio.to_thread(rbackup.is_file):
            return "No backup found. Provide path_b explicitly."
        content_b = await asyncio.to_thread(rbackup.read_text, "utf-8", errors="replace")
    diff = await _diff_or_timeout_note(content_b, content_a, str(path_b or backup), path_a)
    return diff or "(identical)"


async def fs_batch_impl(path: str, operation: str, target: str, security: SecurityValidator,
                        pattern: str | None = None, dry_run: bool = True) -> str:
    rpath = security.resolve_and_validate(path)
    if not rpath.is_dir():
        return f"Error: not a directory: {rpath}"
    # M-F7 (auditoría 2026-08-11): rename with no pattern did
    # `f.name.replace("", target)`, which inserts `target` between every
    # character (garbage filenames) and reported them as successful renames.
    if operation == "rename" and not pattern:
        return "Error: rename requires a non-empty pattern (the substring to replace)."
    if pattern:
        files = [f for f in rpath.iterdir() if f.is_file() and not f.is_symlink() and f.match(pattern)]
    else:
        files = [f for f in rpath.iterdir() if f.is_file() and not f.is_symlink()]
    # P0.1: omitir orígenes denied (no basta validar el dir base).
    from collections import Counter
    denied_counter: Counter[str] = Counter()
    visible = []
    for f in files:
        dp = _is_denied(security, f, "read")
        if dp:
            denied_counter[dp] += 1
            continue
        visible.append(f)
    files = visible
    security.validate_file_count(len(files))
    logger.info("fs_batch path=%s operation=%s files=%d dry_run=%s", path, operation, len(files), dry_run)
    target_path = Path(target)
    if operation in ("copy", "move"):
        # M-F6 (auditoría 2026-08-11): a target outside paths_allow raised a raw
        # PathNotAllowedError (uncaught) instead of a clean tool response.
        try:
            security.resolve_and_validate(str(target_path))
        except PathNotAllowedError as e:
            return f"Access denied: {e}"
    results = []
    for f in files:
        dest = target_path / f.name if operation in ("copy", "move") else rpath / f.name
        if dry_run:
            results.append(f"[DRY RUN] Would {operation} {f.name} -> {dest}")
        else:
            try:
                if operation == "copy":
                    shutil.copy2(f, dest)
                elif operation == "move":
                    shutil.move(str(f), str(dest))
                elif operation == "rename":
                    new_name = f.name.replace(pattern or "", target)
                    f.rename(f.parent / new_name)
                results.append(f"{operation} {f.name} -> {dest.name}")
            except OSError as e:
                results.append(f"Error {operation} {f.name}: {e}")
    base = "\n".join(results) if results else "(no files)"
    return base + _deny_suffix(denied_counter)


def _fs_snapshot_sync(rpath: Path, security=None) -> tuple[dict, Path, dict]:
    """Snapshot the tree as {relpath: {size, modified}} in a SINGLE os.walk.

    F2 (v1.4.84): the previous two-pass version (files via
    _walk_files_no_symlinks + dirs via a second os.walk) cost 2x I/O on large
    trees and inflated the deny counter (a denied dir counted 1 plus every
    denied file inside it counted N). One walk: prune denied dirs, snapshot
    non-denied dirs (size 0) and files, all deny-checked per entry.
    """
    from collections import Counter
    denied_counter: Counter[str] = Counter()
    snapshot: dict[str, dict] = {}
    for dirpath, dirnames, filenames in os.walk(rpath, followlinks=False):
        current = Path(dirpath)
        pruned = []
        for d in dirnames:
            dp = current / d
            if dp.is_symlink():
                continue
            deny_pat = _is_denied(security, dp, "read")
            if deny_pat:
                denied_counter[deny_pat] += 1
                continue
            pruned.append(d)
            try:
                st = dp.stat()
                snapshot[str(dp.relative_to(rpath))] = {
                    "size": 0,
                    "modified": st.st_mtime,
                }
            except (PermissionError, OSError):
                continue
        dirnames[:] = pruned
        for name in filenames:
            f = current / name
            if f.is_symlink():
                continue
            deny_pat = _is_denied(security, f, "read")
            if deny_pat:
                denied_counter[deny_pat] += 1
                continue
            try:
                st = f.stat()
                snapshot[str(f.relative_to(rpath))] = {
                    "size": st.st_size,
                    "modified": st.st_mtime,
                }
            except (PermissionError, OSError):
                continue
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    snapshot_path = rpath / f".snapshot_{ts}.json"
    snapshot_path.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False), encoding="utf-8")
    return snapshot, snapshot_path, denied_counter


async def fs_snapshot_impl(path: str, security: SecurityValidator) -> str:
    rpath = security.resolve_and_validate(path)
    if not rpath.is_dir():
        return f"Error: not a directory: {rpath}"
    # M-F3 (auditoría 2026-08-11): rglob + stat per entry was blocking I/O on the
    # event loop; move the whole scan + write off to a thread.
    # P0.1: walk sin symlinks + filtro deny por archivo.
    snapshot, snapshot_path, denied_counter = await asyncio.to_thread(_fs_snapshot_sync, rpath, security)
    return f"Snapshot saved: {snapshot_path} ({len(snapshot)} entries)" + _deny_suffix(denied_counter)


async def fs_create_directory_impl(path: str, security: SecurityValidator) -> str:
    rpath = security.resolve_and_validate(path)
    await asyncio.to_thread(rpath.mkdir, parents=True, exist_ok=True)
    logger.info("fs_create_directory path=%s", str(rpath))
    return f"Directory created: {rpath}"


async def fs_move_impl(source: str, destination: str, security: SecurityValidator) -> str:
    src = security.resolve_and_validate(source)
    dst = security.resolve_and_validate(destination)
    if not src.exists():
        return f"Error: source does not exist: {src}"
    if dst.exists():
        return f"Error: destination already exists: {dst}"
    if src.is_dir():
        await asyncio.to_thread(shutil.copytree, src, dst, symlinks=True)
        await asyncio.to_thread(shutil.rmtree, src)
    else:
        await asyncio.to_thread(shutil.move, str(src), str(dst))
    logger.info("fs_move path=%s -> %s", str(src), str(dst))
    return f"Moved {src} -> {dst}"


async def fs_delete_impl(path: str, security: SecurityValidator) -> str:
    # No pasar "delete" aquí: el wrapper fs_delete() ya validó el permiso vía
    # validate_tool_path(path, "delete"). Esta segunda resolución es solo para
    # obtener el Path resuelto, igual que fs_write_impl/fs_move_impl/fs_batch_impl.
    # Pasar la operación real vuelve a invocar check_granted() y consume por
    # segunda vez un grant SINGLE que solo tiene una unidad disponible.
    rpath = security.resolve_and_validate(path)
    if not rpath.exists():
        return f"Error: path does not exist: {rpath}"
    if rpath.is_dir():
        return f"Error: fs_delete only supports individual files, not directories: {rpath}"
    size = rpath.stat().st_size
    await asyncio.to_thread(rpath.unlink)
    logger.info("fs_delete path=%s size=%d", str(rpath), size)
    return f"Deleted {rpath} ({size:,} bytes)"


def _count_dir_contents_sync(rpath: Path) -> tuple[int, int]:
    """Count files and total size recursively -- read-only, no ticket needed.
    Used to show the same kind of preview Windows Explorer shows before
    deleting a folder ('this will delete N items, X MB'), not just a bare
    confirm prompt. Reuses the same os.walk() pattern already proven cheap
    by fs_disk_usage/project_git_status (measured: 131k entries in ~30s on
    this machine's real Downloads tree)."""
    file_count = 0
    total_size = 0
    for dirpath, _dirnames, filenames in os.walk(rpath):
        for fname in filenames:
            file_count += 1
            try:
                total_size += (Path(dirpath) / fname).stat().st_size
            except (OSError, PermissionError):
                continue
    return file_count, total_size


async def fs_delete_directory_impl(path: str, security: SecurityValidator) -> str:
    """Recursively delete a directory. Separate tool from fs_delete/
    fs_delete_batch (2026-08-05 design decision) rather than a 'recursive'
    flag bolted onto either of those -- an explicit tool name makes the
    intent (and the blast radius) unambiguous at the call site, same
    reasoning already applied to fs_delete_batch being its own tool instead
    of a loop parameter on fs_delete.

    Motivated by a real gap found in this session: fs_delete and
    fs_delete_batch both explicitly refuse directories
    ('only supports individual files'), and until this tool there was no
    way to delete a directory tree through personal-mcp at all -- a caller
    hit exactly this wall trying to delete a node_modules folder.
    """
    rpath = security.resolve_and_validate(path)
    if not rpath.is_dir():
        return f"Error: not a directory: {rpath}"
    file_count, total_size = await asyncio.to_thread(_count_dir_contents_sync, rpath)
    await asyncio.to_thread(shutil.rmtree, rpath)
    logger.info("fs_delete_directory path=%s files=%d size=%d", str(rpath), file_count, total_size)
    return (f"Deleted directory {rpath} "
            f"({file_count:,} file(s), {total_size:,} bytes / {total_size / 1024 / 1024:.1f} MB)")


def _delete_batch_sync(paths: list[str], security: SecurityValidator) -> tuple[list[str], int]:
    """2026-08-08 fix: whole loop now runs off-thread (see CHANGELOG)."""
    results = []
    deleted = 0
    for p in paths:
        try:
            rpath = security.resolve_and_validate(p)
            if not rpath.exists():
                logger.warning("fs_delete_batch FAIL path=%s error=not_found", p)
                results.append(f"Error: path does not exist: {rpath}")
                continue
            if rpath.is_dir():
                logger.warning("fs_delete_batch FAIL path=%s error=is_directory", p)
                results.append(f"Error: fs_delete_batch only supports individual files, not directories: {rpath}")
                continue
            size = rpath.stat().st_size
            rpath.unlink()
            deleted += 1
            results.append(f"Deleted {rpath} ({size:,} bytes)")
        except Exception as e:
            logger.warning("fs_delete_batch FAIL path=%s error=%s", p, e)
            results.append(f"Error deleting {p}: {e}")
    return results, deleted


async def fs_delete_batch_impl(paths: list[str], security: SecurityValidator) -> str:
    """Same 'don't re-pass the operation' reasoning as fs_delete_impl: the
    fs_delete_batch() wrapper already validated + consumed the batch grant via
    validate_tool_paths_batch(paths, "delete") for every path in the list, so
    each resolve_and_validate() call below uses the default operation="read"
    (deny/paths_allow check only) rather than re-checking/re-consuming "delete".

    No file-count limit here by design (2026-07-19) - matches
    PermissionManager.request_batch()/validate_tool_paths_batch(), neither of
    which caps len(paths) either. Partial failure is reported per-file rather
    than aborting the whole batch on the first error, since a delete grant is
    already consumed per-path regardless of what happens to its neighbors.

    Every failure is also logged individually (2026-08-07 fix): the return
    string used to be the only place a per-file failure reason ever existed;
    server.log only had the aggregate requested=/deleted= counts. That gap is
    exactly why the 232-vs-192 incident (2026-07-31) took this long to
    diagnose after the fact. Successes are not logged per-file -- the
    aggregate line already covers the common case.
    """
    results, deleted = await asyncio.to_thread(_delete_batch_sync, paths, security)
    logger.info("fs_delete_batch requested=%d deleted=%d", len(paths), deleted)
    summary = f"{deleted}/{len(paths)} files deleted"
    return summary + "\n" + "\n".join(results)


def _dedupe_writes(writes: list[dict]) -> tuple[list[dict], list[str]]:
    """Unlike fs_delete_batch (where a repeated path is a harmless duplicate --
    deleting the same file twice has one outcome either way), a repeated path
    here with DIFFERENT content is not a duplicate, it's an ambiguous or
    contradictory instruction: dict.fromkeys()-style dedup would silently keep
    one and discard the other's real intent without telling the caller. Paths
    repeated with IDENTICAL content dedupe silently (same reasoning as delete:
    truly harmless). Paths repeated with conflicting content are reported as
    errors and the whole batch is rejected before touching the filesystem --
    partial silent data loss is worse than a batch that requires the caller to
    resend one entry per path.
    """
    seen: dict[str, str] = {}
    conflicts: set[str] = set()
    for w in writes:
        path, content = w.get("path", ""), w.get("content", "")
        if path in seen and seen[path] != content:
            conflicts.add(path)
        seen.setdefault(path, content)
    if conflicts:
        return [], sorted(conflicts)
    deduped, seen_paths = [], set()
    for w in writes:
        path = w.get("path", "")
        if path in seen_paths:
            continue
        seen_paths.add(path)
        deduped.append(w)
    return deduped, []


def _write_batch_sync(writes: list[dict], security: SecurityValidator,
                      encoding: str = "utf-8") -> tuple[list[str], int]:
    """Whole loop off-thread, same pattern as _delete_batch_sync -- mkdir +
    write per item (fs_write_impl does the same mkdir before writing single
    files; a batch write to a not-yet-existing directory needs it just as
    much), and per-item failure logging (2026-08-07 reasoning from
    fs_delete_batch: the return string was the only place a per-file failure
    reason ever existed, which is exactly why the 232-vs-192 incident took so
    long to diagnose after the fact).
    """
    results = []
    written = 0
    for w in writes:
        p, content = w.get("path", ""), w.get("content", "")
        try:
            rpath = security.resolve_and_validate(p)
            rpath.parent.mkdir(parents=True, exist_ok=True)
            size_bytes = len(content.encode(encoding))
            # O2 (v1.4.86): helper con hint de read-only en Windows.
            write_err = _write_text_sync(rpath, content, encoding)
            if write_err:
                raise OSError(write_err)
            written += 1
            results.append(f"Written {len(content)} chars ({size_bytes:,} bytes) to {rpath}")
        except Exception as e:
            logger.warning("fs_write_batch FAIL path=%s error=%s", p, e)
            results.append(f"Error writing {p}: {e}")
    return results, written


async def fs_write_batch_impl(writes: list[dict], security: SecurityValidator) -> str:
    """Same 'don't re-pass the operation' reasoning as fs_delete_batch_impl:
    the fs_write_batch() wrapper already validated + consumed the batch grant
    via validate_tool_paths_batch(paths, "write") for every path, so
    _write_batch_sync()'s resolve_and_validate() calls use the default
    operation="read" rather than re-checking/re-consuming "write".
    """
    results, written = await asyncio.to_thread(_write_batch_sync, writes, security)
    logger.info("fs_write_batch requested=%d written=%d", len(writes), written)
    summary = f"{written}/{len(writes)} files written"
    return summary + "\n" + "\n".join(results)


def _dedupe_edits(edits: list[dict]) -> tuple[list[dict], list[str]]:
    """Same reasoning as _dedupe_writes: a repeated path with an IDENTICAL
    (old_str, new_str) pair dedupes silently; a repeated path with a
    DIFFERENT pair is an ambiguous instruction, rejected up front rather than
    silently applying one and discarding the other.
    """
    seen: dict[str, tuple] = {}
    conflicts: set[str] = set()
    for e in edits:
        path = e.get("path", "")
        pair = (e.get("old_str", ""), e.get("new_str", ""))
        if path in seen and seen[path] != pair:
            conflicts.add(path)
        seen.setdefault(path, pair)
    if conflicts:
        return [], sorted(conflicts)
    deduped, seen_paths = [], set()
    for e in edits:
        path = e.get("path", "")
        if path in seen_paths:
            continue
        seen_paths.add(path)
        deduped.append(e)
    return deduped, []


async def fs_edit_batch_impl(edits: list[dict], security: SecurityValidator,
                              grant_keys: dict[str, str] | None = None) -> str:
    """Unlike _delete_batch_sync/_write_batch_sync (whole loop off-thread in one
    asyncio.to_thread call), this loop stays in the async function: each
    iteration needs to await _diff_or_timeout_note() (itself async, wrapping
    difflib in its own to_thread+timeout) -- an async function cannot be
    called from inside a sync helper running in a worker thread. Same pattern
    already used by fs_read_multi_impl: a loop of individually-awaited async
    calls rather than one big sync helper. Each file read/write is still
    off-thread via asyncio.to_thread individually, matching fs_edit_impl.

    Same M-F1 reasoning as fs_edit_impl: check the file exists before reading,
    so a nonexistent file reports "does not exist" instead of the misleading
    "old_str not found". Same per-item failure logging as fs_delete_batch/
    fs_write_batch (2026-08-07): a batch's partial failures need to be
    diagnosable from server.log after the fact, not only from the return
    string of a single chat turn. Same "don't re-pass the operation"
    reasoning as fs_delete_batch_impl/fs_write_batch_impl: the wrapper already
    consumed the batch "write" grant via validate_tool_paths_batch(), so
    resolve_and_validate() here uses the default operation="read".

    grant_keys (2026-08-16): {path: key} from the wrapper's has_single_grant()
    peek, taken *before* validate_tool_paths_batch() consumed anything -- None
    for a path whose access came from a session/permanent grant, meaning
    nothing was consumed for it and there is nothing to refund. Only refunded
    on the two failure branches below where the file is provably untouched
    (not found, old_str absent). The bare `except Exception` branch is
    deliberately NOT refunded: write_text() may have already succeeded before
    _diff_or_timeout_note() or something else downstream raised, so we cannot
    tell from here whether the file was actually modified -- refunding on an
    ambiguous failure risks fabricating access to a file that did change.
    """
    grant_keys = grant_keys or {}
    results = []
    edited = 0
    for e in edits:
        p = e.get("path", "")
        old_s = e.get("old_str", "")
        new_s = e.get("new_str", "")
        try:
            rpath = security.resolve_and_validate(p)
            if not await asyncio.to_thread(rpath.is_file):
                logger.warning("fs_edit_batch FAIL path=%s error=not_found", p)
                results.append(f"Error: not a file or does not exist: {rpath}")
                if grant_keys.get(p):
                    security.refund_single(p, grant_keys[p])
                continue
            content = await asyncio.to_thread(rpath.read_text, encoding="utf-8")
            if not old_s:
                # A la derecha de un old_s vacío, content.replace("", new_s, 1)
                # INSERTARÍA new_s al inicio del archivo (corrupción silenciosa).
                # Igual que fs_edit_advanced_impl: rechazar en vez de escribir.
                logger.warning("fs_edit_batch FAIL path=%s error=missing_old_str", p)
                results.append(f"Error: missing 'old_str' for {p}")
                if grant_keys.get(p):
                    security.refund_single(p, grant_keys[p])
                continue
            if old_s not in content:
                logger.warning("fs_edit_batch FAIL path=%s error=old_str_not_found", p)
                results.append(f"Error: old_str not found in {p} (tip: head/tail view may have hidden it)")
                if grant_keys.get(p):
                    security.refund_single(p, grant_keys[p])
                continue
            occurrences = content.count(old_s)
            new_content = content.replace(old_s, new_s, 1)
            # O2 (v1.4.86): escritura como string de error (no excepción);
            # si falló la escritura, el archivo quedó intacto → reembolsar.
            write_err = await asyncio.to_thread(_write_text_sync, rpath, new_content, "utf-8")
            if write_err:
                logger.warning("fs_edit_batch FAIL path=%s error=%s", p, write_err)
                results.append(write_err)
                if grant_keys.get(p):
                    security.refund_single(p, grant_keys[p])
                continue
            diff = await _diff_or_timeout_note(content, new_content)
            edited += 1
            if occurrences > 1:
                results.append(f"Edited {rpath} (note: old_str appeared {occurrences} times — only first replaced):\n{diff}")
            else:
                results.append(f"Edited {rpath}:\n{diff}")
        except Exception as ex:
            logger.warning("fs_edit_batch FAIL path=%s error=%s", p, ex)
            results.append(f"Error editing {p}: {ex}")
    logger.info("fs_edit_batch requested=%d edited=%d", len(edits), edited)
    return f"{edited}/{len(edits)} files edited\n" + "\n".join(results)


async def fs_read_multi_impl(paths: list[str], security: SecurityValidator,
                              encoding: str = "utf-8", max_size_mb: int = 0) -> str:
    # P2: límite de archivos (reusa rate_limit_files_per_operation) + acumulado.
    try:
        security.validate_file_count(len(paths))
    except ValueError as e:
        return f"Error: {e}"
    try:
        max_total = int(security.config.security.max_read_multi_bytes)
    except Exception:
        max_total = 20 * 1024 * 1024
    results = []
    total = 0
    for p in paths:
        try:
            content = await fs_read_impl(p, security, encoding, max_size_mb)
            total += len(content.encode(encoding, errors="replace"))
            results.append(f"--- {p} ---\n{content}")
            if total > max_total:
                results.append(f"[truncated: cumulative limit {max_total:,} bytes exceeded]")
                break
        except Exception as e:
            results.append(f"--- {p} ---\nError: {e}")
    return "\n\n".join(results)


async def fs_list_allowed_impl(security: SecurityValidator) -> str:
    lines = ["Allowed directories:"]
    for p in security.config.security.paths_allow:
        lines.append(f"  {p} (read+write with permission)")
    lines.append(f"  {security.config.data_dir} (internal data)")
    return "\n".join(lines)


async def fs_list_with_sizes_impl(path: str, security: SecurityValidator,
                                   sort_by: str = "name") -> str:
    rpath = security.resolve_and_validate(path)
    if not rpath.is_dir():
        return f"Error: not a directory: {rpath}"
    from collections import Counter
    denied_counter: Counter[str] = Counter()
    entries = []
    with os.scandir(rpath) as it:
        for entry in it:
            # F3 (v1.4.84): filtrar deny por entrada — un .env/id_rsa no debe
            # revelar su nombre/tamaño vía este listado.
            if entry.is_symlink():
                continue
            deny_pat = _is_denied(security, Path(entry.path), "read")
            if deny_pat:
                denied_counter[deny_pat] += 1
                continue
            is_dir = entry.is_dir()
            info = entry.stat()
            entries.append({
                "name": entry.name,
                "type": "dir" if is_dir else "file",
                "size": info.st_size,
            })
    if sort_by == "size":
        entries.sort(key=lambda e: e["size"])
    else:
        entries.sort(key=lambda e: e["name"].lower())
    lines = []
    total_files = 0
    total_dirs = 0
    total_size = 0
    for e in entries:
        tag = "[DIR]" if e["type"] == "dir" else "[FILE]"
        size_str = f"{e['size']:,}B" if e['size'] < 1024 else f"{e['size']/1024:.1f}KB"
        lines.append(f"{tag} {e['name']:40s} {size_str:>10s}")
        if e["type"] == "dir":
            total_dirs += 1
        else:
            total_files += 1
        total_size += e["size"]
    summary = f"\n{'─' * 60}\n{total_files} files, {total_dirs} dirs, {total_size:,} bytes"
    base = "\n".join(lines) + summary if lines else "(empty directory)"
    return base + _deny_suffix(denied_counter)


async def fs_read_media_impl(path: str, security: SecurityValidator) -> str:
    rpath = security.resolve_and_validate(path)
    if not rpath.is_file():
        return f"Error: not a file: {rpath}"
    mime_type, _ = mimetypes.guess_type(str(rpath))
    if not mime_type or not (mime_type.startswith(("image/", "audio/"))):
        return (f"Error: not a supported media file (only image/* and audio/*): "
                f"{mime_type or 'unknown'}")
    # P2: tope antes de leer+base64 (stat barato, evita OOM).
    try:
        max_media = int(security.config.security.max_media_bytes)
    except Exception:
        max_media = 20 * 1024 * 1024
    try:
        size = rpath.stat().st_size
    except (OSError, PermissionError):
        size = 0
    if size > max_media:
        return f"Error: media file too large ({size:,} bytes, max {max_media:,} bytes)"
    data = await asyncio.to_thread(rpath.read_bytes)
    findings = None
    if security.config.security.secret_scanning_enabled:
        # O1 (v1.4.85): scan en thread + acotado a 1MB (el decode de un media
        # de 20MB completo pesaba en el event loop).
        from src.secretscanner import SCAN_MAX_CHARS
        text_content = data.decode("utf-8", errors="replace")[:SCAN_MAX_CHARS]
        findings = await asyncio.to_thread(scan_text, text_content)
        if findings:
            logger.warning("SECRET_SCAN findings=%d path=%s", len(findings), path)
    b64 = base64.b64encode(data).decode("ascii")
    result = f"data:{mime_type};base64,{b64}"
    if findings:
        result += format_findings(findings)
    return result


def _normalize_extensions(extensions: list[str] | None) -> set[str] | None:
    """Accept both '.pdf' and 'pdf' — dot-optional matching is the convention
    users expect (matches pathlib.Path.suffix semantics loosely, but tolerant
    of the form most people actually type). Case-insensitive since Windows
    filesystems are case-insensitive by default and '.PDF' vs '.pdf' should
    not be treated as different types."""
    if not extensions:
        return None
    normalized = set()
    for ext in extensions:
        ext = ext.strip().lower()
        if not ext:
            continue
        if not ext.startswith("."):
            ext = "." + ext
        normalized.add(ext)
    return normalized or None


def _find_duplicates_sync(rpath: Path, recursive: bool, extensions: set[str] | None,
                          exclude: list[str] | None = None,
                          min_size: int = 0,
                          max_size: int | None = None, security=None) -> tuple[list[dict], dict]:
    """Two-phase exact-duplicate search. No default file-count or file-size
    cap (2026-07-31 design discussion): walking + stat() is cheap even over
    thousands of files (measured: 232 files in 240ms on this machine), so a
    max_files limit would only exclude legitimate large directories like a
    real Downloads folder without saving meaningful time. Instead of caps,
    cost is controlled by only hashing when it can possibly matter: two
    files can only be byte-identical if they are already the same size, so
    phase 1 groups by exact size (near-free, no file content read) and
    phase 2 only hashes files that already share a size with at least one
    other file. A unique-sized file, however large, is never hashed.

    Since v1.4.80 the caps are OPT-IN instead of nonexistent:
    - `exclude`: fnmatch patterns (paths_deny style, same helpers as
      fs_disk_usage) — matching directories are PRUNED from the walk
      (dirnames[:] filter, before descending) and matching files skipped.
      None means nothing is excluded, exactly the pre-v1.4.80 behavior.
    - `min_size` (default 0): files smaller than min_size are skipped
      before grouping. Empty files (size 0) are ALWAYS skipped regardless
      of min_size — the consensus default of jdupes/rmlint (empty files
      are noise, not recoverable space).
    - `max_size` (default None): files larger than max_size are skipped —
      bounds hashing cost on huge files (e.g. duplicated multi-GB VM
      images) when the caller needs it. None means no cap, the
      pre-v1.4.80 behavior.
    Both filters run in phase 1, so filtered files are neither grouped nor
    hashed — the saving is real, not just cosmetic.
    """
    patterns = _normalize_exclude_patterns(exclude)
    from collections import Counter
    denied_counter: Counter[str] = Counter()
    size_groups: dict[int, list[Path]] = {}
    for dirpath, dirnames, filenames in os.walk(rpath, followlinks=False):
        current = Path(dirpath)
        dirnames[:] = [d for d in dirnames if not (current / d).is_symlink()]
        # P0.1/M2: podar dirs denied (directo + core-match de patrón, para que
        # **/node_modules/** pode el dir node_modules en sí, no solo su contenido)
        kept = []
        for d in dirnames:
            dp = current / d
            if dp.is_symlink():
                continue
            dp_denied = _is_denied(security, dp, "read") or is_denied_entry_dir(security, dp)
            if dp_denied:
                denied_counter[dp_denied] += 1
                continue
            if patterns and _excluded_by_patterns(rpath, current, d, patterns):
                continue
            kept.append(d)
        dirnames[:] = kept
        if not recursive:
            dirnames[:] = []
        for fname in filenames:
            if patterns and _excluded_by_patterns(rpath, current, fname, patterns):
                continue
            f = current / fname
            if f.is_symlink():
                continue
            dp = _is_denied(security, f, "read")
            if dp:
                denied_counter[dp] += 1
                continue
            try:
                if not f.is_file():
                    continue
                if extensions and f.suffix.lower() not in extensions:
                    continue
                size = f.stat().st_size
            except (PermissionError, OSError):
                continue
            if size == 0:
                continue
            if min_size and size < min_size:
                continue
            if max_size is not None and size > max_size:
                continue
            size_groups.setdefault(size, []).append(f)

    hash_groups: dict[str, list[tuple[Path, int]]] = {}
    for size, files in size_groups.items():
        if len(files) < 2:
            continue
        for f in files:
            try:
                h = hashlib.sha256()
                actual_size = 0
                with open(f, "rb") as fh:
                    while chunk := fh.read(1024 * 1024):
                        h.update(chunk)
                        actual_size += len(chunk)
                # M-F4 (auditoría 2026-08-11): record the size actually hashed,
                # not the phase-1 stat() size -- a file changed between phase 1
                # and phase 2 would otherwise report a stale (wrong) size.
                hash_groups.setdefault(h.hexdigest(), []).append((f, actual_size))
            except (PermissionError, OSError):
                continue

    duplicates = []
    for digest, entries in hash_groups.items():
        if len(entries) < 2:
            continue
        entries_sorted = sorted(entries, key=lambda pair: pair[0].stat().st_ctime)
        size = entries_sorted[0][1]
        duplicates.append({
            "hash": digest,
            "size": size,
            "count": len(entries_sorted),
            "files": [str(f) for f, _ in entries_sorted],
        })
    duplicates.sort(key=lambda d: -(d["size"] * (d["count"] - 1)))
    return duplicates, denied_counter


async def fs_find_duplicates_impl(path: str, security: SecurityValidator,
                                  recursive: bool = False,
                                  extensions: list[str] | None = None,
                                  exclude: list[str] | None = None,
                                  min_size: int = 0,
                                  max_size: int | None = None) -> str:
    rpath = security.resolve_and_validate(path)
    if not rpath.is_dir():
        return f"Error: not a directory: {rpath}"
    if min_size < 0:
        return f"Error: min_size must be >= 0, got {min_size}"
    if max_size is not None and max_size < min_size:
        return f"Error: max_size ({max_size}) must be >= min_size ({min_size})"
    ext_set = _normalize_extensions(extensions)
    duplicates, denied_counter = await asyncio.to_thread(
        _find_duplicates_sync, rpath, recursive, ext_set, exclude, min_size, max_size, security
    )
    logger.info("fs_find_duplicates path=%s recursive=%s groups=%d exclude=%s min_size=%d max_size=%s",
                path, recursive, len(duplicates), exclude, min_size, max_size)
    if not duplicates:
        return "No exact duplicates found" + _deny_suffix(denied_counter)
    total_wasted = sum(d["size"] * (d["count"] - 1) for d in duplicates)
    lines = [
        (f"{len(duplicates)} duplicate group(s) found. "
         f"Recoverable space: {total_wasted:,} bytes ({total_wasted / 1024 / 1024:.1f} MB)"),
        "",
    ]
    for d in duplicates:
        lines.append(f"[{d['count']} copies, {d['size']:,}B each, sha256 {d['hash'][:12]}...]")
        lines.append(f"    ORIGINAL (oldest): {d['files'][0]}")
        for f in d["files"][1:]:
            lines.append(f"    duplicate: {f}")
        lines.append("")
    return "\n".join(lines).rstrip() + _deny_suffix(denied_counter)


def _disk_usage_sync(base: Path, depth: int, exclude: list[str] | None = None,
                     min_size: int = 0,
                     max_size: int | None = None, security=None) -> tuple[list[tuple[Path, int, int]], dict]:
    """Single pass over the tree: attribute every file's size to its ancestor
    directory exactly `depth` levels under `base` (or to `base` itself if the
    file lives shallower than `depth`). One os.walk() over the whole tree
    regardless of how many buckets result — avoids re-walking shared subtrees
    once per sibling folder, which a naive "call this per-subfolder" approach
    would do.

    Returns (bucket_path, total_size, file_count) per bucket, sorted by size
    descending (2026-08-16, v1.4.79: file count added — the walk already
    iterates every filename, so counting is free).

    `exclude` (2026-08-16, v1.4.79): fnmatch patterns in paths_deny style
    ("**/node_modules/**", "node_modules", ".venv"), matched against the
    relative posix path of each directory or file. Matching directories are
    PRUNED from the walk (dirnames[:] filter, before descending) — excluding
    node_modules without pruning would still traverse it, defeating the
    purpose of the common use case (ignoring dependencies when answering
    "which folder weighs most"). Empty/None means no exclusion, exactly the
    pre-v1.4.79 behavior.

    `min_size`/`max_size` (2026-08-16, v1.4.81, same semantics as
    fs_find_duplicates): files outside the [min_size, max_size] range are
    skipped before they count toward any bucket — the report answers "which
    folder weighs most *within these bounds*" (e.g. max_size to ignore
    known multi-GB ISOs when hunting the rest of the space). Unlike
    duplicates, these filters save no I/O (the walk stats every file
    regardless) — they only change what the totals/counts mean. Empty files
    (size 0) are ALWAYS skipped, same rule as fs_find_duplicates: the count
    means "files that occupy space". Research note (rmlint manpage): empty
    files/dirs are a separate lint category there (emptyfiles/emptydirs),
    never mixed into space audits — surfacing empty DIRECTORIES would be a
    different tool, not this one.

    No cap on the number of buckets computed or files scanned (2026-08-01,
    same reasoning as fs_find_duplicates/project_git_status): the real cost
    driver is how much of the tree os.walk() has to traverse, which a count
    limit would not bound anyway. Only the *display* (top_n, in the caller)
    is truncated.
    """
    patterns = _normalize_exclude_patterns(exclude)
    from collections import Counter
    denied_counter: Counter[str] = Counter()
    buckets: dict[Path, tuple[int, int]] = {}
    base_depth = len(base.parts)
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        current = Path(dirpath)
        # P0.1/M2: no seguir symlinks + podar dirs denied (directo + core-match)
        dirnames[:] = [d for d in dirnames if not (current / d).is_symlink()]
        pruned = []
        for d in dirnames:
            dp = current / d
            dp_denied = _is_denied(security, dp, "read") or is_denied_entry_dir(security, dp)
            if dp_denied:
                denied_counter[dp_denied] += 1
            elif patterns and _excluded_by_patterns(base, current, d, patterns):
                continue
            else:
                pruned.append(d)
        # compat: cuando no hay security ni patterns, comportamiento idéntico
        if patterns and security is None:
            dirnames[:] = [
                d for d in pruned
                if not _excluded_by_patterns(base, current, d, patterns)
            ]
        else:
            dirnames[:] = pruned
        rel_depth = len(current.parts) - base_depth
        if rel_depth >= depth:
            ancestor = Path(*current.parts[:base_depth + depth])
        else:
            ancestor = base
        total = 0
        count = 0
        for fname in filenames:
            fpath = current / fname
            if fpath.is_symlink():
                continue
            dp = _is_denied(security, fpath, "read")
            if dp:
                denied_counter[dp] += 1
                continue
            if patterns and _excluded_by_patterns(base, current, fname, patterns):
                continue
            try:
                size = fpath.stat().st_size
            except (OSError, PermissionError):
                continue
            if size == 0:
                continue
            if min_size and size < min_size:
                continue
            if max_size is not None and size > max_size:
                continue
            total += size
            count += 1
        if total:
            prev_total, prev_count = buckets.get(ancestor, (0, 0))
            buckets[ancestor] = (prev_total + total, prev_count + count)
    ranked = sorted(
        ((p, s, c) for p, (s, c) in buckets.items()),
        key=lambda kv: -kv[1],
    )
    return ranked, denied_counter


def _normalize_exclude_patterns(exclude: list[str] | None) -> list[tuple[str, str]]:
    """Normalize exclude patterns to forward-slash posix form and derive a
    "core" name for each (2026-08-16, v1.4.79).

    fnmatch has no real recursive "**" semantics (it is just doubled "*"), so
    "**/node_modules/**" never matches a TOP-LEVEL node_modules — the same
    limitation already documented for paths_deny (AGENTS.md: the repo needed
    explicit duplicate patterns for the direct-child case). For exclusion that
    is the wrong default: pruning node_modules/.venv is the whole point. So
    each pattern is paired with its core — the pattern with one leading
    "**/" and one trailing "/**" stripped — and an entry matches if its bare
    name fnmatches the core (plus the full relative path vs. the full
    pattern). Examples: "**/node_modules/**" -> core "node_modules";
    "*.tmp" -> core "*.tmp"; "build/**" -> core "build".
    """
    if not exclude:
        return []
    normalized = []
    for pat in exclude:
        pat = pat.strip().replace("\\", "/")
        if not pat:
            continue
        core = pat.removeprefix("**/").removesuffix("/**")
        normalized.append((pat, core))
    return normalized


def _excluded_by_patterns(base: Path, dirpath: Path, name: str,
                          patterns: list[tuple[str, str]]) -> bool:
    """Match a directory or file entry against the exclude patterns.

    The candidate is the RELATIVE posix path (dirpath.relative_to(base) /
    name): patterns are anchored to the scanned tree, so "build/**" matches
    "proj/build/..." inside base regardless of where base lives on disk. The
    bare name is ALSO matched against each pattern's core (see
    _normalize_exclude_patterns) — a pattern like "**/node_modules/**" or
    "node_modules" matches ANY directory named node_modules at any depth,
    including a top-level one.
    """
    try:
        rel = dirpath.relative_to(base)
    except ValueError:
        rel = Path()
    candidate = str(rel / name).replace("\\", "/")
    return any(
        fnmatch.fnmatch(candidate, pat) or fnmatch.fnmatch(name, core)
        for pat, core in patterns
    )


async def fs_disk_usage_impl(path: str, security: SecurityValidator,
                              top_n: int = 15, depth: int = 1,
                              exclude: list[str] | None = None,
                              min_size: int = 0,
                              max_size: int | None = None) -> str:
    rpath = security.resolve_and_validate(path)
    if not rpath.is_dir():
        return f"Error: not a directory: {rpath}"
    if min_size < 0:
        return f"Error: min_size must be >= 0, got {min_size}"
    if max_size is not None and max_size < min_size:
        return f"Error: max_size ({max_size}) must be >= min_size ({min_size})"
    buckets, denied_counter = await asyncio.to_thread(
        _disk_usage_sync, rpath, depth, exclude, min_size, max_size, security
    )
    logger.info("fs_disk_usage path=%s depth=%d buckets=%d exclude=%s min_size=%d max_size=%s",
                path, depth, len(buckets), exclude, min_size, max_size)
    if not buckets:
        return "No files found"
    total = sum(size for _, size, _ in buckets)
    shown = buckets[:top_n]
    lines = [
        f"Uso de disco bajo {rpath} — total {total:,} bytes ({total / 1024 / 1024 / 1024:.2f} GB)",
        "",
    ]
    for p, size, count in shown:
        pct = (size / total * 100) if total else 0
        lines.append(
            f"{size:>15,} B  ({size / 1024 / 1024:8.1f} MB, {pct:5.1f}%)  "
            f"{count:,} archivo(s)  {p}"
        )
    remaining = len(buckets) - len(shown)
    if remaining > 0:
        shown_total = sum(size for _, size, _ in shown)
        other_total = total - shown_total
        lines.append(
            f"... y {remaining} carpeta(s) más, "
            f"{other_total:,} bytes ({other_total / 1024 / 1024:.1f} MB) en total"
        )
    return "\n".join(lines) + _deny_suffix(denied_counter)


def _compress_sync(rpaths: list[Path], routput: Path, security=None) -> tuple[list[str], dict]:
    from collections import Counter
    denied_counter: Counter[str] = Counter()
    added = []
    # M-F8 (auditoría 2026-08-11): when routput lives inside one of the paths
    # being compressed, the zip was written to disk first (ZipFile "w" mode) and
    # then picked up by the traversal as a member -- the zip containing itself.
    # Skip the output file explicitly.
    routput_resolved = routput.resolve()
    with zipfile.ZipFile(routput, "w", zipfile.ZIP_DEFLATED) as zf:
        for rpath in rpaths:
            if rpath.is_file():
                if rpath.resolve() == routput_resolved:
                    continue
                dp = _is_denied(security, rpath, "read")
                if dp:
                    denied_counter[dp] += 1
                    continue
                zf.write(rpath, arcname=rpath.name)
                added.append(str(rpath))
            elif rpath.is_dir():
                for f in _walk_files_prune_denied(rpath, security, denied_counter):
                    if f.resolve() == routput_resolved:
                        continue
                    arcname = str(Path(rpath.name) / f.relative_to(rpath))
                    zf.write(f, arcname=arcname)
                    added.append(str(f))
    return added, denied_counter


async def fs_compress_impl(paths: list[str], output_path: str, security: SecurityValidator) -> str:
    rpaths = []
    for p in paths:
        rp = security.resolve_and_validate(p)
        if not rp.exists():
            return f"Error: path does not exist: {rp}"
        rpaths.append(rp)
    routput = security.resolve_and_validate(output_path)
    added, denied_counter = await asyncio.to_thread(_compress_sync, rpaths, routput, security)
    logger.info("fs_compress output=%s files=%d", str(routput), len(added))
    size = routput.stat().st_size
    return f"Created {routput} ({size:,} bytes, {len(added)} file(s))" + _deny_suffix(denied_counter)


def _safe_extract_sync(rzip: Path, routput: Path, security=None) -> tuple[list[str], list[str], list[str]]:
    """Extract a zip, verifying every member's resolved destination stays
    within routput BEFORE writing it (zip slip / CVE-2007-4559-style attack:
    a member named e.g. '../../../Windows/System32/evil.dll' or with an
    absolute path). zipfile.extract()/extractall() sanitize some of this in
    modern Python but the exact guarantees have varied across versions and
    are not something to trust blindly for a tool that writes to disk on
    the caller's behalf — containment is verified explicitly here via
    Path.relative_to(), which raises if dest is not actually inside routput.
    Any member that fails this check is skipped, not silently renamed or
    partially applied.

    P0.2: pre-chequeo zip-bomb por header (archivos, bytes, ratio) + corte
    acumulado durante la escritura (el header puede mentir). Límites desde
    SecurityConfig cuando security se provee; defaults P0.2 si no.

    Returns (extracted, skipped, failed): `skipped` are zip-slip rejections,
    `failed` are members that passed containment but hit an OSError while
    writing (permission, dest is a directory, disk full) — caught per member
    so one bad entry doesn't abort the whole extraction (M-F5, 2026-08-11).
    Raises ValueError with "Error: ..." message when bomb limits trip
    (el caller lo convierte en respuesta, sin escribir nada más).
    """
    if security is not None:
        cfg = security.config.security
        max_files, max_bytes, max_ratio = cfg.max_extract_files, cfg.max_extract_bytes, cfg.max_extract_ratio
    else:
        max_files, max_bytes, max_ratio = 5000, 500 * 1024 * 1024, 100.0
    routput_resolved = routput.resolve()
    extracted = []
    skipped = []
    failed = []
    with zipfile.ZipFile(rzip, "r") as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if len(infos) > max_files:
            raise ValueError(f"Error: zip has {len(infos)} files (max {max_files})")
        total_c = sum(i.compress_size for i in infos)
        total_u = sum(i.file_size for i in infos)
        if total_u > max_bytes:
            raise ValueError(f"Error: zip uncompressed size {total_u:,} bytes (max {max_bytes:,} bytes)")
        if total_c > 0 and (total_u / total_c) > max_ratio:
            raise ValueError(
                f"Error: zip ratio suspicious ({total_u / total_c:.1f}x, max {max_ratio:.0f}x) — possible zip-bomb"
            )
        written = 0
        for info in infos:
            member = info.filename
            dest = (routput_resolved / member).resolve()
            try:
                dest.relative_to(routput_resolved)
            except ValueError:
                skipped.append(member)
                continue
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                # F5 (v1.4.84): contar bytes REALES escritos, no el tamaño
                # declarado en el header (un zip con metadata falsificada no
                # debe evadir el abort). zipfile acota las lecturas de
                # ZipExtFile al tamaño declarado, así que el desfase es teórico;
                # el contador por chunks es defensa en profundidad barata.
                with zf.open(info) as src, open(dest, "wb") as out:
                    while chunk := src.read(1024 * 1024):
                        out.write(chunk)
                        written += len(chunk)
                        if written > max_bytes:
                            raise ValueError(
                                f"Error: extraction exceeds {max_bytes:,} bytes — aborted (possible zip-bomb)"
                            )
                extracted.append(member)
            except OSError as e:
                failed.append(f"{member} ({e})")
    return extracted, skipped, failed


async def fs_extract_impl(zip_path: str, output_dir: str, security: SecurityValidator) -> str:
    rzip = security.resolve_and_validate(zip_path)
    if not rzip.is_file():
        return f"Error: not a file: {rzip}"
    routput = security.resolve_and_validate(output_dir)
    await asyncio.to_thread(routput.mkdir, parents=True, exist_ok=True)
    try:
        extracted, skipped, failed = await asyncio.to_thread(_safe_extract_sync, rzip, routput, security)
    except zipfile.BadZipFile:
        return f"Error: not a valid zip file: {rzip}"
    except ValueError as e:
        # P0.2: límites zip-bomb — mensaje "Error: ..." sin escribir más.
        return str(e)
    logger.info("fs_extract zip=%s output=%s extracted=%d skipped=%d failed=%d",
                str(rzip), str(routput), len(extracted), len(skipped), len(failed))
    lines = [f"Extracted {len(extracted)} file(s) to {routput}"]
    if skipped:
        lines.append(
            f"⚠️ Skipped {len(skipped)} member(s) with a path outside {routput} "
            f"(zip slip protection): " + ", ".join(skipped[:5])
            + (f", ... y {len(skipped) - 5} más" if len(skipped) > 5 else "")
        )
    if failed:
        lines.append(
            f"⚠️ Failed to write {len(failed)} member(s): " + ", ".join(failed[:5])
            + (f", ... y {len(failed) - 5} más" if len(failed) > 5 else "")
        )
    return "\n".join(lines)


async def fs_edit_advanced_impl(path: str, edits: list[dict[str, str]],
                                 security: SecurityValidator, dry_run: bool = False) -> str:
    rpath = security.resolve_and_validate(path)
    # Same fix as fs_edit_impl's M-F1 (2026-08-11), applied here 2026-08-15:
    # editing a nonexistent file used to fall through to a misleading
    # "'old_str' not found" -- fs_read_impl returns an error string rather
    # than raising, and the loop below would try to match old_str against
    # that error string as if it were real file content. Report the real
    # problem instead.
    if not await asyncio.to_thread(rpath.is_file):
        return f"Error: not a file or does not exist: {rpath}"
    # O1 (v1.4.85): lectura cruda, sin footer de security scan (corrupción).
    content = await fs_read_impl(path, security, include_scan=False)
    new_content = content
    match_info = []
    for i, edit in enumerate(edits):
        old_text = edit.get("old_str", "")
        new_text = edit.get("new_str", "")
        if not old_text:
            return f"Error: edit[{i}] missing 'old_str'"
        # warn if old_str appears multiple times — same duplicate issue as fs_edit
        occ = new_content.count(old_text)
        idx = new_content.find(old_text)
        if idx == -1:
            return f"Error: edit[{i}] 'old_str' not found in {path} (tip: head/tail view may have hidden it)"
        new_content = new_content[:idx] + new_text + new_content[idx + len(old_text):]
        if occ > 1:
            match_info.append(f"  Edit {i}: matched at position {idx} (note: appeared {occ} times — only first replaced)")
        else:
            match_info.append(f"  Edit {i}: matched at position {idx}")
    if dry_run:
        diff = await _diff_or_timeout_note(content, new_content)
        return (f"Dry run - would apply {len(edits)} edit(s):\n"
                + "\n".join(match_info) + "\n\nDiff:\n" + diff)
    # O2 (v1.4.86): propagar 'Error: ...' de la escritura (read-only/ACL).
    write_result = await fs_write_impl(path, new_content, security)
    if write_result.startswith("Error:"):
        return write_result
    diff = await _diff_or_timeout_note(content, new_content)
    return (f"Applied {len(edits)} edit(s).\n"
            + "\n".join(match_info) + f"\n\nDiff:\n{diff}")


def register_filesystem_tools(mcp: FastMCP, security: SecurityValidator) -> None:
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def fs_read(path: str, encoding: str = "utf-8", max_size_mb: int = 0,
                      head: int | None = None, tail: int | None = None) -> str:
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        return await fs_read_impl(path, security, encoding, max_size_mb, head, tail)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, idempotentHint=True, destructiveHint=True))
    async def fs_write(path: str, content: str, encoding: str = "utf-8", max_size_mb: int = 0) -> str:
        # Same class of bug as fs_edit (see comment there): fs_write_impl's
        # max_size_mb check runs after validate_tool_path() already consumed
        # the grant, and it's the only "Error:" path fs_write_impl has before
        # ever touching the filesystem (confirmed by reading fs_write_impl:
        # no other early return exists between the grant check and the write).
        grant_key = security.has_single_grant(path, "write")
        err = security.validate_tool_path(path, "write")
        if err:
            return err
        result = await fs_write_impl(path, content, security, encoding, max_size_mb)
        if grant_key and result.startswith("Error:"):
            security.refund_single(path, grant_key)
        return result

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, idempotentHint=False, destructiveHint=True))
    async def fs_edit(path: str, old_str: str, new_str: str) -> str:
        """Reemplaza la primera ocurrencia de `old_str` por `new_str` en el
        archivo `path`, mostrando una vista previa del diff.

        Parámetros canónicos (contrato estándar de edición):
        - `old_str`: texto a buscar (primera ocurrencia si aparece repetido).
        - `new_str`: texto de reemplazo.

        Sin un grant activo, devuelve un ticket de escritura (ver flujo de
        aprobación) en vez de escribir.
        """
        # M-Fxx (2026-08-15): validate_tool_path() consumes a SINGLE grant (if
        # that's what authorizes this call) before fs_edit_impl gets a chance
        # to check whether old_str is even present in the current file.
        # A mismatch there means the grant was spent on an attempt that never
        # touched the filesystem -- refund it so a corrected retry doesn't
        # need a brand new ticket/popup. grant_key is None (no-op refund) when
        # access came from a session/permanent grant instead, since those were
        # never consumed in the first place.
        grant_key = security.has_single_grant(path, "write")
        err = security.validate_tool_path(path, "write")
        if err:
            return err
        result = await fs_edit_impl(path, old_str, new_str, security)
        if grant_key and result.startswith("Error:"):
            security.refund_single(path, grant_key)
        return result

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def fs_list(path: str, pattern: str | None = None, max_results: int | None = 100,
                      recursive: bool = False) -> str:
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        return await fs_list_impl(path, security, pattern, max_results, recursive)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def fs_tree(path: str, max_depth: int = 3,
                      exclude_patterns: list[str] | None = None) -> str:
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        return await fs_tree_impl(path, security, max_depth, exclude_patterns)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def fs_search(path: str, pattern: str, glob_pattern: str | None = None,
                        max_results: int | None = 50,
                        exclude_patterns: list[str] | None = None) -> str:
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        return await fs_search_impl(path, pattern, security, glob_pattern, max_results, exclude_patterns)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def fs_find(path: str, name: str | None = None, min_size: int | None = None,
                      max_size: int | None = None, days_old: int | None = None,
                      max_results: int | None = 50) -> str:
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        return await fs_find_impl(path, security, name, min_size, max_size, days_old, max_results)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def fs_info(path: str) -> str:
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        return await fs_info_impl(path, security)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def fs_diff(path_a: str, path_b: str | None = None) -> str:
        err = security.validate_tool_path(path_a, "read")
        if err:
            return err
        if path_b:
            err = security.validate_tool_path(path_b, "read")
            if err:
                return err
        return await fs_diff_impl(path_a, path_b, security)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, idempotentHint=False, destructiveHint=True))
    async def fs_batch(path: str, operation: str, target: str,
                       pattern: str | None = None, dry_run: bool = True) -> str:
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        # Only validate write permission on target when not a dry run — a dry run
        # never touches the filesystem, so consuming a SINGLE grant for it would
        # silently burn the token before the real operation runs.
        if not dry_run:
            err = security.validate_tool_path(target, "write")
            if err:
                return err
        return await fs_batch_impl(path, operation, target, security, pattern, dry_run)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, idempotentHint=True, destructiveHint=False))
    async def fs_snapshot(path: str) -> str:
        err = security.validate_tool_path(path, "write")
        if err:
            return err
        return await fs_snapshot_impl(path, security)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, idempotentHint=True, destructiveHint=False))
    async def fs_create_directory(path: str) -> str:
        err = security.validate_tool_path(path, "write")
        if err:
            return err
        return await fs_create_directory_impl(path, security)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, idempotentHint=False, destructiveHint=True))
    async def fs_move(source: str, destination: str) -> str:
        err = security.validate_tool_path(source, "read")
        if err:
            return err
        err = security.validate_tool_path(destination, "write")
        if err:
            return err
        return await fs_move_impl(source, destination, security)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, idempotentHint=False, destructiveHint=True))
    async def fs_delete(path: str) -> str:
        err = security.validate_tool_path(path, "delete")
        if err:
            return err
        return await fs_delete_impl(path, security)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, idempotentHint=False, destructiveHint=True))
    async def fs_delete_directory(path: str) -> str:
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        rpath = security.resolve_and_validate(path)
        if not rpath.is_dir():
            return f"Error: not a directory: {rpath}"
        # P2: validar delete ANTES del walk costoso (antes se contaba con solo
        # grant read). Sin grant delete → preview sin conteo + ticket.
        # Con grant → el impl cuenta y borra (conteo único, sin doble walk).
        derr = security.validate_tool_path(path, "delete")
        if derr:
            return (
                f"About to delete directory: {rpath}\n"
                f"Contains: unknown (approve first to preview)\n\n" + derr
            )
        return await fs_delete_directory_impl(path, security)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, idempotentHint=False, destructiveHint=True))
    async def fs_delete_batch(paths: list[str]) -> str:
        if not paths:
            return "Error: empty paths list"
        # Dedupe before anything else touches `paths` (2026-08-07 fix, incident
        # 2026-07-31 22:39: a 232-path batch deleted only 192 -- root cause was
        # duplicate entries in the caller's list. approve() grants exactly one
        # SINGLE unit per resolved path (dict overwrite on repeated targets),
        # but validate_tool_paths_batch()'s consume loop ignores
        # check_granted()'s return value, so a duplicate's second occurrence
        # silently fails to consume a (non-existent) second grant while the
        # batch is still reported as fully authorized. fs_delete_batch_impl
        # then deletes the first occurrence and hits FileNotFoundError on the
        # second -- a false "error" for a file that was actually deleted.
        deduped = list(dict.fromkeys(paths))
        if len(deduped) != len(paths):
            logger.warning("fs_delete_batch dedup requested=%d unique=%d", len(paths), len(deduped))
        err = security.validate_tool_paths_batch(deduped, "delete")
        if err:
            return err
        return await fs_delete_batch_impl(deduped, security)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, idempotentHint=False, destructiveHint=True))
    async def fs_write_batch(writes: list[dict]) -> str:
        if not writes:
            return "Error: empty writes list"
        # A repeated path with identical content dedupes silently (same
        # reasoning as fs_delete_batch); a repeated path with DIFFERENT
        # content is an ambiguous instruction, not a duplicate -- rejected
        # up front instead of silently keeping one and discarding the other.
        deduped, conflicts = _dedupe_writes(writes)
        if conflicts:
            return (
                "Error: conflicting content for the same path(s) in this batch "
                "(each path can appear once, or repeated with identical content): "
                + ", ".join(conflicts)
            )
        paths = [w.get("path", "") for w in deduped]
        err = security.validate_tool_paths_batch(paths, "write")
        if err:
            return err
        return await fs_write_batch_impl(deduped, security)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, idempotentHint=False, destructiveHint=True))
    async def fs_edit_batch(edits: list[dict]) -> str:
        """Edita varios archivos en una sola llamada, con un solo ticket y
        código de confirmación para la lista completa.

        Cada entrada de `edits` usa las claves canónicas:
        - `path`: ruta del archivo a editar.
        - `old_str`: texto a buscar (primera ocurrencia si aparece repetido).
        - `new_str`: texto de reemplazo.

        Una misma ruta repetida con el mismo par `(old_str, new_str)` dedup
        sin error; con un par distinto, el batch completo se rechaza antes de
        tocar el disco (instrucción ambigua). Resumen `N/M files edited` con
        resultados y fallos por archivo.
        """
        if not edits:
            return "Error: empty edits list"
        # Same reasoning as fs_write_batch: identical repeated edits dedupe
        # silently, conflicting repeated edits are rejected up front.
        deduped, conflicts = _dedupe_edits(edits)
        if conflicts:
            return (
                "Error: conflicting old_str/new_str for the same path(s) "
                "in this batch (each path can appear once, or repeated with an "
                "identical edit): " + ", ".join(conflicts)
            )
        paths = [e.get("path", "") for e in deduped]
        # Peek before validate_tool_paths_batch() consumes anything (2026-08-16,
        # same reasoning as fs_edit/fs_edit_advanced/fs_write): a stale
        # old_str on any single path in the batch must not cost that path's
        # grant if nothing was actually written for it.
        grant_keys = {p: security.has_single_grant(p, "write") for p in paths}
        err = security.validate_tool_paths_batch(paths, "write")
        if err:
            return err
        return await fs_edit_batch_impl(deduped, security, grant_keys)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def fs_read_multi(paths: list[str], encoding: str = "utf-8",
                             max_size_mb: int = 0) -> str:
        if not paths:
            return "Error: empty paths list"
        return await fs_read_multi_impl(paths, security, encoding, max_size_mb)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def fs_list_allowed() -> str:
        return await fs_list_allowed_impl(security)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def fs_list_with_sizes(path: str, sort_by: str = "name") -> str:
        if sort_by not in ("name", "size"):
            return "Error: sort_by must be 'name' or 'size'"
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        return await fs_list_with_sizes_impl(path, security, sort_by)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def fs_read_media(path: str) -> str:
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        return await fs_read_media_impl(path, security)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def fs_find_duplicates(path: str, recursive: bool = False,
                                  extensions: list[str] | None = None,
                                  exclude: list[str] | None = None,
                                  min_size: int = 0,
                                  max_size: int | None = None) -> str:
        """Busca archivos con contenido idéntico (SHA256) bajo `path` — la
        respuesta "qué está repetido" (complementa a `fs_disk_usage`, que
        responde "qué carpeta pesa más").

        Dos fases: primero agrupa por tamaño exacto (stat, sin leer
        contenido — un archivo de tamaño único, por grande que sea, nunca se
        hashea), y solo hashea los grupos con 2+ archivos del mismo tamaño.
        Cada grupo reporta N copias, tamaño, SHA256 (12 chars), el ORIGINAL
        (el más viejo por st_ctime) y los duplicados, ordenado por espacio
        desperdiciado (size * (copias - 1)) descendente.

        `recursive` (default false): solo archivos directos de `path`; true
        recorre subcarpetas. `extensions` (default None): filtrar por
        extensión — acepta ".pdf" o "pdf", case-insensitive.

        Filtros opcionales (v1.4.80, todos opt-in — el default es el
        comportamiento histórico sin ellos):
        - `exclude`: patrones fnmatch estilo paths_deny ("**/node_modules/**",
          "node_modules", ".venv", "*.tmp"). Las carpetas que matchean se
          PODAN del recorrido (no se desciende a ellas — excluir node_modules
          sin podar no ahorraría el tiempo de hashear miles de dependencias
          repetidas); los archivos que matchean se omiten. Un patrón desnudo
          como "node_modules" matchea cualquier carpeta con ese nombre a
          cualquier profundidad. Default None: nada se excluye.
        - `min_size` (default 0): ignora archivos de tamaño < min_size.
          Los archivos VACÍOS (size 0) se ignoran siempre, sin importar este
          valor — el consenso de jdupes/rmlint: los vacíos son ruido, no
          espacio recuperable. Pasar min_size=1024 filtra todo lo menor a 1 KB.
        - `max_size` (default None): ignora archivos de tamaño > max_size —
          acota el coste de hashear archivos enormes (ej. imágenes de VM de
          varios GB duplicadas) cuando hace falta. None = sin tope.

        Solo lectura — no borra nada. Sin límite de archivos escaneados;
        para limpiar, pasar las rutas marcadas `duplicate:` a
        `fs_delete_batch` siguiendo el flujo de ticket/confirm_code.
        """
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        return await fs_find_duplicates_impl(path, security, recursive,
                                             extensions, exclude, min_size, max_size)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def fs_disk_usage(path: str, top_n: int = 15, depth: int = 1,
                             exclude: list[str] | None = None,
                             min_size: int = 0,
                             max_size: int | None = None) -> str:
        """Uso de disco por carpeta bajo `path`, agrupado a `depth` niveles.

        Cada archivo se atribuye a su carpeta ancestro exactamente `depth`
        niveles bajo `path` (o a `path` mismo si vive más superficial). Devuelve
        las `top_n` carpetas que más pesan con tamaño, porcentaje del total y
        número de archivos, ordenadas descendentemente.

        Semántica de `depth` (v1.4.79, documentado): los ancestros intermedios
        NO aparecen como bucket propio — con `depth=2`, el archivo en
        `a/b/c/x` se atribuye a `a/b`, no a `a`. `a` solo aparece como bucket
        si contiene archivos directos (esos caen a `path` mismo, no a `a`).

        `exclude` (v1.4.79): patrones fnmatch estilo paths_deny ("**/node_modules/**",
        "node_modules", ".venv") contra la ruta relativa de cada entrada — un
        patrón desnudo como "node_modules" matchea cualquier carpeta con ese
        nombre a cualquier profundidad. Las carpetas que matchean se PODAN del
        recorrido (no se desciende a ellas); los archivos que matchean se
        omiten del conteo. Default None: nada se excluye (comportamiento
        previo a v1.4.79).

        Filtros de tamaño opt-in (v1.4.81, misma semántica que
        fs_find_duplicates; el default conserva el comportamiento histórico):
        - `min_size` (default 0): ignora archivos de tamaño < min_size.
          Los archivos VACÍOS (size 0) se ignoran SIEMPRE — el conteo por
          bucket significa "archivos que ocupan espacio" (mismo criterio que
          fs_find_duplicates, consenso jdupes/rmlint; en rmlint los vacíos
          son una categoría aparte, emptyfiles/emptydirs, no parte de la
          auditoría de espacio). Nota: encontrar carpetas vacías sería una
          tool distinta, no esta.
        - `max_size` (default None): ignora archivos de tamaño > max_size —
          responde "qué pesa más, dentro de estos límites" (ej. ignorar ISOs
          de varios GB ya conocidos al cazar el resto del espacio).
        A diferencia de duplicados, estos filtros NO ahorran I/O (el walk
        igualmente stastea cada archivo) — solo cambian el significado del
        total y los conteos.

        Solo lectura; sin límite de carpetas ni de archivos escaneados — solo
        la salida (top_n) se trunca.
        """
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        return await fs_disk_usage_impl(path, security, top_n, depth, exclude,
                                        min_size, max_size)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, idempotentHint=True, destructiveHint=False))
    async def fs_compress(paths: list[str], output_path: str) -> str:
        if not paths:
            return "Error: empty paths list"
        for p in paths:
            err = security.validate_tool_path(p, "read")
            if err:
                return err
        err = security.validate_tool_path(output_path, "write")
        if err:
            return err
        return await fs_compress_impl(paths, output_path, security)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, idempotentHint=False, destructiveHint=True))
    async def fs_extract(zip_path: str, output_dir: str) -> str:
        err = security.validate_tool_path(zip_path, "read")
        if err:
            return err
        err = security.validate_tool_path(output_dir, "write")
        if err:
            return err
        return await fs_extract_impl(zip_path, output_dir, security)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, idempotentHint=False, destructiveHint=True))
    async def fs_edit_advanced(path: str, edits: list[dict[str, str]],
                                dry_run: bool = False) -> str:
        """Aplica una lista ordenada de ediciones sobre un único archivo
        `path`, con vista previa de diff o dry-run.

        Cada entrada de `edits` usa las claves canónicas:
        - `old_str`: texto a buscar (primera ocurrencia si aparece repetido).
        - `new_str`: texto de reemplazo.

        Las ediciones se aplican en orden; una entrada sin `old_str` o con un
        `old_str` inexistente se rechaza sin tocar el archivo. `dry_run=true`
        muestra la vista previa sin escribir nada y sin consumir el grant.
        """
        # Same reasoning as fs_edit (see comment there): validate_tool_path()
        # consumes a SINGLE grant, if that's what authorizes this call, before
        # any old_str match is checked. Both early-return failure paths below
        # (empty edits, and every "Error:" return from the impl) happen after
        # that consumption without ever touching the filesystem.
        grant_key = security.has_single_grant(path, "write")
        err = security.validate_tool_path(path, "write")
        if err:
            return err
        if not edits:
            if grant_key:
                security.refund_single(path, grant_key)
            return "Error: edits list is empty"
        result = await fs_edit_advanced_impl(path, edits, security, dry_run)
        # dry_run never touches the filesystem regardless of whether the
        # match preview succeeded or failed -- refund unconditionally, not
        # just on "Error:", or a successful dry run still burns the grant.
        if grant_key and (dry_run or result.startswith("Error:")):
            security.refund_single(path, grant_key)
        return result
