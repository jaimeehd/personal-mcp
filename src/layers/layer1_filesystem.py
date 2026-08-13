import asyncio
import base64
import difflib
import fnmatch
import hashlib
import json
import mimetypes
import os
import re
import shutil
import time
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from src.log import get_logger, timed
from src.secretscanner import format_findings, scan_text
from src.security import PathNotAllowedError, SecurityValidator

logger = get_logger("layer1_filesystem")

async def fs_read_impl(path: str, security: SecurityValidator, encoding: str = "utf-8",
                       max_size_mb: int = 0,
                       head: int | None = None, tail: int | None = None) -> str:
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
        if security.config.security.secret_scanning_enabled:
            findings = scan_text(content)
            if findings:
                content += format_findings(findings)
                logger.warning("SECRET_SCAN findings=%d path=%s", len(findings), path)
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
    size_bytes = len(content.encode(encoding))
    if max_size_mb and size_bytes > max_size_mb * 1024 * 1024:
        return f"Error: content too large ({size_bytes / 1024 / 1024:.1f}MB). Max: {max_size_mb}MB"
    logger.info("fs_write path=%s size=%d", str(rpath), size_bytes)
    with timed("mkdir", path=str(rpath.parent)):
        await asyncio.to_thread(rpath.parent.mkdir, parents=True, exist_ok=True)
    with timed("write_text", path=str(rpath), size=size_bytes):
        await asyncio.to_thread(rpath.write_text, content, encoding=encoding)
    return f"Written {len(content)} chars ({size_bytes:,} bytes) to {rpath}"


async def fs_edit_impl(path: str, old_string: str, new_string: str, security: SecurityValidator) -> str:
    rpath = security.resolve_and_validate(path)
    # M-F1 (auditoría 2026-08-11): editing a nonexistent file used to fall through
    # to a misleading "old_string not found" (fs_read_impl returns an error string
    # rather than raising). Report the real problem instead.
    if not await asyncio.to_thread(rpath.is_file):
        return f"Error: not a file or does not exist: {rpath}"
    content = await fs_read_impl(path, security)
    if old_string not in content:
        return f"Error: old_string not found in {path}"
    new_content = content.replace(old_string, new_string, 1)
    await fs_write_impl(path, new_content, security)
    diff = await _diff_or_timeout_note(content, new_content)
    return f"Applied edit. Diff:\n{diff}"


def _fs_list_sync(rpath: Path, pattern: str | None, max_results: int | None,
                  recursive: bool) -> list[dict]:
    entries = []
    if recursive:
        for root, dirs, files in os.walk(rpath):
            root_rel = Path(root).relative_to(rpath)
            for name in sorted(dirs + files):
                if pattern and not fnmatch.fnmatch(name, pattern):
                    continue
                full = Path(root) / name
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
                    return entries
    else:
        with os.scandir(rpath) as it:
            scan_entries = sorted(it, key=lambda e: e.name)
            for scan_entry in scan_entries:
                if pattern and not fnmatch.fnmatch(scan_entry.name, pattern):
                    continue
                is_dir = scan_entry.is_dir()
                info = scan_entry.stat()
                entries.append({
                    "name": scan_entry.name,
                    "type": "dir" if is_dir else "file",
                    "size": info.st_size if not is_dir else 0,
                    "modified": datetime.fromtimestamp(
                        info.st_mtime, tz=UTC
                    ).isoformat(),
                })
                if max_results and len(entries) >= max_results:
                    return entries
    return entries


async def fs_list_impl(path: str, security: SecurityValidator, pattern: str | None = None,
                       max_results: int | None = 100, recursive: bool = False) -> str:
    rpath = security.resolve_and_validate(path)
    if not rpath.is_dir():
        return f"Error: not a directory: {rpath}"
    # M-F3 (auditoría 2026-08-11): os.walk/scandir + stat per entry was blocking I/O
    # on the event loop; move the whole walk off to a thread.
    try:
        entries = await asyncio.to_thread(_fs_list_sync, rpath, pattern, max_results, recursive)
    except PermissionError as e:
        return f"Permission denied: {e}"
    lines = []
    for e in entries:
        tag = "dir" if e["type"] == "dir" else "file"
        size_str = f"{e['size']:,}B" if e["size"] < 1024 else f"{e['size']/1024:.1f}KB"
        lines.append(f"{tag:4s} {e['name']:40s} {size_str:10s} {e['modified'][:19]}")
    return "\n".join(lines) if lines else "(empty directory)"


def _fs_tree_sync(rpath: Path, max_depth: int, exclude_patterns: list[str] | None) -> str:
    def _should_exclude(name: str) -> bool:
        if not exclude_patterns:
            return False
        return any(fnmatch.fnmatch(name, pat) for pat in exclude_patterns)

    def _tree(dir_path: Path, prefix: str = "", depth: int = 0) -> list[str]:
        if depth > max_depth:
            return [f"{prefix}└── ..."]
        lines = []
        entries = sorted(dir_path.iterdir())
        for i, entry in enumerate(entries):
            if _should_exclude(entry.name):
                continue
            is_last = i == len(entries) - 1
            connector = "└── " if is_last else "├── "
            lines.append(f"{prefix}{connector}{entry.name}/" if entry.is_dir() else f"{prefix}{connector}{entry.name}")
            if entry.is_dir():
                ext = "    " if is_last else "│   "
                lines.extend(_tree(entry, prefix + ext, depth + 1))
        return lines

    result = [f"{rpath.name}/"]
    result.extend(_tree(rpath))
    return "\n".join(result)


async def fs_tree_impl(path: str, security: SecurityValidator, max_depth: int = 3,
                       exclude_patterns: list[str] | None = None) -> str:
    rpath = security.resolve_and_validate(path)
    if not rpath.is_dir():
        return f"Error: not a directory: {rpath}"
    # M-F3 (auditoría 2026-08-11): recursive iterdir() was blocking I/O on the
    # event loop; move the whole traversal off to a thread.
    return await asyncio.to_thread(_fs_tree_sync, rpath, max_depth, exclude_patterns)


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
_DIFF_TIMEOUT_SECONDS = 10.0


def _unified_diff_sync(content_from: str, content_to: str,
                        fromfile: str = "before", tofile: str = "after") -> str:
    return "".join(difflib.unified_diff(
        content_from.splitlines(keepends=True),
        content_to.splitlines(keepends=True),
        fromfile=fromfile, tofile=tofile,
    ))


async def _diff_or_timeout_note(content_from: str, content_to: str,
                                 fromfile: str = "before", tofile: str = "after") -> str:
    """The actual edit/write this diff describes has already happened by the
    time this runs (in every call site) -- a timed-out diff only means the
    response can't show a preview, never that the underlying operation failed
    or was skipped.
    """
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_unified_diff_sync, content_from, content_to, fromfile, tofile),
            timeout=_DIFF_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        return (f"[diff timed out after {_DIFF_TIMEOUT_SECONDS}s -- this file's content made "
                f"this specific diff expensive to compute. The operation itself still "
                f"completed successfully; only this diff preview is unavailable.]")


def _walk_files_no_symlinks(root: Path):
    """Yield regular files under root without following symlinks/junctions.

    A-1 (auditoría 2026-08-11): `Path.rglob()` follows intermediate symlinks, so a
    junction placed inside a `paths_allow` directory could reach content outside it
    (e.g. `.ssh`) without ever passing through `resolve_and_validate()`'s
    paths_deny/paths_allow checks. `os.walk(followlinks=False)` does not recurse
    into symlinked directories; the extra `is_symlink()` filter covers symlinked
    files, which os.walk still lists in `filenames` regardless of `followlinks`.
    """
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if not (Path(dirpath) / d).is_symlink()]
        for name in filenames:
            filepath = Path(dirpath) / name
            if filepath.is_symlink():
                continue
            yield filepath


def _fs_search_sync(rpath: Path, regex: "re.Pattern", glob_pattern: str | None,
                     max_results: int, exclude_patterns: list[str] | None) -> str:
    matches = []
    try:
        for filepath in _walk_files_no_symlinks(rpath):
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
    return "\n".join(matches) if matches else "No matches found"


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
            asyncio.to_thread(_fs_search_sync, rpath, regex, glob_pattern, max_results, exclude_patterns),
            timeout=_SEARCH_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        return (f"Error: search timed out after {_SEARCH_TIMEOUT_SECONDS}s. "
                f"The pattern may be too expensive (catastrophic backtracking) or the "
                f"file set too large — try a simpler pattern or a narrower glob_pattern.")


def _fs_find_sync(rpath: Path, name: str | None, min_size: int | None,
                  max_size: int | None, days_old: int | None,
                  max_results: int | None) -> str:
    results = []
    now = time.time()
    for entry in rpath.rglob(name or "*"):
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
    return "\n".join(results) if results else "No files found"


async def fs_find_impl(path: str, security: SecurityValidator, name: str | None = None,
                       min_size: int | None = None, max_size: int | None = None,
                       days_old: int | None = None,
                       max_results: int | None = 50) -> str:
    rpath = security.resolve_and_validate(path)
    if not rpath.is_dir():
        return f"Error: not a directory: {rpath}"
    # M-F3 (auditoría 2026-08-11): rglob() traversal was blocking I/O on the event
    # loop; move the whole scan off to a thread.
    return await asyncio.to_thread(
        _fs_find_sync, rpath, name, min_size, max_size, days_old, max_results,
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
        if stat.st_size <= 100 * 1024 * 1024:
            info["sha256"] = hashlib.sha256(rpath.read_bytes()).hexdigest()
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
    content_a = await fs_read_impl(path_a, security)
    if path_b:
        rpath_b = security.resolve_and_validate(path_b)
        if not await asyncio.to_thread(rpath_b.is_file):
            return f"Error: not a file or does not exist: {rpath_b}"
        content_b = await fs_read_impl(path_b, security)
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
        files = [f for f in rpath.iterdir() if f.is_file() and f.match(pattern)]
    else:
        files = [f for f in rpath.iterdir() if f.is_file()]
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
    return "\n".join(results)


def _fs_snapshot_sync(rpath: Path) -> tuple[dict, Path]:
    snapshot = {}
    for entry in sorted(rpath.rglob("*")):
        try:
            stat = entry.stat()
            snapshot[str(entry.relative_to(rpath))] = {
                "size": stat.st_size,
                "modified": stat.st_mtime,
            }
        except (PermissionError, OSError):
            continue
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    snapshot_path = rpath / f".snapshot_{ts}.json"
    snapshot_path.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False), encoding="utf-8")
    return snapshot, snapshot_path


async def fs_snapshot_impl(path: str, security: SecurityValidator) -> str:
    rpath = security.resolve_and_validate(path)
    if not rpath.is_dir():
        return f"Error: not a directory: {rpath}"
    # M-F3 (auditoría 2026-08-11): rglob + stat per entry was blocking I/O on the
    # event loop; move the whole scan + write off to a thread.
    snapshot, snapshot_path = await asyncio.to_thread(_fs_snapshot_sync, rpath)
    return f"Snapshot saved: {snapshot_path} ({len(snapshot)} entries)"


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


async def fs_read_multi_impl(paths: list[str], security: SecurityValidator,
                              encoding: str = "utf-8", max_size_mb: int = 0) -> str:
    results = []
    for p in paths:
        try:
            content = await fs_read_impl(p, security, encoding, max_size_mb)
            results.append(f"--- {p} ---\n{content}")
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
    entries = []
    with os.scandir(rpath) as it:
        for entry in it:
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
    return "\n".join(lines) + summary if lines else "(empty directory)"


async def fs_read_media_impl(path: str, security: SecurityValidator) -> str:
    rpath = security.resolve_and_validate(path)
    if not rpath.is_file():
        return f"Error: not a file: {rpath}"
    mime_type, _ = mimetypes.guess_type(str(rpath))
    if not mime_type or not (mime_type.startswith(("image/", "audio/"))):
        return (f"Error: not a supported media file (only image/* and audio/*): "
                f"{mime_type or 'unknown'}")
    data = await asyncio.to_thread(rpath.read_bytes)
    findings = None
    if security.config.security.secret_scanning_enabled:
        text_content = data.decode("utf-8", errors="replace")
        findings = scan_text(text_content)
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


def _find_duplicates_sync(rpath: Path, recursive: bool, extensions: set[str] | None) -> list[dict]:
    """Two-phase exact-duplicate search, deliberately with no file-count or
    file-size cap (2026-07-31 design discussion): walking + stat() is cheap
    even over thousands of files (measured: 232 files in 240ms on this
    machine), so a max_files limit would only exclude legitimate large
    directories like a real Downloads folder without saving meaningful time.
    A max_file_size limit would defeat the actual use case (finding files
    that waste the most disk space), so instead of size caps, cost is
    controlled by only hashing when it can possibly matter: two files can
    only be byte-identical if they are already the same size, so phase 1
    groups by exact size (near-free, no file content read) and phase 2 only
    hashes files that already share a size with at least one other file.
    A unique-sized file, however large, is never hashed.
    """
    size_groups: dict[int, list[Path]] = {}
    iterator = rpath.rglob("*") if recursive else rpath.iterdir()
    for entry in iterator:
        try:
            if not entry.is_file():
                continue
            if extensions and entry.suffix.lower() not in extensions:
                continue
            size = entry.stat().st_size
            size_groups.setdefault(size, []).append(entry)
        except (PermissionError, OSError):
            continue

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
    return duplicates


async def fs_find_duplicates_impl(path: str, security: SecurityValidator,
                                   recursive: bool = False,
                                   extensions: list[str] | None = None) -> str:
    rpath = security.resolve_and_validate(path)
    if not rpath.is_dir():
        return f"Error: not a directory: {rpath}"
    ext_set = _normalize_extensions(extensions)
    duplicates = await asyncio.to_thread(_find_duplicates_sync, rpath, recursive, ext_set)
    logger.info("fs_find_duplicates path=%s recursive=%s groups=%d", path, recursive, len(duplicates))
    if not duplicates:
        return "No exact duplicates found"
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
    return "\n".join(lines).rstrip()


def _disk_usage_sync(base: Path, depth: int) -> list[tuple[Path, int]]:
    """Single pass over the tree: attribute every file's size to its ancestor
    directory exactly `depth` levels under `base` (or to `base` itself if the
    file lives shallower than `depth`). One os.walk() over the whole tree
    regardless of how many buckets result — avoids re-walking shared subtrees
    once per sibling folder, which a naive "call this per-subfolder" approach
    would do.

    No cap on the number of buckets computed or files scanned (2026-08-01,
    same reasoning as fs_find_duplicates/project_git_status): the real cost
    driver is how much of the tree os.walk() has to traverse, which a count
    limit would not bound anyway. Only the *display* (top_n, in the caller)
    is truncated.
    """
    buckets: dict[Path, int] = {}
    base_depth = len(base.parts)
    for dirpath, _dirnames, filenames in os.walk(base):
        current = Path(dirpath)
        rel_depth = len(current.parts) - base_depth
        if rel_depth >= depth:
            ancestor = Path(*current.parts[:base_depth + depth])
        else:
            ancestor = base
        total = 0
        for fname in filenames:
            try:
                total += (current / fname).stat().st_size
            except (OSError, PermissionError):
                continue
        if total:
            buckets[ancestor] = buckets.get(ancestor, 0) + total
    return sorted(buckets.items(), key=lambda kv: -kv[1])


async def fs_disk_usage_impl(path: str, security: SecurityValidator,
                              top_n: int = 15, depth: int = 1) -> str:
    rpath = security.resolve_and_validate(path)
    if not rpath.is_dir():
        return f"Error: not a directory: {rpath}"
    buckets = await asyncio.to_thread(_disk_usage_sync, rpath, depth)
    logger.info("fs_disk_usage path=%s depth=%d buckets=%d", path, depth, len(buckets))
    if not buckets:
        return "No files found"
    total = sum(size for _, size in buckets)
    shown = buckets[:top_n]
    lines = [
        f"Uso de disco bajo {rpath} — total {total:,} bytes ({total / 1024 / 1024 / 1024:.2f} GB)",
        "",
    ]
    for p, size in shown:
        pct = (size / total * 100) if total else 0
        lines.append(f"{size:>15,} B  ({size / 1024 / 1024:8.1f} MB, {pct:5.1f}%)  {p}")
    remaining = len(buckets) - len(shown)
    if remaining > 0:
        shown_total = sum(size for _, size in shown)
        other_total = total - shown_total
        lines.append(
            f"... y {remaining} carpeta(s) más, "
            f"{other_total:,} bytes ({other_total / 1024 / 1024:.1f} MB) en total"
        )
    return "\n".join(lines)


def _compress_sync(rpaths: list[Path], routput: Path) -> list[str]:
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
                zf.write(rpath, arcname=rpath.name)
                added.append(str(rpath))
            elif rpath.is_dir():
                for f in _walk_files_no_symlinks(rpath):
                    if f.resolve() == routput_resolved:
                        continue
                    arcname = str(Path(rpath.name) / f.relative_to(rpath))
                    zf.write(f, arcname=arcname)
                    added.append(str(f))
    return added


async def fs_compress_impl(paths: list[str], output_path: str, security: SecurityValidator) -> str:
    rpaths = []
    for p in paths:
        rp = security.resolve_and_validate(p)
        if not rp.exists():
            return f"Error: path does not exist: {rp}"
        rpaths.append(rp)
    routput = security.resolve_and_validate(output_path)
    added = await asyncio.to_thread(_compress_sync, rpaths, routput)
    logger.info("fs_compress output=%s files=%d", str(routput), len(added))
    size = routput.stat().st_size
    return f"Created {routput} ({size:,} bytes, {len(added)} file(s))"


def _safe_extract_sync(rzip: Path, routput: Path) -> tuple[list[str], list[str], list[str]]:
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

    Returns (extracted, skipped, failed): `skipped` are zip-slip rejections,
    `failed` are members that passed containment but hit an OSError while
    writing (permission, dest is a directory, disk full) — caught per member
    so one bad entry doesn't abort the whole extraction (M-F5, 2026-08-11).
    """
    routput_resolved = routput.resolve()
    extracted = []
    skipped = []
    failed = []
    with zipfile.ZipFile(rzip, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            member = info.filename
            dest = (routput_resolved / member).resolve()
            try:
                dest.relative_to(routput_resolved)
            except ValueError:
                skipped.append(member)
                continue
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(dest, "wb") as out:
                    shutil.copyfileobj(src, out)
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
        extracted, skipped, failed = await asyncio.to_thread(_safe_extract_sync, rzip, routput)
    except zipfile.BadZipFile:
        return f"Error: not a valid zip file: {rzip}"
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
    content = await fs_read_impl(path, security)
    new_content = content
    match_info = []
    for i, edit in enumerate(edits):
        old_text = edit.get("oldText", "")
        new_text = edit.get("newText", "")
        if not old_text:
            return f"Error: edit[{i}] missing 'oldText'"
        idx = new_content.find(old_text)
        if idx == -1:
            return f"Error: edit[{i}] 'oldText' not found in {path}"
        new_content = new_content[:idx] + new_text + new_content[idx + len(old_text):]
        match_info.append(f"  Edit {i}: matched at position {idx}")
    if dry_run:
        diff = await _diff_or_timeout_note(content, new_content)
        return (f"Dry run - would apply {len(edits)} edit(s):\n"
                + "\n".join(match_info) + "\n\nDiff:\n" + diff)
    await fs_write_impl(path, new_content, security)
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
        err = security.validate_tool_path(path, "write")
        if err:
            return err
        return await fs_write_impl(path, content, security, encoding, max_size_mb)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, idempotentHint=False, destructiveHint=True))
    async def fs_edit(path: str, old_string: str, new_string: str) -> str:
        err = security.validate_tool_path(path, "write")
        if err:
            return err
        return await fs_edit_impl(path, old_string, new_string, security)

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
        file_count, total_size = await asyncio.to_thread(_count_dir_contents_sync, rpath)
        err = security.validate_tool_path(path, "delete")
        if err:
            return (
                f"About to delete directory: {rpath}\n"
                f"Contains {file_count:,} file(s), {total_size:,} bytes "
                f"({total_size / 1024 / 1024:.1f} MB)\n\n" + err
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
                                  extensions: list[str] | None = None) -> str:
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        return await fs_find_duplicates_impl(path, security, recursive, extensions)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def fs_disk_usage(path: str, top_n: int = 15, depth: int = 1) -> str:
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        return await fs_disk_usage_impl(path, security, top_n, depth)

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
        err = security.validate_tool_path(path, "write")
        if err:
            return err
        if not edits:
            return "Error: edits list is empty"
        return await fs_edit_advanced_impl(path, edits, security, dry_run)
