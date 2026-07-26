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
from datetime import UTC, datetime
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from src.log import get_logger, timed
from src.secretscanner import format_findings, scan_text
from src.security import SecurityValidator

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
    content = await fs_read_impl(path, security)
    if old_string not in content:
        return f"Error: old_string not found in {path}"
    new_content = content.replace(old_string, new_string, 1)
    diff = list(difflib.unified_diff(
        content.splitlines(keepends=True),
        new_content.splitlines(keepends=True),
        fromfile="before", tofile="after"
    ))
    await fs_write_impl(path, new_content, security)
    return f"Applied edit. Diff:\n{''.join(diff)}"


async def fs_list_impl(path: str, security: SecurityValidator, pattern: str | None = None,
                       max_results: int | None = 100, recursive: bool = False) -> str:
    rpath = security.resolve_and_validate(path)
    if not rpath.is_dir():
        return f"Error: not a directory: {rpath}"
    entries = []
    try:
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
                        break
                if max_results and len(entries) >= max_results:
                    break
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
                        break
    except PermissionError as e:
        return f"Permission denied: {e}"
    lines = []
    for e in entries:
        tag = "dir" if e["type"] == "dir" else "file"
        size_str = f"{e['size']:,}B" if e["size"] < 1024 else f"{e['size']/1024:.1f}KB"
        lines.append(f"{tag:4s} {e['name']:40s} {size_str:10s} {e['modified'][:19]}")
    return "\n".join(lines) if lines else "(empty directory)"


async def fs_tree_impl(path: str, security: SecurityValidator, max_depth: int = 3,
                       exclude_patterns: list[str] | None = None) -> str:
    rpath = security.resolve_and_validate(path)
    if not rpath.is_dir():
        return f"Error: not a directory: {rpath}"

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


# ReDoS mitigation: a single catastrophic regex.search() call cannot be interrupted
# mid-execution in pure Python (no external timeout-capable engine, e.g. the `regex`
# package, is a dependency of this project). Running the blocking search in a thread
# and bounding the wait with asyncio.wait_for() cannot stop the runaway thread itself,
# but it guarantees the MCP call returns to the caller instead of hanging the server
# indefinitely — the actual failure mode this fixes.
_SEARCH_TIMEOUT_SECONDS = 10.0
_SEARCH_MAX_FILE_MB = 10


def _fs_search_sync(rpath: Path, regex: "re.Pattern", glob_pattern: str | None,
                     max_results: int, exclude_patterns: list[str] | None) -> str:
    matches = []
    try:
        for filepath in rpath.rglob(glob_pattern or "*"):
            if filepath.is_dir():
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


async def fs_find_impl(path: str, security: SecurityValidator, name: str | None = None,
                       min_size: int | None = None, max_size: int | None = None,
                       days_old: int | None = None,
                       max_results: int | None = 50) -> str:
    rpath = security.resolve_and_validate(path)
    if not rpath.is_dir():
        return f"Error: not a directory: {rpath}"
    results = []
    now = time.time()
    for entry in rpath.rglob(name or "*"):
        if len(results) >= max_results:
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


async def fs_info_impl(path: str, security: SecurityValidator) -> str:
    rpath = security.resolve_and_validate(path)
    if not rpath.exists():
        return f"Error: path does not exist: {rpath}"
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
        info["sha256"] = hashlib.sha256(rpath.read_bytes()).hexdigest()
        info["extension"] = rpath.suffix
    return "\n".join(f"{k}: {v}" for k, v in info.items())


async def fs_diff_impl(path_a: str, path_b: str | None, security: SecurityValidator) -> str:
    content_a = await fs_read_impl(path_a, security)
    if path_b:
        content_b = await fs_read_impl(path_b, security)
    else:
        backup = Path(path_a).with_suffix(Path(path_a).suffix + ".bak")
        backup_exists = await asyncio.to_thread(backup.exists)
        if not backup_exists:
            return "No backup found. Provide path_b explicitly."
        content_b = await asyncio.to_thread(backup.read_text, "utf-8", errors="replace")
    diff = difflib.unified_diff(
        content_b.splitlines(keepends=True),
        content_a.splitlines(keepends=True),
        fromfile=str(path_b or backup),
        tofile=path_a
    )
    return "".join(diff) or "(identical)"


async def fs_batch_impl(path: str, operation: str, target: str, security: SecurityValidator,
                        pattern: str | None = None, dry_run: bool = True) -> str:
    rpath = security.resolve_and_validate(path)
    if not rpath.is_dir():
        return f"Error: not a directory: {rpath}"
    if pattern:
        files = [f for f in rpath.iterdir() if f.is_file() and f.match(pattern)]
    else:
        files = [f for f in rpath.iterdir() if f.is_file()]
    security.validate_file_count(len(files))
    logger.info("fs_batch path=%s operation=%s files=%d dry_run=%s", path, operation, len(files), dry_run)
    target_path = Path(target)
    if operation in ("copy", "move"):
        security.resolve_and_validate(str(target_path))
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


async def fs_snapshot_impl(path: str, security: SecurityValidator) -> str:
    rpath = security.resolve_and_validate(path)
    if not rpath.is_dir():
        return f"Error: not a directory: {rpath}"
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
    await asyncio.to_thread(
        snapshot_path.write_text,
        json.dumps(snapshot, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
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
        await asyncio.to_thread(shutil.copytree, src, dst)
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
    """
    results = []
    deleted = 0
    for p in paths:
        try:
            rpath = security.resolve_and_validate(p)
            if not rpath.exists():
                results.append(f"Error: path does not exist: {rpath}")
                continue
            if rpath.is_dir():
                results.append(f"Error: fs_delete_batch only supports individual files, not directories: {rpath}")
                continue
            size = rpath.stat().st_size
            await asyncio.to_thread(rpath.unlink)
            deleted += 1
            results.append(f"Deleted {rpath} ({size:,} bytes)")
        except Exception as e:
            results.append(f"Error deleting {p}: {e}")
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
            norm_old = "\n".join(line.rstrip() for line in old_text.splitlines())
            norm_content = "\n".join(line.rstrip() for line in new_content.splitlines())
            idx = norm_content.find(norm_old)
            if idx == -1:
                return f"Error: edit[{i}] 'oldText' not found in {path}"
            pre = norm_content[:idx]
            orig_lines = pre.count("\n") + 1
            search_from = 0
            for _ in range(orig_lines - 1):
                nxt = new_content.find("\n", search_from)
                if nxt == -1:
                    break
                search_from = nxt + 1
            idx = search_from
            old_lines = old_text.splitlines(keepends=True)
            old_len = 0
            rest = new_content[idx:]
            for j, _ in enumerate(old_lines):
                nxt = rest.find("\n", old_len)
                if nxt == -1:
                    if j < len(old_lines) - 1:
                        old_len = len(rest)
                    else:
                        old_len = len(rest)
                    break
                old_len = nxt + 1
            new_content = new_content[:idx] + new_text + new_content[idx + old_len:]
        else:
            new_content = new_content[:idx] + new_text + new_content[idx + len(old_text):]
        match_info.append(f"  Edit {i}: matched at position {idx}")
    if dry_run:
        diff = difflib.unified_diff(
            content.splitlines(keepends=True),
            new_content.splitlines(keepends=True),
            fromfile="before", tofile="after"
        )
        return (f"Dry run - would apply {len(edits)} edit(s):\n"
                + "\n".join(match_info) + "\n\nDiff:\n" + "".join(diff))
    await fs_write_impl(path, new_content, security)
    diff = "".join(difflib.unified_diff(
        content.splitlines(keepends=True),
        new_content.splitlines(keepends=True),
        fromfile="before", tofile="after"
    ))
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
    async def fs_delete_batch(paths: list[str]) -> str:
        if not paths:
            return "Error: empty paths list"
        err = security.validate_tool_paths_batch(paths, "delete")
        if err:
            return err
        return await fs_delete_batch_impl(paths, security)

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

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, idempotentHint=False, destructiveHint=True))
    async def fs_edit_advanced(path: str, edits: list[dict[str, str]],
                                dry_run: bool = False) -> str:
        err = security.validate_tool_path(path, "write")
        if err:
            return err
        if not edits:
            return "Error: edits list is empty"
        return await fs_edit_advanced_impl(path, edits, security, dry_run)
