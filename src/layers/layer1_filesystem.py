import asyncio
import difflib
import fnmatch
import hashlib
import json
import os
import re
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from mcp.server.fastmcp import FastMCP

from src.security import SecurityValidator
from src.log import get_logger, timed

logger = get_logger("layer1_filesystem")

async def fs_read_impl(path: str, security: SecurityValidator, encoding: str = "utf-8",
                       max_size_mb: int = 0) -> str:
    rpath = security.resolve_and_validate(path)
    exists = await asyncio.to_thread(rpath.is_file)
    if not exists:
        logger.info("fs_read not_found path=%s", path)
        return f"Error: not a file or does not exist: {rpath}"
    size = await asyncio.to_thread(lambda: rpath.stat().st_size)
    if size > 10 * 1024 * 1024:
        logger.warning("fs_read large_file path=%s size=%d", path, size)
    if max_size_mb and size > max_size_mb * 1024 * 1024:
        return f"Error: file too large ({size / 1024 / 1024:.1f}MB). Max: {max_size_mb}MB"
    try:
        return await asyncio.to_thread(rpath.read_text, encoding=encoding)
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


async def fs_list_impl(path: str, security: SecurityValidator, pattern: Optional[str] = None,
                       max_results: Optional[int] = 100, recursive: bool = False) -> str:
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
                            info.st_mtime, tz=timezone.utc
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
                            info.st_mtime, tz=timezone.utc
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


async def fs_tree_impl(path: str, security: SecurityValidator, max_depth: int = 3) -> str:
    rpath = security.resolve_and_validate(path)
    if not rpath.is_dir():
        return f"Error: not a directory: {rpath}"

    def _tree(dir_path: Path, prefix: str = "", depth: int = 0) -> List[str]:
        if depth > max_depth:
            return [f"{prefix}└── ..."]
        lines = []
        entries = sorted(dir_path.iterdir())
        for i, entry in enumerate(entries):
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


async def fs_search_impl(path: str, pattern: str, security: SecurityValidator,
                         glob_pattern: Optional[str] = None,
                         max_results: Optional[int] = 50) -> str:
    rpath = security.resolve_and_validate(path)
    if not rpath.is_dir():
        return f"Error: not a directory: {rpath}"
    regex = re.compile(pattern, re.IGNORECASE)
    matches = []
    try:
        for filepath in rpath.rglob(glob_pattern or "*"):
            if filepath.is_dir():
                continue
            if len(matches) >= max_results:
                break
            try:
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


async def fs_find_impl(path: str, security: SecurityValidator, name: Optional[str] = None,
                       min_size: Optional[int] = None, max_size: Optional[int] = None,
                       days_old: Optional[int] = None,
                       max_results: Optional[int] = 50) -> str:
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
        "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
    }
    if rpath.is_file():
        info["sha256"] = hashlib.sha256(rpath.read_bytes()).hexdigest()
        info["extension"] = rpath.suffix
    return "\n".join(f"{k}: {v}" for k, v in info.items())


async def fs_diff_impl(path_a: str, path_b: Optional[str], security: SecurityValidator) -> str:
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
                        pattern: Optional[str] = None, dry_run: bool = True) -> str:
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


def register_filesystem_tools(mcp: FastMCP, security: SecurityValidator) -> None:
    @mcp.tool()
    async def fs_read(path: str, encoding: str = "utf-8", max_size_mb: int = 0) -> str:
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        return await fs_read_impl(path, security, encoding, max_size_mb)

    @mcp.tool()
    async def fs_write(path: str, content: str, encoding: str = "utf-8", max_size_mb: int = 0) -> str:
        err = security.validate_tool_path(path, "write")
        if err:
            return err
        return await fs_write_impl(path, content, security, encoding, max_size_mb)

    @mcp.tool()
    async def fs_edit(path: str, old_string: str, new_string: str) -> str:
        err = security.validate_tool_path(path, "write")
        if err:
            return err
        return await fs_edit_impl(path, old_string, new_string, security)

    @mcp.tool()
    async def fs_list(path: str, pattern: Optional[str] = None, max_results: Optional[int] = 100,
                      recursive: bool = False) -> str:
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        return await fs_list_impl(path, security, pattern, max_results, recursive)

    @mcp.tool()
    async def fs_tree(path: str, max_depth: int = 3) -> str:
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        return await fs_tree_impl(path, security, max_depth)

    @mcp.tool()
    async def fs_search(path: str, pattern: str, glob_pattern: Optional[str] = None,
                        max_results: Optional[int] = 50) -> str:
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        return await fs_search_impl(path, pattern, security, glob_pattern, max_results)

    @mcp.tool()
    async def fs_find(path: str, name: Optional[str] = None, min_size: Optional[int] = None,
                      max_size: Optional[int] = None, days_old: Optional[int] = None,
                      max_results: Optional[int] = 50) -> str:
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        return await fs_find_impl(path, security, name, min_size, max_size, days_old, max_results)

    @mcp.tool()
    async def fs_info(path: str) -> str:
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        return await fs_info_impl(path, security)

    @mcp.tool()
    async def fs_diff(path_a: str, path_b: Optional[str] = None) -> str:
        err = security.validate_tool_path(path_a, "read")
        if err:
            return err
        if path_b:
            err = security.validate_tool_path(path_b, "read")
            if err:
                return err
        return await fs_diff_impl(path_a, path_b, security)

    @mcp.tool()
    async def fs_batch(path: str, operation: str, target: str,
                       pattern: Optional[str] = None, dry_run: bool = True) -> str:
        err = security.validate_tool_path(path, "read")
        if err:
            return err
        err = security.validate_tool_path(target, "write")
        if err:
            return err
        return await fs_batch_impl(path, operation, target, security, pattern, dry_run)

    @mcp.tool()
    async def fs_snapshot(path: str) -> str:
        err = security.validate_tool_path(path, "write")
        if err:
            return err
        return await fs_snapshot_impl(path, security)
