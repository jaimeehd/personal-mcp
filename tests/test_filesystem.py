import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.layers.layer1_filesystem import (
    fs_read_impl, fs_write_impl, fs_edit_impl, fs_list_impl,
    fs_tree_impl, fs_search_impl, fs_find_impl, fs_info_impl,
    fs_diff_impl, fs_batch_impl, fs_snapshot_impl,
    fs_create_directory_impl, fs_move_impl, fs_read_multi_impl,
    fs_list_allowed_impl, fs_list_with_sizes_impl, fs_read_media_impl,
    fs_edit_advanced_impl,
)
from src.security import PathNotAllowedError
from src.config import AppConfig, SecurityConfig
from src.security import SecurityValidator
from src.permissions import GrantLevel, PermissionManager


@pytest.fixture
def sec(temp_home):
    config = AppConfig(
        security=SecurityConfig(
            paths_allow=[
                str(temp_home / "Repos"),
                str(temp_home / "Desktop"),
                str(temp_home / ".personal-mcp"),
            ],
            paths_deny=["**\\.git\\**"],
        ),
    )
    validator = SecurityValidator(config)
    validator.perm_manager = PermissionManager(config)
    # Grant session-wide access to temp_home for all filesystem tests
    validator.perm_manager.grant_direct(str(temp_home), "*", GrantLevel.SESSION)
    return validator


@pytest.mark.asyncio
async def test_read_file(sample_file, sec):
    content = await fs_read_impl(str(sample_file), sec)
    assert "Hello, World!" in content


@pytest.mark.asyncio
async def test_read_nonexistent(temp_home, sec):
    result = await fs_read_impl(str(temp_home / "Repos" / "nonexistent.txt"), sec)
    assert "Error" in result


@pytest.mark.asyncio
async def test_write_file(temp_home, sec):
    target = temp_home / "Repos" / "new_file.txt"
    result = await fs_write_impl(str(target), "test content", sec)
    assert target.exists()
    assert "Written" in result


@pytest.mark.asyncio
async def test_write_outside_allowed(temp_home, sec):
    with pytest.raises(PathNotAllowedError):
        await fs_write_impl(str(temp_home / "forbidden.txt"), "test", sec)


@pytest.mark.asyncio
async def test_edit_file(sample_file, sec):
    result = await fs_edit_impl(str(sample_file), "Hello", "Goodbye", sec)
    assert "Applied edit" in result
    assert sample_file.read_text().startswith("Goodbye")


@pytest.mark.asyncio
async def test_list_directory(sample_dir, sec):
    result = await fs_list_impl(str(sample_dir), sec)
    assert "src" in result
    assert "README.md" in result


@pytest.mark.asyncio
async def test_list_with_pattern(sample_dir, sec):
    result = await fs_list_impl(str(sample_dir), sec, pattern="*.md")
    assert "README.md" in result
    assert "src" not in result


@pytest.mark.asyncio
async def test_tree(temp_home, sec):
    result = await fs_tree_impl(str(temp_home / "Repos" / "sample_project"), sec)
    assert "sample_project" in result or "main.py" in result


@pytest.mark.asyncio
async def test_search(sample_dir, sec):
    result = await fs_search_impl(str(sample_dir), "print", sec)
    assert "No matches" in result or "print" in result or "main.py" in result


@pytest.mark.asyncio
async def test_search_invalid_pattern(sample_dir, sec):
    result = await fs_search_impl(str(sample_dir), "(unclosed[", sec)
    assert "Error" in result
    assert "invalid regex" in result


@pytest.mark.asyncio
async def test_search_timeout(monkeypatch, sample_dir, sec):
    # Regression test for ReDoS mitigation: fs_search must return a clean timeout
    # message instead of hanging the event loop when the search takes too long.
    # A mocked slow search is used instead of a real catastrophic-backtracking
    # pattern to keep the test fast and deterministic.
    import src.layers.layer1_filesystem as layer1
    import time as time_module

    monkeypatch.setattr(layer1, "_SEARCH_TIMEOUT_SECONDS", 0.05)

    def slow_search(*args, **kwargs):
        time_module.sleep(0.3)
        return "No matches found"

    monkeypatch.setattr(layer1, "_fs_search_sync", slow_search)
    result = await fs_search_impl(str(sample_dir), "print", sec)
    assert "timed out" in result


@pytest.mark.asyncio
async def test_find_by_name(sample_dir, sec):
    result = await fs_find_impl(str(sample_dir), sec, name="README.md")
    assert "README.md" in result


@pytest.mark.asyncio
async def test_file_info(sample_file, sec):
    result = await fs_info_impl(str(sample_file), sec)
    assert "sha256" in result
    assert "permissions" in result


@pytest.mark.asyncio
async def test_file_info_dir(sample_dir, sec):
    result = await fs_info_impl(str(sample_dir), sec)
    assert "permissions" in result
    assert result.startswith("path:")


@pytest.mark.asyncio
async def test_search_exclude_patterns(sample_dir, sec):
    result = await fs_search_impl(str(sample_dir), "print", sec, exclude_patterns=["*.py"])
    assert "No matches" in result


@pytest.mark.asyncio
async def test_tree_exclude_patterns(sample_dir, sec):
    result = await fs_tree_impl(str(sample_dir), sec, exclude_patterns=["src"])
    assert "src" not in result
    assert "README.md" in result


@pytest.mark.asyncio
async def test_diff(sample_file, sec):
    await fs_edit_impl(str(sample_file), "Hello", "Bonjour", sec)
    result = await fs_diff_impl(str(sample_file), None, sec)
    assert (("Bonjour" in result) or ("(identical)" in result) or ("backup" in result))


@pytest.mark.asyncio
async def test_batch_dry_run(sample_dir, sec):
    dest = sample_dir / "backup"
    dest.mkdir(exist_ok=True)
    result = await fs_batch_impl(str(sample_dir), "copy", str(dest), sec, pattern="*.py", dry_run=True)
    assert "DRY RUN" in result


@pytest.mark.asyncio
async def test_snapshot(sample_dir, sec):
    result = await fs_snapshot_impl(str(sample_dir), sec)
    assert "Snapshot saved" in result


@pytest.mark.asyncio
async def test_path_traversal_tool(temp_home, sec):
    with pytest.raises(PathNotAllowedError):
        await fs_read_impl(str(temp_home / "Repos" / ".." / ".." / "secrets.txt"), sec)


@pytest.mark.asyncio
async def test_list_scandir_many_entries(temp_home, sec):
    base = temp_home / "Repos" / "many_files"
    base.mkdir()
    for i in range(200):
        (base / f"file_{i:04d}.txt").write_text(f"content {i}")
    result = await fs_list_impl(str(base), sec, max_results=10)
    assert "file_0000.txt" in result
    assert "file_0010.txt" not in result


@pytest.mark.asyncio
async def test_read_large_file_rejected(temp_home, sec):
    target = temp_home / "Repos" / "large.bin"
    data = b"\xff\xfe\xfd\xfc" * (3 * 1024 * 1024)
    target.write_bytes(data)
    result = await fs_read_impl(str(target), sec, max_size_mb=10)
    assert "too large" in result


@pytest.mark.asyncio
async def test_read_large_file_override(temp_home, sec):
    target = temp_home / "Repos" / "large_ok.bin"
    data = b"\xff\xfe\xfd\xfc" * (3 * 1024 * 1024)
    target.write_bytes(data)
    result = await fs_read_impl(str(target), sec, max_size_mb=20)
    assert result.startswith("[Binary file")


@pytest.mark.asyncio
async def test_write_large_content_rejected(temp_home, sec):
    target = temp_home / "Repos" / "large_out.txt"
    content = "x" * (5 * 1024 * 1024)
    result = await fs_write_impl(str(target), content, sec, max_size_mb=1)
    assert "too large" in result


@pytest.mark.asyncio
async def test_list_recursive(temp_home, sec):
    base = temp_home / "Repos" / "nested"
    base.mkdir()
    (base / "top.txt").write_text("top")
    (base / "sub").mkdir()
    (base / "sub" / "inner.txt").write_text("inner")
    (base / "sub" / "deeper").mkdir()
    (base / "sub" / "deeper" / "deep.txt").write_text("deep")
    result = await fs_list_impl(str(base), sec, recursive=True)
    assert "top.txt" in result
    assert "sub" + os.sep + "inner.txt" in result or "sub/inner.txt" in result or "sub\\inner.txt" in result
    assert "deep.txt" in result


# --- head/tail ---

@pytest.mark.asyncio
async def test_read_with_head(sample_file, sec):
    result = await fs_read_impl(str(sample_file), sec, head=1)
    assert "Hello, World!" in result
    assert "This is a test" not in result


@pytest.mark.asyncio
async def test_read_with_tail(sample_file, sec):
    result = await fs_read_impl(str(sample_file), sec, tail=1)
    assert "This is a test" in result
    assert "Hello, World!" not in result


# --- fs_create_directory ---

@pytest.mark.asyncio
async def test_create_directory_new(temp_home, sec):
    target = temp_home / "Repos" / "new_dir"
    result = await fs_create_directory_impl(str(target), sec)
    assert target.is_dir()
    assert "Directory created" in result


# --- fs_move ---

@pytest.mark.asyncio
async def test_move_file(temp_home, sec):
    src = temp_home / "Repos" / "move_src.txt"
    dst = temp_home / "Repos" / "move_dst.txt"
    src.write_text("moveme")
    result = await fs_move_impl(str(src), str(dst), sec)
    assert "Moved" in result
    assert dst.exists()
    assert not src.exists()


@pytest.mark.asyncio
async def test_move_destination_exists(temp_home, sec):
    src = temp_home / "Repos" / "src_exists.txt"
    dst = temp_home / "Repos" / "dst_exists.txt"
    src.write_text("src")
    dst.write_text("dst")
    result = await fs_move_impl(str(src), str(dst), sec)
    assert "Error" in result
    assert "destination already exists" in result


# --- fs_read_multi ---

@pytest.mark.asyncio
async def test_read_multi_all_exist(temp_home, sec):
    a = temp_home / "Repos" / "multi_a.txt"
    b = temp_home / "Repos" / "multi_b.txt"
    a.write_text("alpha")
    b.write_text("beta")
    result = await fs_read_multi_impl([str(a), str(b)], sec)
    assert "alpha" in result
    assert "beta" in result


# --- fs_list_allowed ---

@pytest.mark.asyncio
async def test_list_allowed(temp_home, sec):
    result = await fs_list_allowed_impl(sec)
    assert "Allowed directories" in result
    assert str(temp_home / "Repos") in result
    assert str(temp_home / "Desktop") in result


# --- fs_list_with_sizes ---

@pytest.mark.asyncio
async def test_list_with_sizes_sort_by_name(sample_dir, sec):
    result = await fs_list_with_sizes_impl(str(sample_dir), sec, sort_by="name")
    assert "[FILE]" in result or "[DIR]" in result
    assert "README.md" in result
    assert "files" in result


# --- fs_read_media ---

@pytest.mark.asyncio
async def test_read_media_image(temp_home, sec):
    target = temp_home / "Repos" / "pixel.png"
    minimal_png = (
        b"\x89PNG\r\n\x1a\n"
        b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
        b"\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    target.write_bytes(minimal_png)
    result = await fs_read_media_impl(str(target), sec)
    assert result.startswith("data:image/png;base64,")


# --- fs_edit_advanced ---

@pytest.mark.asyncio
async def test_edit_advanced_single(sample_file, sec):
    result = await fs_edit_advanced_impl(
        str(sample_file),
        [{"oldText": "Hello, World!", "newText": "Bonjour, World!"}],
        sec,
    )
    assert "Applied" in result
    assert sample_file.read_text().startswith("Bonjour")


@pytest.mark.asyncio
async def test_edit_advanced_multiple(sample_file, sec):
    result = await fs_edit_advanced_impl(
        str(sample_file),
        [
            {"oldText": "Hello", "newText": "Bonjour"},
            {"oldText": "test", "newText": "essai"},
        ],
        sec,
    )
    assert "Applied" in result
    content = sample_file.read_text()
    assert "Bonjour" in content
    assert "essai" in content


@pytest.mark.asyncio
async def test_edit_advanced_dry_run(sample_file, sec):
    original = sample_file.read_text()
    result = await fs_edit_advanced_impl(
        str(sample_file),
        [{"oldText": "Hello", "newText": "Bonjour"}],
        sec,
        dry_run=True,
    )
    assert "Dry run" in result
    assert sample_file.read_text() == original



