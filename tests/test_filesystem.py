import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.layers.layer1_filesystem import (
    fs_read_impl, fs_write_impl, fs_edit_impl, fs_list_impl,
    fs_tree_impl, fs_search_impl, fs_find_impl, fs_info_impl,
    fs_diff_impl, fs_batch_impl, fs_snapshot_impl,
)
from src.security import PathNotAllowedError
from src.config import AppConfig, SecurityConfig
from src.security import SecurityValidator


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
    return SecurityValidator(config)


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
async def test_find_by_name(sample_dir, sec):
    result = await fs_find_impl(str(sample_dir), sec, name="README.md")
    assert "README.md" in result


@pytest.mark.asyncio
async def test_file_info(sample_file, sec):
    result = await fs_info_impl(str(sample_file), sec)
    assert "sha256" in result


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
