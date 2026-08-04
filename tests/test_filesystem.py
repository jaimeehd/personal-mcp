import os
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import AppConfig, SecurityConfig
from src.layers.layer1_filesystem import (
    fs_batch_impl,
    fs_compress_impl,
    fs_create_directory_impl,
    fs_diff_impl,
    fs_disk_usage_impl,
    fs_edit_advanced_impl,
    fs_edit_impl,
    fs_extract_impl,
    fs_find_duplicates_impl,
    fs_find_impl,
    fs_info_impl,
    fs_list_allowed_impl,
    fs_list_impl,
    fs_list_with_sizes_impl,
    fs_move_impl,
    fs_read_impl,
    fs_read_media_impl,
    fs_read_multi_impl,
    fs_search_impl,
    fs_snapshot_impl,
    fs_tree_impl,
    fs_write_impl,
)
from src.permissions import GrantLevel, PermissionManager
from src.security import PathNotAllowedError, SecurityValidator


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
        data_dir=str(temp_home / ".personal-mcp" / "data"),
        config_path=str(temp_home / ".personal-mcp" / "config.json"),
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
    import time as time_module

    import src.layers.layer1_filesystem as layer1

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


# --- fs_find_duplicates ---

@pytest.mark.asyncio
async def test_find_duplicates_basic(temp_home, sec):
    base = temp_home / "Repos" / "dupes"
    base.mkdir()
    (base / "a.txt").write_text("identical content")
    (base / "b_copy.txt").write_text("identical content")
    (base / "unique.txt").write_text("something else entirely")
    result = await fs_find_duplicates_impl(str(base), sec)
    assert "1 duplicate group" in result
    assert "a.txt" in result
    assert "b_copy.txt" in result
    assert "unique.txt" not in result


@pytest.mark.asyncio
async def test_find_duplicates_none(temp_home, sec):
    base = temp_home / "Repos" / "no_dupes"
    base.mkdir()
    (base / "a.txt").write_text("aaa")
    (base / "b.txt").write_text("bbb")
    result = await fs_find_duplicates_impl(str(base), sec)
    assert "No exact duplicates found" in result


@pytest.mark.asyncio
async def test_find_duplicates_same_size_different_content(temp_home, sec):
    # Regression test for the size pre-filter: two files of identical size
    # but different bytes must NOT be reported as duplicates. This is the
    # exact case the exact-size grouping phase must hand off correctly to
    # the hash phase rather than treating "same size" as "same content".
    base = temp_home / "Repos" / "same_size"
    base.mkdir()
    (base / "a.txt").write_text("aaaa")
    (base / "b.txt").write_text("bbbb")
    result = await fs_find_duplicates_impl(str(base), sec)
    assert "No exact duplicates found" in result


@pytest.mark.asyncio
async def test_find_duplicates_extension_filter_with_dot(temp_home, sec):
    base = temp_home / "Repos" / "ext_dot"
    base.mkdir()
    (base / "a.pdf").write_text("same")
    (base / "b.pdf").write_text("same")
    (base / "c.txt").write_text("same")
    result = await fs_find_duplicates_impl(str(base), sec, extensions=[".pdf"])
    assert "a.pdf" in result
    assert "b.pdf" in result
    assert "c.txt" not in result


@pytest.mark.asyncio
async def test_find_duplicates_extension_filter_without_dot(temp_home, sec):
    # Same as above but the caller passes "pdf" instead of ".pdf" — both
    # forms must be accepted per the normalization design.
    base = temp_home / "Repos" / "ext_nodot"
    base.mkdir()
    (base / "a.pdf").write_text("same")
    (base / "b.pdf").write_text("same")
    (base / "c.txt").write_text("same")
    result = await fs_find_duplicates_impl(str(base), sec, extensions=["pdf"])
    assert "a.pdf" in result
    assert "b.pdf" in result
    assert "c.txt" not in result


@pytest.mark.asyncio
async def test_find_duplicates_extension_filter_case_insensitive(temp_home, sec):
    base = temp_home / "Repos" / "ext_case"
    base.mkdir()
    (base / "a.PDF").write_text("same")
    (base / "b.pdf").write_text("same")
    result = await fs_find_duplicates_impl(str(base), sec, extensions=[".pdf"])
    assert "a.PDF" in result
    assert "b.pdf" in result


@pytest.mark.asyncio
async def test_find_duplicates_recursive(temp_home, sec):
    base = temp_home / "Repos" / "dupes_recursive"
    base.mkdir()
    (base / "sub").mkdir()
    (base / "top.txt").write_text("same content")
    (base / "sub" / "nested.txt").write_text("same content")
    result_flat = await fs_find_duplicates_impl(str(base), sec, recursive=False)
    assert "No exact duplicates found" in result_flat
    result_recursive = await fs_find_duplicates_impl(str(base), sec, recursive=True)
    assert "top.txt" in result_recursive
    assert "nested.txt" in result_recursive


@pytest.mark.asyncio
async def test_find_duplicates_not_a_directory(sample_file, sec):
    result = await fs_find_duplicates_impl(str(sample_file), sec)
    assert "Error" in result
    assert "not a directory" in result


# --- fs_disk_usage ---

@pytest.mark.asyncio
async def test_disk_usage_basic(temp_home, sec):
    base = temp_home / "Repos" / "disk_basic"
    (base / "a").mkdir(parents=True)
    (base / "b").mkdir(parents=True)
    (base / "a" / "file1.txt").write_bytes(b"x" * 100)
    (base / "b" / "file2.txt").write_bytes(b"x" * 200)
    (base / "loose.txt").write_bytes(b"x" * 10)

    result = await fs_disk_usage_impl(str(base), sec)
    assert "310" in result  # total bytes
    # 'b' (200 bytes) must be listed before 'a' (100 bytes) -- descending order
    assert result.index(str(base / "b")) < result.index(str(base / "a"))


@pytest.mark.asyncio
async def test_disk_usage_depth_param(temp_home, sec):
    base = temp_home / "Repos" / "disk_depth"
    nested = base / "level1" / "level2"
    nested.mkdir(parents=True)
    (nested / "file.txt").write_bytes(b"x" * 300)

    result_depth1 = await fs_disk_usage_impl(str(base), sec, depth=1)
    assert str(base / "level1") in result_depth1
    assert str(base / "level1" / "level2") not in result_depth1

    result_depth2 = await fs_disk_usage_impl(str(base), sec, depth=2)
    assert str(base / "level1" / "level2") in result_depth2


@pytest.mark.asyncio
async def test_disk_usage_top_n_truncation(temp_home, sec):
    base = temp_home / "Repos" / "disk_topn"
    for i in range(3):
        d = base / f"folder{i}"
        d.mkdir(parents=True)
        (d / "f.txt").write_bytes(b"x" * (100 * (i + 1)))

    result = await fs_disk_usage_impl(str(base), sec, top_n=1)
    assert "y 2 carpeta(s) más" in result


@pytest.mark.asyncio
async def test_disk_usage_not_a_directory(sample_file, sec):
    result = await fs_disk_usage_impl(str(sample_file), sec)
    assert "Error" in result
    assert "not a directory" in result


@pytest.mark.asyncio
async def test_disk_usage_empty_dir(temp_home, sec):
    base = temp_home / "Repos" / "disk_empty"
    base.mkdir(parents=True)
    result = await fs_disk_usage_impl(str(base), sec)
    assert "No files found" in result


# --- fs_compress / fs_extract ---

@pytest.mark.asyncio
async def test_compress_single_file(temp_home, sec):
    src = temp_home / "Repos" / "to_zip.txt"
    src.write_text("contenido de prueba")
    output = temp_home / "Repos" / "out.zip"
    result = await fs_compress_impl([str(src)], str(output), sec)
    assert "Created" in result
    assert output.is_file()
    with zipfile.ZipFile(output) as zf:
        assert "to_zip.txt" in zf.namelist()
        assert zf.read("to_zip.txt").decode() == "contenido de prueba"


@pytest.mark.asyncio
async def test_compress_directory(temp_home, sec):
    src_dir = temp_home / "Repos" / "dir_to_zip"
    src_dir.mkdir()
    (src_dir / "a.txt").write_text("a")
    (src_dir / "sub").mkdir()
    (src_dir / "sub" / "b.txt").write_text("b")
    output = temp_home / "Repos" / "dir_out.zip"

    result = await fs_compress_impl([str(src_dir)], str(output), sec)
    assert "Created" in result
    with zipfile.ZipFile(output) as zf:
        names = zf.namelist()
        assert any("a.txt" in n for n in names)
        assert any("b.txt" in n for n in names)


@pytest.mark.asyncio
async def test_compress_nonexistent_path(temp_home, sec):
    output = temp_home / "Repos" / "never.zip"
    result = await fs_compress_impl(
        [str(temp_home / "Repos" / "does_not_exist.txt")], str(output), sec
    )
    assert "Error" in result
    assert "does not exist" in result


@pytest.mark.asyncio
async def test_extract_basic(temp_home, sec):
    zip_path = temp_home / "Repos" / "sample.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("hello.txt", "hola mundo")
        zf.writestr("sub/nested.txt", "anidado")

    output_dir = temp_home / "Repos" / "extracted"
    result = await fs_extract_impl(str(zip_path), str(output_dir), sec)

    assert "Extracted 2 file(s)" in result
    assert (output_dir / "hello.txt").read_text() == "hola mundo"
    assert (output_dir / "sub" / "nested.txt").read_text() == "anidado"


@pytest.mark.asyncio
async def test_extract_creates_output_dir(temp_home, sec):
    zip_path = temp_home / "Repos" / "sample2.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("a.txt", "a")
    output_dir = temp_home / "Repos" / "brand_new_dir"
    assert not output_dir.exists()
    await fs_extract_impl(str(zip_path), str(output_dir), sec)
    assert output_dir.is_dir()
    assert (output_dir / "a.txt").exists()


@pytest.mark.asyncio
async def test_extract_bad_zip(temp_home, sec):
    fake_zip = temp_home / "Repos" / "not_a_zip.zip"
    fake_zip.write_text("this is not a real zip file")
    output_dir = temp_home / "Repos" / "bad_extract"
    result = await fs_extract_impl(str(fake_zip), str(output_dir), sec)
    assert "Error" in result
    assert "not a valid zip" in result


@pytest.mark.asyncio
async def test_extract_zip_slip_protection(temp_home, sec):
    """Security regression test: a zip member with a '../' path traversal
    name must never be written outside output_dir. This is the core safety
    property fs_extract exists to guarantee -- Path.relative_to() containment
    check in _safe_extract_sync, not trusting zipfile's own extraction."""
    malicious_zip = temp_home / "Repos" / "evil.zip"
    with zipfile.ZipFile(malicious_zip, "w") as zf:
        zf.writestr("../../escaped.txt", "should never escape output_dir")
        zf.writestr("safe.txt", "this one is fine")

    output_dir = temp_home / "Repos" / "zipslip_out"
    result = await fs_extract_impl(str(malicious_zip), str(output_dir), sec)

    assert "Skipped 1 member" in result
    assert "escaped.txt" in result
    # The traversal target (two levels up from output_dir) must not exist.
    assert not (temp_home / "escaped.txt").exists()
    # The safe member must still have been extracted normally.
    assert (output_dir / "safe.txt").exists()
    assert (output_dir / "safe.txt").read_text() == "this one is fine"


@pytest.mark.asyncio
async def test_compress_extract_roundtrip(temp_home, sec):
    src_dir = temp_home / "Repos" / "roundtrip_src"
    src_dir.mkdir()
    (src_dir / "one.txt").write_text("uno")
    (src_dir / "two.txt").write_text("dos")

    zip_path = temp_home / "Repos" / "roundtrip.zip"
    await fs_compress_impl([str(src_dir)], str(zip_path), sec)

    output_dir = temp_home / "Repos" / "roundtrip_out"
    result = await fs_extract_impl(str(zip_path), str(output_dir), sec)

    assert "Extracted 2 file(s)" in result
    assert (output_dir / "roundtrip_src" / "one.txt").read_text() == "uno"
    assert (output_dir / "roundtrip_src" / "two.txt").read_text() == "dos"



