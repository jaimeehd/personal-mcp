import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.layers.layer4_personal import Journal, project_git_status_impl


@pytest.fixture
def journal(temp_home):
    path = temp_home / ".personal-mcp" / "data" / "journal"
    return Journal(path)


def test_journal_add(journal):
    entry = journal.add("Test entry", tags=["test", "pytest"], category="testing")
    assert entry["content"] == "Test entry"
    assert "test" in entry["tags"]
    assert entry["category"] == "testing"


def test_journal_list(journal):
    journal.add("Entry 1", tags=["a"])
    journal.add("Entry 2", tags=["b"])
    journal.add("Entry 3", tags=["a"])
    entries = journal.list(limit=10)
    assert len(entries) == 3


def test_journal_list_with_tag(journal):
    journal.add("Entry A1", tags=["alpha"])
    journal.add("Entry B1", tags=["beta"])
    journal.add("Entry A2", tags=["alpha"])
    entries = journal.list(tag="alpha")
    assert len(entries) == 2


def test_journal_list_with_category(journal):
    journal.add("Work entry", category="work")
    journal.add("Personal entry", category="personal")
    entries = journal.list(category="work")
    assert len(entries) == 1


def test_journal_search(journal):
    journal.add("The quick brown fox")
    journal.add("Lazy dog sleeps")
    entries = journal.search("fox")
    assert len(entries) == 1
    assert "fox" in entries[0]["content"]


def test_journal_search_no_results(journal):
    journal.add("Something")
    entries = journal.search("nonexistent")
    assert len(entries) == 0


def test_journal_stats(journal):
    journal.add("A", tags=["x"], category="cat1")
    journal.add("B", tags=["y"], category="cat2")
    journal.add("C", tags=["x"], category="cat1")
    stats = journal.stats()
    assert stats["total_entries"] == 3
    assert stats["tags"]["x"] == 2
    assert stats["categories"]["cat1"] == 2


def test_journal_export_json(journal):
    journal.add("Export test")
    output = journal.export(fmt="json")
    assert "Export test" in output
    parsed = json.loads(output)
    assert len(parsed) >= 1


def test_journal_export_markdown(journal):
    journal.add("Markdown export test")
    output = journal.export(fmt="markdown")
    assert "Markdown export test" in output


def test_journal_persistence(temp_home):
    path = temp_home / ".personal-mcp" / "data" / "journal"
    journal1 = Journal(path)
    journal1.add("Persistent entry")
    journal2 = Journal(path)
    entries = journal2.list(limit=10)
    assert len(entries) == 1


# --- project_git_status ---

def _git(args, cwd):
    subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.com", *args],
        cwd=str(cwd), capture_output=True, text=True, check=True,
    )


def _init_repo(path: Path):
    path.mkdir(parents=True, exist_ok=True)
    _git(["init", "-q"], path)
    (path / "README.md").write_text("hello")
    _git(["add", "."], path)
    _git(["commit", "-q", "-m", "initial"], path)


@pytest.mark.asyncio
async def test_project_git_status_no_repos(security):
    result = await project_git_status_impl(security)
    assert "No git repositories found" in result


@pytest.mark.asyncio
async def test_project_git_status_clean_repo(temp_home, security):
    _init_repo(temp_home / "Repos" / "clean_project")
    result = await project_git_status_impl(security)
    assert "clean_project" in result
    assert "sin cambios pendientes" in result


@pytest.mark.asyncio
async def test_project_git_status_uncommitted_changes(temp_home, security):
    repo = temp_home / "Repos" / "dirty_project"
    _init_repo(repo)
    (repo / "new_file.txt").write_text("uncommitted")
    result = await project_git_status_impl(security)
    assert "dirty_project" in result
    assert "cambios pendientes" in result
    assert "sin commitear" in result


@pytest.mark.asyncio
async def test_project_git_status_ahead_of_remote(temp_home, security):
    # Real remote via a local bare repo -- exercises the actual `git rev-list
    # --left-right --count @{u}...HEAD` path, not just the no-upstream branch.
    bare = temp_home / "remote.git"
    bare.mkdir()
    subprocess.run(["git", "init", "-q", "--bare"], cwd=str(bare), check=True)

    repo = temp_home / "Repos" / "tracked_project"
    _init_repo(repo)
    _git(["remote", "add", "origin", str(bare)], repo)
    _git(["push", "-q", "-u", "origin", "HEAD"], repo)

    (repo / "unpushed.txt").write_text("local only")
    _git(["add", "."], repo)
    _git(["commit", "-q", "-m", "local commit"], repo)

    result = await project_git_status_impl(security)
    assert "tracked_project" in result
    assert "sin pushear" in result


@pytest.mark.asyncio
async def test_project_git_status_skips_node_modules(temp_home, security):
    # A .git dir inside node_modules must not be discovered as a project --
    # regression test for _REPO_DISCOVERY_SKIP_DIRS.
    nested = temp_home / "Repos" / "app" / "node_modules" / "some_pkg"
    _init_repo(nested)
    result = await project_git_status_impl(security)
    assert "some_pkg" not in result
