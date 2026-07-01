import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.layers.layer4_personal import Journal


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
