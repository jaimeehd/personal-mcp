import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.layers.layer6_permissions import _single_grant_directory_error

# --- 2026-08-08 fix (found via external audit) ---
# check_granted()'s single-grant lookup is an exact-path match, unlike session
# grants which walk up parent directories. Requesting a 'single' grant on a
# directory could never satisfy a later check on a file inside it -- the
# ticket got created and could even be approved, but never actually granted
# anything usable. fs_request_allow now rejects this case up front via this
# standalone, directly-testable function (same pattern as
# _validate_command_paths/_check_spawn_permission in layer2_shell.py).


def test_single_grant_on_directory_rejected(temp_home):
    folder = temp_home / "Repos" / "some_project"
    folder.mkdir()
    error = _single_grant_directory_error(str(folder))
    assert error is not None
    assert "directory" in error.lower()
    assert "session" in error.lower()


def test_single_grant_on_file_allowed(temp_home):
    file_path = temp_home / "Repos" / "some_file.txt"
    file_path.write_text("hello")
    error = _single_grant_directory_error(str(file_path))
    assert error is None


def test_single_grant_on_nonexistent_path_allowed(temp_home):
    # A path that doesn't exist yet (e.g. a file about to be created) is not
    # a directory -- must not be rejected just because it can't be stat'd
    # as one either way.
    missing = temp_home / "Repos" / "not_created_yet.txt"
    error = _single_grant_directory_error(str(missing))
    assert error is None
