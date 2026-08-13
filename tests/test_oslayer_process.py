import asyncio
import sys

import pytest

from src.oslayer.process import run_subprocess

pytestmark = pytest.mark.asyncio


async def test_run_subprocess_defaults_stdin_devnull():
    """stdin defaults to DEVNULL (prevents hanging on inherited stdin -- the
    project_git_status incident, 1.4.50, and 6 more call sites found in 1.4.53).
    With DEVNULL (not PIPE), asyncio never creates a StreamWriter for stdin.
    """
    proc = await run_subprocess([sys.executable, "-c", "pass"])
    assert proc.stdin is None
    await proc.wait()


async def test_run_subprocess_caller_can_override_stdin():
    proc = await run_subprocess(
        [sys.executable, "-c", "import sys; print(sys.stdin.read().strip())"],
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate(input=b"override\n")
    assert stdout.strip() == b"override"


async def test_run_subprocess_caller_can_override_env():
    proc = await run_subprocess(
        [sys.executable, "-c", "import os; print(os.environ.get('CUSTOM_MARKER', ''))"],
        env={"CUSTOM_MARKER": "yes"},
        stdout=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    assert stdout.strip() == b"yes"


@pytest.mark.skipif(sys.platform != "win32", reason="PATHEXT is Windows-only")
async def test_run_subprocess_fixes_broken_pathext_on_windows(monkeypatch):
    """Regression test for a broken/incomplete inherited PATHEXT
    (seen live on this machine as just '.CPL', no '.EXE') breaks PowerShell's
    own command resolution even though shutil.which() finds the same binary
    fine. run_subprocess() must hand the child a PATHEXT containing '.EXE'
    even when the parent's own env is broken.
    """
    monkeypatch.setenv("PATHEXT", ".CPL")
    proc = await run_subprocess(
        [sys.executable, "-c", "import os; print(os.environ.get('PATHEXT', ''))"],
        stdout=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    assert b".EXE" in stdout.upper()


@pytest.mark.skipif(sys.platform == "win32", reason="env=None fallback is the non-Windows path")
async def test_run_subprocess_env_default_is_noop_on_non_windows():
    """shell_subprocess_env() returns None on non-Windows -- passing env=None
    to create_subprocess_exec must behave identically to omitting it (inherit
    the parent's environment), not wipe it out.
    """
    proc = await run_subprocess(
        [sys.executable, "-c", "import os; print(os.environ.get('PATH', '') != '')"],
        stdout=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    assert stdout.strip() == b"True"
