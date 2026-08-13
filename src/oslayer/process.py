import asyncio

import psutil

from src.shell_resolver import shell_subprocess_env


async def kill_process_tree(pid: int) -> None:
    """Kill process and all its children (cross-platform)."""
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in children:
            try:
                child.kill()
            except psutil.NoSuchProcess:
                pass
        parent.kill()
    except psutil.NoSuchProcess:
        pass
    except Exception:
        pass


async def reap_after_kill(process: asyncio.subprocess.Process) -> None:
    """Wait for process to be reaped after kill to avoid handle leaks."""
    try:
        await asyncio.wait_for(process.wait(), timeout=10)
    except TimeoutError:
        pass
    except Exception:
        pass


async def run_subprocess(cmd, **kwargs) -> asyncio.subprocess.Process:
    """Create subprocess with the safety defaults every shell-spawning call site
    in this project needs, applied once instead of copy-pasted per call site.

    - stdin=DEVNULL by default: prevents hanging on inherited stdin (the
      project_git_status bug, 1.4.50, found again at 6 more call sites in
      1.4.53).
    - env=shell_subprocess_env() by default: fixes a broken/incomplete
      inherited PATHEXT breaking PowerShell's own command resolution on
      Windows. Returns None on
      non-Windows platforms; passing env=None has the same effect as
      omitting it (subprocess inherits the current environment), so no
      platform branching is needed at the call site.

    Both are set via setdefault(), so a caller that needs to override either
    can still pass its own stdin=/env= explicitly.

    NOT meant for sh_exec's native-argv fast path (shutil.which() + direct
    create_subprocess_exec, no real shell involved) -- that path never had
    the PATHEXT bug (see shell_subprocess_env()'s own docstring) and stays
    on its own direct call, not this helper.
    """
    kwargs.setdefault("stdin", asyncio.subprocess.DEVNULL)
    kwargs.setdefault("env", shell_subprocess_env())
    return await asyncio.create_subprocess_exec(*cmd, **kwargs)