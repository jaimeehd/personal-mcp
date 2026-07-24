import asyncio

import psutil


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
    """Create subprocess with stdin=DEVNULL by default (prevents hanging on inherited stdin)."""
    kwargs.setdefault("stdin", asyncio.subprocess.DEVNULL)
    return await asyncio.create_subprocess_exec(*cmd, **kwargs)