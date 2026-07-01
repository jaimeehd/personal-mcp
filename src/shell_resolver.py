import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ShellInfo:
    name: str
    executable: str
    command_args: List[str] = field(default_factory=list)
    session_args: List[str] = field(default_factory=list)
    script_args: List[str] = field(default_factory=list)
    workdir_prefix: str = ""


SHELL_REGISTRY: Dict[str, ShellInfo] = {
    "powershell": ShellInfo(
        name="powershell",
        executable="powershell.exe",
        command_args=["-NoProfile", "-Command"],
        session_args=["-NoExit", "-Command", "-"],
        script_args=["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"],
        workdir_prefix='Set-Location -LiteralPath "{wd}"; ',
    ),
    "pwsh": ShellInfo(
        name="pwsh",
        executable="pwsh.exe",
        command_args=["-NoProfile", "-Command"],
        session_args=["-NoExit", "-Command", "-"],
        script_args=["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"],
        workdir_prefix='Set-Location -LiteralPath "{wd}"; ',
    ),
    "cmd": ShellInfo(
        name="cmd",
        executable="cmd.exe",
        command_args=["/d", "/c"],
        session_args=[],
        script_args=["/d", "/c"],
        workdir_prefix='cd /d "{wd}" && ',
    ),
    "bash": ShellInfo(
        name="bash",
        executable="",
        command_args=["-c"],
        session_args=[],
        script_args=["-c"],
        workdir_prefix='cd "{wd}" && ',
    ),
}


def _find_executable(name: str, shell_map: Optional[Dict[str, str]] = None) -> Optional[str]:
    if shell_map and name in shell_map:
        candidate = shell_map[name]
        if os.path.isfile(candidate):
            return candidate
    if name == "bash":
        return _find_git_bash()
    return shutil.which(name)


def _find_git_bash() -> Optional[str]:
    git_bash = os.environ.get("OPENCODE_GIT_BASH_PATH")
    if git_bash and os.path.isfile(git_bash):
        return git_bash
    try:
        result = subprocess.run(
            ["git", "--exec-path"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            git_path = result.stdout.strip()
            for candidate in [
                os.path.join(os.path.dirname(git_path), "..", "bin", "bash.exe"),
                os.path.join(git_path, "..", "..", "bin", "bash.exe"),
                r"C:\Program Files\Git\bin\bash.exe",
                r"C:\Program Files (x86)\Git\bin\bash.exe",
            ]:
                normalized = os.path.normpath(candidate)
                if os.path.isfile(normalized):
                    return normalized
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return None


def resolve_shell(name: str, shell_map: Optional[Dict[str, str]] = None) -> ShellInfo:
    if name not in SHELL_REGISTRY:
        valid = list(SHELL_REGISTRY.keys())
        raise ValueError(f"Unknown shell '{name}'. Valid options: {valid}")
    info = SHELL_REGISTRY[name]
    executable = _find_executable(name, shell_map)
    if not executable:
        raise ValueError(
            f"Shell '{name}' executable not found. "
            f"Install it or set a custom path in config.shell.shell_map"
        )
    resolved = ShellInfo(
        name=info.name,
        executable=executable,
        command_args=list(info.command_args),
        session_args=list(info.session_args),
        script_args=list(info.script_args),
        workdir_prefix=info.workdir_prefix,
    )
    return resolved
