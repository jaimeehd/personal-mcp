import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field


@dataclass
class ShellInfo:
    name: str
    executable: str
    command_args: list[str] = field(default_factory=list)
    session_args: list[str] = field(default_factory=list)
    script_args: list[str] = field(default_factory=list)
    workdir_prefix: str = ""


_SHELL_OPERATORS_RE = re.compile(r'[|;&<>`\n]|\$\(')


def tokenize_command(command: str) -> list[str]:
    """Split a command string into argv tokens, respecting single and double quotes."""
    tokens: list[str] = []
    current: list[str] = []
    quote_char: str | None = None
    for c in command:
        if quote_char:
            if c == quote_char:
                quote_char = None
            else:
                current.append(c)
        elif c in ('"', "'"):
            quote_char = c
        elif c in (' ', '\t', '\n'):
            if current:
                tokens.append(''.join(current))
                current = []
        else:
            current.append(c)
    if current:
        tokens.append(''.join(current))
    return tokens


def has_shell_operators(command: str) -> bool:
    """Check if command contains shell operators outside quoted strings."""
    stripped = re.sub(r'"[^"]*"', '', command)
    stripped = re.sub(r"'[^']*'", '', stripped)
    return bool(_SHELL_OPERATORS_RE.search(stripped))


def split_command_segments(command: str) -> list[str]:
    """Split a command string into segments on shell operators (| ; & < > ` $(), plus
    newlines, ignoring operators found inside single/double-quoted sections.

    Used to validate EVERY segment of a chained command (e.g. "git status; rm -rf /",
    or "echo hi\\nWrite-Host injected") against the command whitelist independently —
    the whole raw string is passed to a real shell whenever has_shell_operators() is
    True, so each segment becomes an independently-executed command and must be
    checked on its own. Newlines are included because PowerShell/cmd/bash all treat
    them as statement separators just like ';', even though earlier versions of this
    function did not split on them (see AGENTS.md security fix log).
    """
    segments: list[str] = []
    current: list[str] = []
    quote_char: str | None = None
    i = 0
    while i < len(command):
        c = command[i]
        if quote_char:
            current.append(c)
            if c == quote_char:
                quote_char = None
            i += 1
            continue
        if c in ('"', "'"):
            quote_char = c
            current.append(c)
            i += 1
            continue
        if c == '$' and command[i:i + 2] == '$(':
            segments.append(''.join(current))
            current = []
            i += 2
            continue
        if c in '|;&<>`\n':
            segments.append(''.join(current))
            current = []
            i += 1
            continue
        current.append(c)
        i += 1
    segments.append(''.join(current))
    return [s.strip() for s in segments if s.strip()]


def has_unsafe_substitution(command: str) -> bool:
    """Detect command substitution ($() or backticks) inside double-quoted sections.

    has_shell_operators() strips quoted sections BEFORE searching for operators,
    and split_command_segments() does not split inside quotes -- but a real shell
    (PowerShell, bash, zsh) DOES expand $() and backticks inside double quotes.
    `echo "$(whoami)"` therefore passes the operator check while the shell still
    executes `whoami`. This function scans the RAW string and fails closed for
    that case (C-2, auditoría 2026-08-11).

    Single-quoted sections are intentionally NOT flagged: in both PowerShell and
    bash single quotes are fully literal (no $()/backtick expansion), so flagging
    them would be a false positive. Bare `$` is not flagged either -- only `$(`,
    the actual substitution syntax. Over-flagging is accepted by design (Opción A:
    fail-closed beats a subtle off-by-one in a security boundary).
    """
    in_double = False
    in_single = False
    i = 0
    while i < len(command):
        c = command[i]
        if in_double:
            if c == '"':
                in_double = False
            elif c == '`' or (c == '$' and command[i:i + 2] == '$('):
                return True
            i += 1
            continue
        if in_single:
            if c == "'":
                in_single = False
            i += 1
            continue
        if c == '"':
            in_double = True
        elif c == "'":
            in_single = True
        i += 1
    return False


# Platform-specific shell registries
_WINDOWS_SHELLS: dict[str, ShellInfo] = {
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

_LINUX_SHELLS: dict[str, ShellInfo] = {
    "bash": ShellInfo(
        name="bash",
        executable="bash",
        command_args=["-c"],
        session_args=[],
        script_args=["-c"],
        workdir_prefix='cd "{wd}" && ',
    ),
    "zsh": ShellInfo(
        name="zsh",
        executable="zsh",
        command_args=["-c"],
        session_args=[],
        script_args=["-c"],
        workdir_prefix='cd "{wd}" && ',
    ),
    "fish": ShellInfo(
        name="fish",
        executable="fish",
        command_args=["-c"],
        session_args=[],
        script_args=["-c"],
        workdir_prefix='cd "{wd}" && ',
    ),
    "sh": ShellInfo(
        name="sh",
        executable="sh",
        command_args=["-c"],
        session_args=[],
        script_args=["-c"],
        workdir_prefix='cd "{wd}" && ',
    ),
}

if sys.platform == "win32":
    SHELL_REGISTRY = _WINDOWS_SHELLS
else:
    SHELL_REGISTRY = _LINUX_SHELLS


def get_default_shell() -> str:
    """Return the default shell for the current platform."""
    if sys.platform == "win32":
        return "powershell"
    # On Linux/macOS, prefer bash (ubiquitous)
    return "bash"


def _find_executable(name: str, shell_map: dict[str, str] | None = None) -> str | None:
    if shell_map and name in shell_map:
        candidate = shell_map[name]
        if os.path.isfile(candidate):
            return candidate
    if name == "bash" and sys.platform == "win32":
        return _find_git_bash()
    return shutil.which(name)


def _find_git_bash() -> str | None:
    git_bash = os.environ.get("PERSONAL_MCP_GIT_BASH_PATH")
    if git_bash and os.path.isfile(git_bash):
        return git_bash
    try:
        result = subprocess.run(
            ["git", "--exec-path"],
            capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL,
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


def resolve_shell(name: str, shell_map: dict[str, str] | None = None) -> ShellInfo:
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


_DEFAULT_PATHEXT = ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC"


def shell_subprocess_env() -> dict[str, str] | None:
    """Env explicito para spawns que invocan un shell real (PowerShell/cmd/bash).

    No usar para la Ruta A de sh_exec (exec nativo via shutil.which +
    create_subprocess_exec directo) -- esa ruta no pasa por resolucion de
    comandos de PowerShell y no tiene este bug.

    Causa raiz (diagnosticado 2026-08-06/08, confirmado empiricamente con
    _diag_pathext_fix.py): el
    proceso Python del servidor puede heredar un PATHEXT vacio o incompleto
    (visto en vivo en esta maquina: ".CPL" solamente, sin ".EXE"). Sin
    ".EXE" en esa lista, la resolucion de comandos de PowerShell (Get-Command
    y el interprete de -Command) no reconoce git.exe como ejecutable, aunque
    el archivo exista y su carpeta este en PATH. shutil.which() no depende de
    PATHEXT del mismo modo -- por eso la Ruta A nunca mostro este bug.

    Devuelve None en plataformas no-Windows: PATHEXT es un concepto exclusivo
    de Windows, no hay nada que corregir ahi (el llamador debe omitir env= si
    esto devuelve None, para no pisar el entorno heredado sin necesidad).
    """
    if sys.platform != "win32":
        return None
    env = os.environ.copy()
    if ".EXE" not in env.get("PATHEXT", "").upper():
        env["PATHEXT"] = _DEFAULT_PATHEXT
    return env
