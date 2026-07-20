import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class CommandPolicy(BaseModel):
    allow_prefix: List[str] = Field(default_factory=lambda: ["git", "npm", "python", "ls", "pytest", "echo"])
    readonly_prefix: List[str] = Field(default_factory=lambda: [
        "git status", "git log", "git diff", "git show", "git branch", "git remote -v",
        "ls", "dir", "cat", "type", "echo",
        "docker ps", "docker images", "docker version",
        "npm list", "npm --version", "npm ls",
        "dotnet --version", "dotnet --info",
        "node --version", "pnpm --version", "pnpm list",
        "flutter --version", "flutter doctor",
        "python --version",
    ])
    deny: List[str] = Field(default_factory=lambda: [
        "shutdown", "reboot", "restart-computer", "stop-computer",
        "format", "format-volume", "reg delete", "net user",
        "net localgroup administrators", "clear-eventlog",
        "remove-item -recurse -force", "rm -rf", "rm -r -f"
    ])
    require_flag_approval: List[str] = Field(default_factory=lambda: [
        "-force", "-f", "/f", "/q", "-recurse -force"
    ])
    # General-purpose interpreters require an explicit HITL execute-approval ticket
    # (session grant) before sh_exec/sh_session_send will run them, even though they
    # remain in allow_prefix. See security.validate_shell_execution() in security.py.
    approval_required_prefix: List[str] = Field(default_factory=lambda: ["python", "node", "bash"])

    def is_command_allowed(self, command: str) -> tuple[bool, str]:
        cmd_lower = command.strip().lower()
        from src.shell_resolver import split_command_segments
        segments = split_command_segments(command) or [command]

        for denied in self.deny:
            denied_lower = denied.lower()
            if " " in denied_lower:
                # Multi-word phrase: match anywhere in the full command.
                if re.search(r'\b' + re.escape(denied_lower) + r'\b', cmd_lower):
                    return False, f"Command denied: '{denied}' is in the deny list"
            else:
                # Single word: only match a segment's own first token, not as a
                # substring anywhere else (avoids false positives like
                # 'Format-Table' or '--format' being blocked by a bare 'format' entry).
                for segment in segments:
                    seg_first = segment.strip().lower().split()[0] if segment.strip() else ""
                    seg_first_clean = Path(seg_first).stem.lower()
                    if seg_first_clean == denied_lower:
                        return False, f"Command denied: '{denied}' is in the deny list"

        if not self.allow_prefix:
            return False, "Command blocked: No allowed command prefixes configured"
        for segment in segments:
            seg_lower = segment.strip().lower()
            first_word = seg_lower.split()[0] if seg_lower.split() else ""
            first_word_clean = Path(first_word).stem.lower()
            if not any(first_word_clean == allowed.lower() for allowed in self.allow_prefix):
                return False, (
                    f"Command '{first_word}' is not in the allowed command whitelist "
                    f"(found in segment: '{segment[:60]}')"
                )
        for flag in self.require_flag_approval:
            if re.search(r'(?<!\w)' + re.escape(flag.lower()) + r'(?!\w)', cmd_lower):
                return False, f"Flag '{flag}' requires explicit approval"
        return True, ""

    def is_script_readonly(self, script: str) -> tuple[bool, str]:
        """Validate a multi-line sh_script submission: EVERY non-empty, non-comment
        line must start with an explicitly whitelisted read-only prefix.

        This is intentionally a SEPARATE, stricter allowlist than allow_prefix (used by
        sh_exec): sh_script writes the entire content to a file and executes it in one
        shot with no further per-line approval, so a first-line-only or first-100-chars
        check (the previous behavior) gives no real guarantee about the rest of the
        script. Every line is checked independently here.
        """
        if not self.readonly_prefix:
            return False, "No read-only command prefixes configured (security.commands.readonly_prefix)"
        for i, raw_line in enumerate(script.splitlines(), 1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            line_lower = line.lower()
            if not any(line_lower.startswith(p.lower()) for p in self.readonly_prefix):
                return False, f"Line {i} is not in the read-only whitelist: '{line[:60]}'"
        return True, ""


class SecurityConfig(BaseModel):
    paths_allow: List[str] = Field(default_factory=lambda: [
        str(Path.home() / "Repos"),
        str(Path.home() / "Desktop"),
        str(Path.home() / "OneDrive"),
        str(Path.home() / ".personal-mcp"),
    ])
    paths_deny: List[str] = Field(default_factory=lambda: [
        "**\\node_modules\\**", "**\\.git\\**", "**\\bin\\**", "**\\obj\\**",
        str(Path.home() / "AppData"),
    ])
    # Excepcion acotada a paths_deny, para necesidades legitimas como verificar
    # artefactos de build de un proyecto (.NET, etc.) sin abrir **\bin\**/**\obj\**
    # en general -- eso sigue bloqueado para todo lo demas (node_modules,
    # binarios de terceros, etc.). Se evalua SOLO para operaciones de lectura
    # (fs_find/fs_read) y SOLO si la extension del archivo esta en
    # paths_deny_exception_extensions. Nunca aplica a escritura, borrado ni
    # ejecucion -- ver SecurityValidator._deny_exception_applies() en security.py.
    # Vacio por defecto: no cambia el comportamiento existente hasta que se
    # agregue un patron explicitamente.
    paths_deny_exceptions: List[str] = Field(default_factory=list)
    paths_deny_exception_extensions: List[str] = Field(default_factory=lambda: [
        ".dll", ".exe", ".pdb"
    ])
    commands: CommandPolicy = Field(default_factory=CommandPolicy)
    rate_limit_commands_per_minute: int = 60
    rate_limit_files_per_operation: int = 100
    secret_scanning_enabled: bool = True


class ShellConfig(BaseModel):
    enabled: bool = True
    default_shell: str = "powershell"
    shell_map: Dict[str, str] = Field(default_factory=dict)
    session_timeout_seconds: int = 600
    command_timeout_seconds: int = 120


class SSHConfig(BaseModel):
    enabled: bool = False


class LogConfig(BaseModel):
    level: str = "INFO"
    max_bytes: int = 10 * 1024 * 1024
    backup_count: int = 3


class JournalConfig(BaseModel):
    enabled: bool = True
    path: str = Field(default_factory=lambda: str(Path.home() / ".personal-mcp" / "data" / "journal"))


class AppConfig(BaseModel):
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    shell: ShellConfig = Field(default_factory=ShellConfig)
    ssh: SSHConfig = Field(default_factory=SSHConfig)
    log: LogConfig = Field(default_factory=LogConfig)
    journal: JournalConfig = Field(default_factory=JournalConfig)
    audit_max_entries: int = 10000
    data_dir: str = Field(default_factory=lambda: str(Path.home() / ".personal-mcp" / "data"))

    config_path: Optional[str] = None

    @classmethod
    def default_path(cls) -> Path:
        return Path.home() / ".personal-mcp" / "config.json"

    def get_config_path(self) -> Path:
        if self.config_path:
            return Path(self.config_path)
        return self.default_path()

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "AppConfig":
        path = path or cls.default_path()
        if path.exists():
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            return cls.model_validate(data)
        cfg = cls()
        cfg.save(path)
        return cfg

    def save(self, path: Optional[Path] = None) -> None:
        path = path or self.get_config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.model_dump(mode="json"), f, indent=2, ensure_ascii=False)
