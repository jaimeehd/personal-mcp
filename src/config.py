import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class CommandPolicy(BaseModel):
    allow_prefix: List[str] = Field(default_factory=list)
    deny: List[str] = Field(default_factory=lambda: [
        "shutdown", "reboot", "restart-computer", "stop-computer",
        "format", "format-volume", "reg delete", "net user",
        "net localgroup administrators", "clear-eventlog",
        "remove-item -recurse -force", "rm -rf", "rm -r -f"
    ])
    require_flag_approval: List[str] = Field(default_factory=lambda: [
        "-force", "-f", "/f", "/q", "-recurse -force"
    ])

    def is_command_allowed(self, command: str) -> tuple[bool, str]:
        cmd_lower = command.strip().lower()
        for denied in self.deny:
            if re.search(r'\b' + re.escape(denied) + r'\b', cmd_lower):
                return False, f"Command denied: '{denied}' is in the deny list"
        if self.allow_prefix:
            first_word = cmd_lower.split()[0] if cmd_lower.split() else ""
            if not any(first_word == allowed.lower() for allowed in self.allow_prefix):
                return False, f"Command prefix '{first_word}' not in allow list"
        for flag in self.require_flag_approval:
            if re.search(r'(?<!\w)' + re.escape(flag.lower()) + r'(?!\w)', cmd_lower):
                return False, f"Flag '{flag}' requires explicit approval"
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
    commands: CommandPolicy = Field(default_factory=CommandPolicy)
    rate_limit_commands_per_minute: int = 60
    rate_limit_files_per_operation: int = 100


class ShellConfig(BaseModel):
    enabled: bool = True
    default_shell: str = "powershell"
    shell_map: Dict[str, str] = Field(default_factory=dict)
    session_timeout_seconds: int = 600
    command_timeout_seconds: int = 120


class SSHConfig(BaseModel):
    enabled: bool = False


class JournalConfig(BaseModel):
    enabled: bool = True
    path: str = Field(default_factory=lambda: str(Path.home() / ".personal-mcp" / "data" / "journal"))


class AppConfig(BaseModel):
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    shell: ShellConfig = Field(default_factory=ShellConfig)
    ssh: SSHConfig = Field(default_factory=SSHConfig)
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
