# personal-mcp

Custom MCP server for Windows workstation orchestration. High-security "Human-in-the-Loop" (HITL) model, fully async I/O, persistent PowerShell sessions.

## Architecture

```
6 layers, hexagonal design:
  Layer 1: Filesystem      — 11 tools (read, write, edit, list, tree, search, find, info, diff, batch, snapshot)
Layer 2: Shell — 9 tools (exec, persistent sessions, script execution, history, configurable shell)
  Layer 3: SSH             — 4 tools (list hosts, connect, exec, disconnect) [disabled by default]
  Layer 4: Personal        — 8 tools (journal CRUD, quick notes, project scan, project find)
  Layer 5: Health/Diagnostics — 8 tools (health check, disk, processes, config, diag, audit log, tool list, benchmark)
  Layer 6: Permissions     — 6 tools (approve, deny, pre-authorize, list pending, revoke, stats)
```

## Tools

### Layer 1 — Filesystem (restricted to allowed_paths from config)
| Tool | Description |
|------|-------------|
| `fs_read` | Read file content (auto-detect binary) |
| `fs_write` | Write file content |
| `fs_edit` | Replace text in file with diff preview |
| `fs_list` | List directory with filters |
| `fs_tree` | Directory tree with depth limit |
| `fs_search` | Grep-like regex search across files |
| `fs_find` | Find files by name, size, age |
| `fs_info` | File metadata including SHA256 hash |
| `fs_diff` | Diff two files or file vs snapshot |
| `fs_batch` | Batch copy/move/rename with dry-run |
| `fs_snapshot` | Snapshot directory state to JSON |

### Layer 2 — Shell (multi-shell execution, runtime shell switching)
| Tool | Description |
|------|-------------|
| `sh_exec` | Execute one-shot command. Parameters: `command`, `timeout`, `working_dir?`, `shell?` (powershell/pwsh/cmd/bash) |
| `sh_session_start` | Create persistent shell session (powershell/pwsh only). Parameters: `timeout?`, `shell?` |
| `sh_session_list` | List active sessions |
| `sh_session_send` | Send command to session |
| `sh_session_read` | Read pending output from session |
| `sh_session_interrupt` | Send Ctrl+C to session |
| `sh_session_close` | Close session |
| `sh_script` | Execute multi-line script from temp file. Parameters: `script`, `timeout`, `working_dir?`, `shell?` |

### Layer 3 — SSH (conditional, off by default)
| Tool | Description |
|------|-------------|
| `ssh_list_hosts` | List hosts from ~/.ssh/config |
| `ssh_connect` | Open SSH session |
| `ssh_exec` | Execute command on remote host |
| `ssh_disconnect` | Close SSH session |

### Layer 4 — Personal
| Tool | Description |
|------|-------------|
| `journal_add` | Add journal entry with tags/category |
| `journal_list` | List entries with filters |
| `journal_search` | Full-text search in journal |
| `journal_stats` | Entry statistics by tag/category |
| `journal_export` | Export journal as JSON or Markdown |
| `note_quick` | Quick note to inbox file |
| `project_scan` | Scan repos: branch, uncommitted changes |
| `project_find` | Find file across all allowed repos |

### Layer 5 — Health & Diagnostics
| Tool | Description |
|------|-------------|
| `health_check` | Full system health overview |
| `health_disk` | Disk usage for specified paths |
| `health_processes` | Top processes by CPU |
| `health_config` | Current config (validated) |
| `mcp_diag` | Full diagnostic report |
| `mcp_audit_log` | Recent operation audit trail |
| `mcp_list_tools` | List all registered tools |
| `mcp_benchmark` | Performance benchmarks |

### Layer 6 — Permissions
| Tool | Description |
|------|-------------|
| `fs_approve` | Approve a pending permission ticket (single/session/permanent) |
| `fs_deny` | Explicitly deny a ticket |
| `fs_request_allow` | Pre-authorize a path without requiring a ticket |
| `security_pending` | List all pending permission requests |
| `security_revoke` | Revoke an active session/permanent grant |
| `security_stats` | Permission system statistics |

## Security

- **Human-in-the-Loop (HITL)**: No file operation (read, write, edit) or shell execution is performed without explicit user approval. The server generates a permission ticket, and the user must approve it via `fs_approve` before the action is executed.
- **Strict Path Hard-Lock**: Only paths defined in `security.paths_allow` (and internal `data_dir`) are accessible. Any attempt to access paths outside this list is immediately denied with a hard error—no dynamic requests are permitted for external paths.
- **Command Whitelist**: Shell execution is restricted to a strict whitelist of approved command prefixes (e.g., `git`, `npm`, `python`, `ls`). Commands not in the whitelist are blocked.
- **Recursive Session Grants**: Approving a directory for a session (`level='session'`) automatically grants access to all its sub-directories and files, reducing approval friction for complex projects.
- **Path denylist**: Paths matching `security.paths_deny` patterns (e.g. `**\node_modules\**`, `**\.git\**`) are blocked even if they're under an allowed directory.
- **`validate_tool_path()`**: All layer 1/2 tools validate paths through this method. If a path is in `paths_allow` but lacks a grant, a `permission_required` JSON payload is returned for user approval.
- **Output truncation**: All shell output is capped at 1 MiB to prevent memory issues. Truncated output is flagged with a notice.
- **Process tree cleanup**: Timed-out commands use `taskkill /T /F` to recursively terminate all child processes.
- **Rate limits**: Commands/min and files/operation limits.
- **Audit trail**: Every operation logged (circular buffer, 10k entries) with sensitive data automatically scrubbed.

## Shell Configuration

The shell layer supports multiple shells configured via `~/.personal-mcp/config.json`:

| Shell | Config value | Interactive sessions | Script execution | Auto-detected path |
|-------|-------------|---------------------|-----------------|-------------------|
| PowerShell (default) | `"powershell"` | Yes | Yes (`.ps1`) | `%PATH%` |
| PowerShell Core | `"pwsh"` | Yes | Yes (`.ps1`) | `%PATH%` or custom path |
| CMD | `"cmd"` | No | Yes (`.bat`) | `%COMSPEC%` |
| Git Bash | `"bash"` | No | Yes (`.sh`) | `git --exec-path` or `OPENCODE_GIT_BASH_PATH` |

```json
{
  "shell": {
    "default_shell": "powershell",
    "shell_map": {
      "pwsh": "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
      "bash": "C:\\Program Files\\Git\\bin\\bash.exe"
    }
  }
}
```

The agent can also switch shells at runtime per-command via the `shell` parameter on `sh_exec`, `sh_script`, and `sh_session_start`. Example:

```
sh_exec("echo hello", shell="cmd")
sh_script("echo hello", shell="cmd")
sh_session_start(shell="pwsh")
```

When `shell` is omitted, the configured `default_shell` is used. Invalid shell names return a clear error message.

## Installation

```powershell
.\install.ps1
```

This will:
1. Verify Python 3.10+
2. Create virtual environment (`.venv`)
3. Create directory structure
4. Install Python dependencies in the venv
5. Generate default config with auto-detected workspace paths
6. Register with Claude Desktop using the venv Python

## Configuration

Edit `~/.personal-mcp/config.json` to customize. A read-only mirror of this
file is kept at the repo root (`config.json`) for convenience — run
`sync-config.ps1` to refresh it from the official copy. See
[`CONFIG-GUIA.md`](CONFIG-GUIA.md) for a plain-language, non-technical
explanation of every field (in Spanish).

- **Interactive Setup**: Use `python configure_paths.py` to manage your allowed directories without editing the JSON manually.
- **Example Config**: See `config.demo.json` for a secure, productivity-optimized template.
- `security.paths_allow`: Accessible directories (default: `~/Repos`, `~/Desktop`, `~/OneDrive`, `~/.personal-mcp`)
- `security.paths_deny`: Blocked path patterns (default: `**\node_modules\**`, `**\.git\**`, `**\bin\**`, `**\obj\**`, `~/AppData`)
- `security.commands.allow_prefix`: Mandatory whitelist of permitted command prefixes (e.g. `git`, `npm`, `python`).
- `security.rate_limit_commands_per_minute`: Max commands per minute (default: 60)
- `shell.session_timeout_seconds`: Session idle timeout (default: 600)
- `ssh.enabled`: Set `true` to enable SSH layer (requires ~/.ssh/config)

## Development

```bash
.\.venv\Scripts\python -m pytest tests/ -v      # 121 tests (all pass)
.\.venv\ modifying .venv\Scripts\python -m src.server             # stdio mode
.\install.ps1                    # register with Claude Desktop (auto-creates venv)
```
