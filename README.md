# personal-mcp

Custom MCP server for Windows workstation orchestration. Allowlist-based security with HITL approval for writes, secret scanning, per-operation rate limiting, fully async I/O, persistent PowerShell sessions.

## Architecture

```
6 layers, hexagonal design:
  Layer 1: Filesystem      — 20 tools (read, write, edit, delete, delete-batch, list, tree, search, find, info, diff, batch, snapshot, create-dir, move, read-multi, list-allowed, list-with-sizes, read-media, edit-advanced)
Layer 2: Shell — 9 tools (exec, persistent sessions, script execution, history, configurable shell)
  Layer 3: SSH             — 4 tools (list hosts, connect, exec, disconnect) [disabled by default]
  Layer 4: Personal        — 8 tools (journal CRUD, quick notes, project scan, project find)
  Layer 5: Health/Diagnostics — 9 tools (health check, disk, processes, config, diag, audit log, tool list, benchmark, log tail)
  Layer 6: Permissions     — 6 tools (approve, deny, pre-authorize, list pending, revoke, stats)
```

56 tools total, 52 active (SSH's 4 disabled by default).

## Tools

### Layer 1 — Filesystem (restricted to allowed_paths from config)
| Tool | Description |
|------|-------------|
| `fs_read` | Read file content (auto-detect binary) |
| `fs_write` | Write file content |
| `fs_edit` | Replace text in file with diff preview |
| `fs_delete` | Delete a single file (no directories/recursion). `delete` tickets are always single-use — session/permanent grants are not possible, by design |
| `fs_delete_batch` | Delete multiple explicitly-listed files under one ticket/one confirmation code, instead of one popup per file. Same `delete`-only-single-use rule as `fs_delete` |
| `fs_list` | List directory with filters |
| `fs_tree` | Directory tree with depth limit |
| `fs_search` | Grep-like regex search across files (skips files >10MB) |
| `fs_find` | Find files by name, size, age |
| `fs_info` | File metadata including SHA256 hash |
| `fs_diff` | Diff two files or file vs snapshot |
| `fs_batch` | Batch copy/move/rename with dry-run |
| `fs_snapshot` | Snapshot directory state to JSON |
| `fs_create_directory` | Create a directory (and parents as needed) |
| `fs_move` | Move/rename a file |
| `fs_read_multi` | Read several files in one call |
| `fs_list_allowed` | List the configured `paths_allow` directories |
| `fs_list_with_sizes` | List directory entries with file sizes, sortable |
| `fs_read_media` | Read an image/binary file as base64, with secret scanning on decoded content |
| `fs_edit_advanced` | Multiple find/replace edits to a file in one call, with dry-run |

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
| `mcp_log` | Tail the server's own log file, filterable by level |

### Layer 6 — Permissions
| Tool | Description |
|------|-------------|
| `fs_approve` | Approve a pending permission ticket (single/session) |
| `fs_deny` | Explicitly deny a ticket |
| `fs_request_allow` | Create a pending permission ticket; use `fs_approve` to confirm |
| `security_pending` | List all pending permission requests |
| `security_revoke` | Revoke an active session/permanent grant |
| `security_stats` | Permission system statistics |

## Security

- **Human-in-the-Loop (HITL) with HMAC confirmation**: Write/delete operations and shell executions require explicit user approval via tickets. `fs_approve` requires a `confirm_code` — a 6-digit code shown *only* via a native Windows popup on the user's screen, never returned by any tool response. An agent has no channel to read or guess it (`hmac.compare_digest()` verification against an in-memory secret). Use `fs_request_allow` to create a pending ticket, then `fs_approve(ticket_id, confirm_code, level)` to confirm. Read operations within `paths_allow` pass directly (no ticket needed).
- **Execute-approval gate for general-purpose interpreters**: `python`/`node`/`bash` are whitelisted for legitimate dev workflows, but running one is a black box once approved — an explicit `execute` ticket (same HMAC-confirmed flow) is required before the interpreter is allowed to start at all, on top of the command whitelist below.
- **Batch operations use one ticket, not one per file**: `fs_delete_batch` binds a single ticket/confirmation code to an explicit list of paths.
- **Strict Path Hard-Lock**: Only paths defined in `security.paths_allow` (and internal `data_dir`) are accessible for reads without a ticket; paths outside are denied. Write/delete still require an explicit grant regardless of `paths_allow`'s scope.
- **Command Whitelist**: Shell execution is restricted to a strict whitelist of approved command prefixes (e.g., `git`, `npm`, `python`, `ls`). Commands not in the whitelist, or explicitly denied, are blocked.
- **Recursive Session Grants**: Approving a directory for a session (`level='session'`) automatically grants access to all its sub-directories and files, reducing approval friction for complex projects.
- **Path denylist**: Paths matching `security.paths_deny` patterns (e.g. `**\node_modules\**`, `**\.git\**`, `**\.ssh\**`, `**\.env*`, `**\*.pem`, credential files for git/npm/pip/docker/aws/azure/kube) are blocked even if they're under an allowed directory. A narrow, explicit, read-only exception exists for inspecting a project's own build artifacts (`.dll`/`.exe`/`.pdb` under `**\bin\**`/`**\obj\**`) without opening those folders in general — off by default, opt-in per project via `security.paths_deny_exceptions`.
- **`validate_tool_path()`**: All layer 1 tools validate paths through this method. For write/delete operations without a grant, a `permission_required` JSON ticket is returned. Reads in `paths_allow` pass directly (no ticket).
- **Rate limiting per-operation**: Sliding window rate limiter (`security.rate_limit_commands_per_minute`) applied independently per operation type (read/write) in `validate_tool_path()`. Disabled when set to 0.
- **Secret scanning**: File and media contents scanned for credentials (GitHub tokens, AWS keys, private keys, DB connection strings, etc.) on `fs_read`/`fs_read_media`/shell output/journal entries — warns only, never blocks. Configurable via `security.secret_scanning_enabled`.
- **Output truncation**: All shell output is capped at 1 MiB to prevent memory issues. Truncated output is flagged with a notice.
- **Process tree cleanup**: Timed-out commands use `taskkill /T /F` to recursively terminate all child processes, followed by reaping the original process handle to avoid leaking OS-level async I/O resources on Windows.
- **Audit trail**: Every operation logged (circular buffer, 10k entries) with sensitive data automatically scrubbed.
- **Known limitation — the generic `Filesystem` MCP connector, if also enabled with write access to this repo's own folder, bypasses every protection above.** It writes directly to disk with no tickets, no `confirm_code`, no audit trail — this server's security model only covers the tools *this* server exposes, not the repository as a file on disk. There is no code fix possible from within this project; if you also use the official `Filesystem` connector in the same MCP client, either avoid granting it write access to this repo's path, or accept that it's a parallel, unprotected write path to your own security configuration.

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

### Windows (PowerShell)
```powershell
.\install.ps1
```

### Linux / macOS (bash)
```bash
chmod +x install.sh
./install.sh
```

Both installers will:
1. Verify Python 3.10+
2. Create virtual environment (`.venv`)
3. Create directory structure
4. Install Python dependencies in the venv
5. Generate default config with auto-detected workspace paths
6. Register with Claude Desktop using the venv Python

### Manual Installation (all platforms)
```bash
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
# Windows: pip install pywin32
python -m src.server  # test run
```

Then configure Claude Desktop manually:
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

Add to `mcpServers`:
```json
{
  "mcpServers": {
    "personal-mcp": {
      "command": "/full/path/to/.venv/bin/python",
      "args": ["/full/path/to/run_server.py"]
    }
  }
}
```

## Configuration

Edit `~/.personal-mcp/config.json` to customize. A read-only mirror of this
file is kept at the repo root (`config.json`) for convenience — run
`sync-config.ps1` to refresh it from the official copy. See
[`CONFIG-GUIA.md`](CONFIG-GUIA.md) for a plain-language, non-technical
explanation of every field (in Spanish).

- **Interactive Setup**: Use `python configure_paths.py` to manage your allowed directories without editing the JSON manually.
- **Example Config**: See `config.demo.json` for a secure, productivity-optimized template.
- `security.paths_allow`: Accessible directories for reads without a ticket. In this deployment, deliberately set to `["C:\\"]` (whole drive) — write/delete still requires an explicit ticket regardless. Default for a fresh install remains scoped (e.g. `~/Repos`, `~/Desktop`, `~/OneDrive`, `~/.personal-mcp`); widen only if you understand `paths_deny` becomes your only real read control at that point.
- `security.paths_deny`: Blocked path patterns (default: `**\node_modules\**`, `**\.git\**`, `**\bin\**`, `**\obj\**`, `~/AppData` (recursive), plus credential-focused patterns: `.ssh`, `.aws`, `.azure`, `.kube`, `.gnupg`, `.env*`, `*.pem`, `id_rsa*`, `id_ed25519*`, git/npm/pip/docker credential files)
- `security.paths_deny_exceptions` / `paths_deny_exception_extensions`: narrow, read-only, opt-in exception to `paths_deny` for inspecting a project's own build artifacts (see Security section above). Empty by default.
- `security.commands.allow_prefix`: Mandatory whitelist of permitted command prefixes (e.g. `git`, `npm`, `python`).
- `security.rate_limit_commands_per_minute`: Max commands per minute (default: 60, 0 = disabled)
- `security.secret_scanning_enabled`: Scan file contents for secrets on fs_read (default: true)
- `shell.session_timeout_seconds`: Session idle timeout (default: 600)
- `ssh.enabled`: Set `true` to enable SSH layer (requires ~/.ssh/config)

## Development

```bash
# Windows
.\.venv\Scripts\python -m pytest tests/ -v
.\.venv\Scripts\python -m src.server

# Linux / macOS
source .venv/bin/activate
python -m pytest tests/ -v
python -m src.server
```

### Sync config mirror (repo copy → user config)
```bash
# Windows
.\sync-config.ps1

# Linux / macOS
./sync-config.sh
```
