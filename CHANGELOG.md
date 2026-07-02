# Changelog

## [1.4.0] — 2026-07-01

### Added
- **Structured Logging System** (`src/log.py`): New logging infrastructure with `RotatingFileHandler`, log levels (INFO, DEBUG, WARN, ERROR), and precise operation timing using `timed()` context manager.
- **Sensitive Data Sanitization**: Recursive scrubbing of sensitive keys (`password`, `token`, `secret`, etc.) in all server logs to prevent information leakage.
- **Interactive Path Configurator** (`configure_paths.py`): CLI utility to manage `paths_allow` without manual JSON editing.
- **Configuration Template**: `config.demo.json` added as a secure reference for new users.

### Changed
- **Hard-Lock Security Model**: 
  - **Absolute Path Lockdown**: Paths outside `paths_allow` or `data_dir` are now strictly denied immediately. No dynamic tickets can bypass this lock.
  - **Strict Command Whitelist**: Replaced the blocklist model with a mandatory whitelist (`allow_prefix`). Only explicitly approved command prefixes (e.g., `git`, `npm`, `python`) can be executed.
- **Human-in-the-Loop (HITL) Enforcement**: All read, write, and execute operations now require explicit user approval via tickets, regardless of whether the path is in the allowlist.
- **Recursive Session Grants**: `PermissionManager` now supports recursive session grants; approving a directory allows access to all its sub-paths for the duration of the session.
- **Productivity Pack**: Expanded default command whitelist to include essential dev tools: `uv`, `make`, `docker`, `mkdir`, `rmdir`, `cat`, `type`.

### Fixed
- **Single Grant Consumption Bug**: Fixed a race condition where `SINGLE` grants were consumed during the validation phase before the tool could execute.
- **Path normalization consistency**: Improved path resolution in `PermissionManager` to prevent casing mismatches on Windows.

## [1.3.0] — 2026-07-01
... (rest of the file)

### Added
- **Shell resolver module** (`src/shell_resolver.py`): `ShellInfo` dataclass, `SHELL_REGISTRY` with 4 shells (powershell, pwsh, cmd, bash), `resolve_shell()` with auto-detection. Git Bash discovery via `git --exec-path` or `OPENCODE_GIT_BASH_PATH` env var.
- **Configurable shell**: Respects `ShellConfig.default_shell` (powershell/pwsh/cmd/bash) and `ShellConfig.shell_map` for custom executable paths.
- **Output truncation**: Captured output capped at 1 MiB (`MAX_CAPTURE_BYTES`). Truncated outputs include `[output truncated at 1,048,576 bytes — use a more specific command to narrow results]` notice.
- **Process tree killing**: Timeout cleanup uses `taskkill /pid <pid> /T /F` to recursively terminate process trees on Windows.
- **Advisory path warnings**: Shell commands with absolute paths outside `paths_allow` produce `[warning]` lines in output (non-blocking, informational).
- **12 new tests**: Shell resolver, truncation, cmd/pwsh execution, session rejection for non-interactive shells, kill tree, path warnings.

### Changed
- **`ShellManager`**: Accepts `shell_info: ShellInfo` parameter. Defaults to auto-resolved PowerShell if not provided.
- **`ShellSession`**: Constructor accepts `shell_info` parameter; `start()` uses resolved shell's `session_args` instead of hardcoded `powershell.exe -NoExit -Command -`.
- **`sh_exec_impl`**: Accepts optional `shell_info`; uses resolved shell's `command_args` and `workdir_prefix` for working directory.
- **`sh_script_impl`**: Accepts optional `shell_info`; uses resolved shell's `script_args`; temp file extension adapts to shell (`.ps1`/`.bat`/`.sh`).
- **`sh_session_start_impl`**: Returns error JSON when shell doesn't support interactive sessions (cmd, bash).
- **`register_shell_tools` closures**: `sh_exec`, `sh_script`, `sh_session_send` now produce `[warning]` lines for paths outside allowlist (non-blocking).
- **`ShellConfig`**: Added `shell_map: dict[str, str]` field for custom executable paths.
- **`shell` parameter on tools**: `sh_exec`, `sh_script`, and `sh_session_start` now accept an optional `shell` parameter (e.g. `shell="cmd"`, `shell="pwsh"`). When provided, the tool resolves and uses that shell for that single invocation. Falls back to configured default when omitted.
- **`ShellManager.__init__`**: Now accepts `shell_map` parameter — stored for runtime shell resolution.
- **`ShellManager.resolve_shell(name)`**: New method that delegates to `resolve_shell(name, self.shell_map)`, enabling runtime shell switching.
- **`server.py`**: Passes `config.shell.shell_map` to `ShellManager`.
- **105 tests** (0 skipped): `test_resolve_pwsh` now passes after installing PowerShell 7.5.0 portable. 5 new tests for shell switching.

### Fixed
- Timeout handlers in `sh_exec_impl` and `sh_script_impl` now use `_kill_process_tree()` (taskkill /T /F) instead of `process.kill()`, ensuring child processes are cleaned up.
- `ShellSession.close()` timeout path uses taskkill for recursive cleanup.

## [1.2.0] — 2026-07-01

### Changed
- **Security model from allowlist to blocklist**: `allow_prefix` defaults to `[]` (empty). Any command not in the deny list is allowed. Desktop Commander-compatible model.
- **`authorize()` → `validate_tool_path()`**: Hot-path tools (filesystem, shell) no longer generate permission tickets. Returns a plain error string when a path is outside `paths_allow`. Tickets only appear via explicit `fs_approve`/`fs_deny` tools.
- **`check_granted()` now uses `operation`**: `_session_grants` changed from `Set[str]` to `Dict[str, Set[str]]`. A "read" grant no longer silently authorizes "write".
- **`_validate_command_paths()` uses `is_path_allowed()`**: Shell commands with absolute paths outside the allowlist return a clean error string instead of a ticket JSON blob.
- **Async I/O for all filesystem ops**: `fs_read`, `fs_write`, `fs_diff`, `fs_snapshot` use `asyncio.to_thread()` for blocking file operations. No more event loop blocking.
- **Async I/O for shell scripts**: `sh_script_impl` wraps `write_text()` and `unlink()` in `asyncio.to_thread()`.
- **`fs_write` no longer creates `.bak` backups**: Eliminates unnecessary I/O on every write.
- **`config_path` field on `AppConfig`**: Tests write to isolated temp configs via `config_path`, never touch `~/.personal-mcp/config.json`.

### Fixed
- `PATH_RE` regex now matches forward-slash paths (e.g. `C:/foo/bar`) — PowerShell accepts both separators; backslash-only regex let `C:/` paths bypass shell command scanning.
- `import uvicorn` removed from `server.py` (FastMCP 3.x doesn't use it).
- `SecurityValidator` unreferenced `_resolved_allowed` cache stays valid across config saves.
- Tests no longer pollute real config: `strict_config` fixture includes `config_path`.

### Removed
- `default_deny: bool` from `SecurityConfig` — dead code, never read.

## [1.1.0] — 2026-06-30

### Added
- **Permission system (Layer 6)**: New `PermissionManager` with ticket-based access control. When a tool accesses a path outside the allowlist, a structured `permission_required` response is returned instead of an error, allowing the user to approve via `fs_approve`.
  - Three grant levels: `single` (one-time), `session` (server lifetime), `permanent` (added to config)
  - Automatic expiry of pending tickets after 5 minutes
  - Session grants tracked in-memory; permanent grants persisted to `config.json`
- **6 permission tools**: `fs_approve`, `fs_deny`, `fs_request_allow`, `security_pending`, `security_revoke`, `security_stats`
- **`working_dir` parameter**: `sh_exec` and `sh_script` now accept an optional `working_dir` to scope command execution to a specific directory
- **Absolute path scanning in shell commands**: Commands are scanned for `C:\...` patterns; paths outside the allowlist trigger permission tickets
- **`security.is_path_allowed()`**: Quick boolean check without raising exceptions
- **`security.extract_absolute_paths()`**: Regex-based extraction of Windows absolute paths from text
- **16 permission tests**: Covering ticket lifecycle, grant levels, revoke, stats, direct grants
- **`GrantLevel` enum**: `SINGLE`, `SESSION`, `PERMANENT` with string serialization

### Changed
- **Filesystem layer**: All 11 tools now catch `PathNotAllowedError` and return a permission ticket response instead of failing
- **Shell layer**: `sh_exec` and `sh_script` validate `working_dir` and scan commands for absolute paths
- **`SecurityValidator`**: Optional `perm_manager` attribute wired to `PermissionManager`
- **`PermissionManager.approve()`**: Now accepts optional `level` override parameter
- **`install.ps1`**: Updated tool summary to include Layer 6
- **README.md**: Updated architecture to 6 layers, added Layer 6 tools table, expanded security section

### Fixed
- `PermissionManager.revoke_ticket()` had a `token` / `ticket` typo — corrected
- `SecurityValidator.extract_absolute_paths()` regex now stops at whitespace (was greedy across words like "and")
- `PermissionManager._session_grants` now stores resolved paths (normalizes Windows casing) to fix set lookup mismatches

## [1.0.0] — 2026-06-30

### Added
- Initial release with 5-layer architecture
- Layer 1: Filesystem — 11 tools for read/write/edit/list/tree/search/find/info/diff/batch/snapshot
- Layer 2: Shell — 9 tools with persistent PowerShell sessions
- Layer 3: SSH — 4 tools (disabled by default)
- Layer 4: Personal — 8 tools (journal, notes, project scanning)
- Layer 5: Health — 8 diagnostic tools
- Security validator with path allowlist/denylist and command policy
- Audit log with circular buffer (10k entries) and JSON persistence
- 57 initial tests
- Installer script for Claude Desktop integration
- Verification script for live testing
