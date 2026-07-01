# personal-mcp — AGENTS.md

## Quick start
```powershell
cd C:\Repos\.personal-mcp
.\.venv\Scripts\python -m pytest tests/ -v       # 105 tests (all pass)
.\.venv\Scripts\python -m src.server              # stdio mode for Claude Desktop
.\install.ps1                                     # register with Claude Desktop (auto-creates venv)
```

## Architecture — 6 hexagonal layers, 46 tools
| Layer | File | Tools | Security boundary |
|-------|------|-------|-------------------|
| 1 Filesystem | `layer1_filesystem.py` | 11 | `resolve_and_validate()` on every path |
| 2 Shell | `layer2_shell.py` + `shell_resolver.py` | 9 | command deny list + path scanning + multi-shell (powershell/pwsh/cmd/bash) |
| 3 SSH | `layer3_ssh.py` | 4 | disabled by default (`ssh.enabled: false`) |
| 4 Personal | `layer4_personal.py` | 8 | journal, notes, project scan |
| 5 Health | `layer5_health.py` | 8 | diagnostics, audit, benchmark |
| 6 Permissions | `layer6_permissions.py` | 6 | ticket-based approval flow |

- Every tool has a standalone `_impl` async function (testable without FastMCP)
- Closures in `register_*()` wrap `_impl` with security/permission checks
- `sys.path.insert(0, ...)` at top of `server.py` and `conftest.py` — always run from repo root

## Security rules (don't violate)
1. **All paths** go through `security.resolve_and_validate()` — `PathNotAllowedError` if outside `paths_allow`
2. **Shell commands** validated via `config.security.commands.is_command_allowed()` (deny list → optional prefix allowlist → flag approval). Blocklist model by default.
3. **No tickets on hot path**: `validate_tool_path()` returns error string (never `permission_required` JSON). Tickets only from explicit `fs_request_allow`.
4. `working_dir` prefix resolved from `shell_info.workdir_prefix` (per-shell: `Set-Location`, `cd /d`, `cd`)
5. Shell commands scanned for absolute paths (`C:\...`, `C:/...`) via `security.extract_absolute_paths()`
6. `check_granted()` now uses `Dict[str, Set[str]]` — grants are per-operation, "read" != "write"

## Key modules
- `src/shell_resolver.py` — `ShellInfo` dataclass, `SHELL_REGISTRY` (4 shells), `resolve_shell()`, `_find_executable()`, `_find_git_bash()`
- `src/config.py:ShellConfig` — `default_shell` (string), `shell_map` (dict for custom paths)
- `src/layers/layer2_shell.py` — `MAX_CAPTURE_BYTES=1MiB`, `_truncate()`, `_kill_process_tree()` (taskkill /T /F), `_scan_command_warnings()`

## PermissionManager quirks
- `GrantLevel`: `SINGLE`, `SESSION`, `PERMANENT`
- `_session_grants` changed from `Set[str]` to `Dict[str, Set[str]]` — stores (path, operation) pairs
- `check_granted(resource, operation)` now verifies operation matches (or "*")
- `check_granted()` auto-grants any path under `data_dir` or `paths_allow`
- Tickets expire after 300s
- `grant_direct()` bypasses pending, creates approved ticket immediately
- `config.save()` writes to config_path — tests set `config_path` to temp path

## Testing
- `asyncio_mode = "auto"` — `async def` tests auto-run (no marker needed)
- Tests import `_impl` directly (not through FastMCP) — this is the intended pattern
- `conftest.py` provides: `temp_home` (tmp_path), `test_config`, `security`, `sample_file`, `sample_dir`
- `tests/test_shell_resolver.py` — 8 tests for shell resolution, executable finding
- Always create fresh `SecurityValidator` per test — `_resolved_allowed` caches stale
- `ResourceWarning` about `_ProactorBasePipeTransport.__del__` is harmless Windows asyncio cleanup

## Gotchas
- `Path.resolve()` on Windows normalizes casing (e.g. `Temp` → `temp`) — use `self._resolve()` helper in PermissionManager
- FastMCP 3.x constructor only accepts `name`
- `config.data_dir` overridden at `server.py:32` to `~/.personal-mcp/data`
- `sh_script` writes temp file with extension matching shell (`.ps1`/`.bat`/`.sh`) to `~/.personal-mcp/data/`
- `sh_session_start` returns error if shell doesn't support interactive sessions (cmd, bash have `session_args=[]`)
- **Shell switching**: `sh_exec`, `sh_script`, `sh_session_start` accept optional `shell` param — resolves at runtime via `ShellManager.resolve_shell()`
- **`validate_tool_path(self, raw_path, operation="read")`**: Layer 1 calls pass `"read"`/`"write"` as operation; Layer 2 calls omit it (uses default). The `operation` param is accepted but not currently enforced.
- Shell output truncated at 1 MiB — message appended if truncated
- Timeout cleanup uses `taskkill /pid /T /F` (recursive, Windows-only)
- SSH layer is opt-in — `ssh.enabled: false` by default
- `import sys; sys.path.insert(0, ...)` required at every entrypoint for `src.` imports
- All `_impl` functions accept `security` as parameter — closures bind it at registration time
