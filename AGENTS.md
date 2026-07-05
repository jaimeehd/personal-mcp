# personal-mcp — AGENTS.md

> ⚠️ **LEE ESTO PRIMERO SI VAS A TOCAR `config.json`:**
> El `config.json` en la raíz de este repo (`C:\Repos\.personal-mcp\config.json`) es
> **solo un espejo de solo lectura**. NO lo edites pensando que cambia algo — no lo
> hace. El único config real que carga el servidor está en
> `~/.personal-mcp/config.json` (ver `AppConfig.default_path()` en `src/config.py`).
> Para actualizar el espejo tras editar el oficial, ejecuta `sync-config.ps1` desde
> la raíz del repo. Explicación completa en `CONFIG-GUIA.md`.

## Quick start
```powershell
cd C:\Repos\.personal-mcp
.\.venv\Scripts\python -m pytest tests/ -v       # 257 tests (all pass)
.\.venv\Scripts\python -m src.server              # stdio mode for Claude Desktop
.\install.ps1                                     # register with Claude Desktop (auto-creates venv)
.\sync-config.ps1                                 # refresh the read-only config.json mirror from ~/.personal-mcp/config.json
```

## Architecture — 6 hexagonal layers, 47 tools
| Layer | File | Tools | Security boundary |
|-------|------|-------|-------------------|
| 1 Filesystem | `layer1_filesystem.py` | 12 | `resolve_and_validate()` on every path |
| 2 Shell | `layer2_shell.py` + `shell_resolver.py` | 9 | command deny list + path scanning + multi-shell (powershell/pwsh/cmd/bash) |
| 3 SSH | `layer3_ssh.py` | 4 | disabled by default (`ssh.enabled: false`) |
| 4 Personal | `layer4_personal.py` | 8 | journal, notes, project scan |
| 5 Health | `layer5_health.py` | 9 | diagnostics, audit, benchmark, log tail (`mcp_log`) |
| 6 Permissions | `layer6_permissions.py` | 6 | ticket-based approval flow |

- Every tool has a standalone `_impl` async function (testable without FastMCP)
- Closures in `register_*()` wrap `_impl` with security/permission checks
- `sys.path.insert(0, ...)` at top of `server.py` and `conftest.py` — always run from repo root

## Security rules (don't violate)
1. **All paths** go through `security.resolve_and_validate()`. Read operations in `paths_allow` or `data_dir` pass directly. Write operations in `paths_allow` require explicit grant (session/single/permanent) via `check_granted()`. Paths outside both raise `PathNotAllowedError`.
2. **Shell commands** validated via a strict whitelist defined in `config.security.commands.allow_prefix`. Commands not matching the whitelist or explicitly denied are blocked.
   - ✅ **`sh_script` is genuinely read-only, enforced line by line**: `CommandPolicy.is_script_readonly()` validates EVERY non-empty, non-comment line against `security.commands.readonly_prefix` (a separate, stricter list than `allow_prefix`). A single line not matching an explicit read-only prefix rejects the whole script before it's written to disk or executed. (Previously this claim was documented but not enforced — only the first 100 characters were checked against the general whitelist; fixed 2026-07-03.)
3. **No tickets on hot path**: `validate_tool_path()` returns `None` for allowed read operations, a `permission_required` JSON payload for blocked write operations, or an error string for strictly denied paths (outside `paths_allow`/`data_dir`).
4. `working_dir` prefix resolved from `shell_info.workdir_prefix` (per-shell: `Set-Location`, `cd /d`, `cd`)
5. Shell commands scanned for absolute paths (`C:\...`, `C:/...`) via `security.extract_absolute_paths()`
6. `check_granted()` now uses `Dict[str, Set[str]]` — grants are per-operation, "read" != "write"
7. **`fs_delete`** uses `operation="delete"`, fully isolated from `"read"`/`"write"` — an existing write session grant on a path does NOT authorize delete on it. `PermissionManager.approve()` forces delete tickets to `SINGLE` regardless of the level requested via `fs_approve` — no session/permanent grants are possible for delete, by design (no exceptions). `fs_delete` only supports individual files, never directories/recursion.
8. **Wrapper validates, `_impl` never re-checks permissions**: every `register_filesystem_tools()` closure calls `security.validate_tool_path(path, <real_operation>)` before invoking its `_impl`. The `_impl` functions call `security.resolve_and_validate(path)` **without** passing `operation` — the default (`"read"`) skips `check_granted()` entirely, so path resolution doesn't re-consume a grant already spent by the wrapper. `fs_delete_impl` broke this convention until 2026-07-04 (see CHANGELOG 1.4.6): it passed `"delete"` explicitly, causing a second `check_granted()` call that consumed the same `SINGLE` grant twice in one request, uncaught, surfacing as a raw exception instead of a `permission_required` response. Any new `_impl` must NOT pass the real operation to its own `resolve_and_validate()` call — that's the wrapper's job, exactly once.

## Key modules
- `src/log.py` — `configure()`, `get_logger()`, `timed()` context manager; `RotatingFileHandler` via stdlib `logging`
- `src/shell_resolver.py` — `ShellInfo` dataclass, `SHELL_REGISTRY` (4 shells), `resolve_shell()`, `_find_executable()`, `_find_git_bash()`
- `src/config.py:LogConfig` — `level`, `max_bytes`, `backup_count` for structured logging
- `src/config.py:ShellConfig` — `default_shell` (string), `shell_map` (dict for custom paths)
- `src/layers/layer2_shell.py` — `MAX_CAPTURE_BYTES=1MiB`, `_truncate()`, `_kill_process_tree()` (taskkill /T /F), `_scan_command_warnings()`

## PermissionManager quirks
- `GrantLevel`: `SINGLE`, `SESSION`, `PERMANENT`
- `_session_grants` changed from `Set[str]` to `Dict[str, Set[str]]` — stores (path, operation) pairs
- `_single_grants: Dict[str, Dict[str, int]]` — single-use grants, consumed on first access. Wildcard `"*"` matches any operation.
- `check_granted(resource, operation)` verifies operation matches (or "*"); auto-grants `data_dir` paths only (not `paths_allow` — reads are handled by `resolve_and_validate()` directly)
- Permanent grants add to `paths_allow`, which auto-allows reads; writes still need session/single grant
- Tickets expire after 300s
- `grant_direct()` creates approved ticket but `fs_request_allow_impl` no longer uses it — goes through pending→approve flow
- `config.save()` writes to config_path — tests set `config_path` to temp path

## Testing
- `asyncio_mode = "auto"` — `async def` tests auto-run (no marker needed)
- Tests import `_impl` directly (not through FastMCP) — this is the intended pattern
- `conftest.py` provides: `temp_home` (tmp_path), `test_config`, `security`, `sample_file`, `sample_dir`
- `tests/test_shell_resolver.py` — 8 tests for shell resolution, executable finding
- Always create fresh `SecurityValidator` per test — `_resolved_allowed` caches stale
- `ResourceWarning` about `_ProactorBasePipeTransport.__del__` is harmless Windows asyncio cleanup

## Gotchas
- **`config.json` en la raíz del repo es un espejo, no el config real** — editarlo no tiene efecto. El real está en `~/.personal-mcp/config.json`. Ver nota al inicio de este archivo y `CONFIG-GUIA.md`.
- `Path.resolve()` on Windows normalizes casing (e.g. `Temp` → `temp`) — use `self._resolve()` helper in PermissionManager
- FastMCP 3.x constructor only accepts `name`
- **Intercepting every tool call (e.g. for auditing) requires subclassing FastMCP, not `app.call_tool = wrapper`**: `FastMCP._setup_handlers()` (called inside `FastMCP.__init__()`) does `self._mcp_server.call_tool(validate_input=False)(self.call_tool)` — this registers the bound method with the low-level MCP server via a closure at the moment `app = FastMCP(...)` runs, *before* any post-construction attribute reassignment could take effect. Reassigning `app.call_tool` afterwards is silently a no-op for real client invocations (confirmed bug in v1.4.3 and earlier: `mcp_audit_log` stayed empty and `audit.json` was never created despite real tool activity — fixed in v1.4.4). Correct pattern: subclass `FastMCP` and override `call_tool()` as a real instance method (see `AuditedFastMCP` in `server.py`) — Python resolves `self.call_tool` by the instance's class (MRO) at the moment `_setup_handlers()` runs, which is after `self` is already the subclass instance.
- `config.data_dir` overridden at `server.py:32` to `~/.personal-mcp/data`
- `sh_script` writes temp file with extension matching shell (`.ps1`/`.bat`/`.sh`) to `~/.personal-mcp/data/`
- `sh_session_start` returns error if shell doesn't support interactive sessions (cmd, bash have `session_args=[]`)
- **Shell switching**: `sh_exec`, `sh_script`, `sh_session_start` accept optional `shell` param — resolves at runtime via `ShellManager.resolve_shell()`
- Shell output truncated at 1 MiB — message appended if truncated
- Timeout cleanup uses `taskkill /pid /T /F` (recursive, Windows-only)
- SSH layer is opt-in — `ssh.enabled: false` by default
- `import sys; sys.path.insert(0, ...)` required at every entrypoint for `src.` imports
- All `_impl` functions accept `security` as parameter — closures bind it at registration time

## Regla obligatoria antes de eliminar cualquier símbolo
Antes de eliminar una función, clase, método o constante:
1. Busca el nombre exacto del símbolo en src/ Y tests/ (no solo donde ya se sabe que se usa)
2. Pega el resultado de esa búsqueda explícitamente
3. Si aparece en un test, la eliminación requiere actualizar ese test en el mismo cambio,
   no como una tarea separada