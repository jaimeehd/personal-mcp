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
.\.venv\Scripts\python -m pytest tests/ -v       # 283 tests, verified 2026-07-20 (0 failed). CHANGELOG 1.4.23 claimed 331 -- investigated (1.4.29): compared against two independent repo backups, neither has more tests than this tree. 331 was never accurate, not a loss.
.\.venv\Scripts\python -m src.server              # stdio mode for Claude Desktop
.\install.ps1                                     # register with Claude Desktop (auto-creates venv)
.\sync-config.ps1                                 # refresh the read-only config.json mirror from ~/.personal-mcp/config.json
```

## Architecture — 6 hexagonal layers, 56 tools (52 active — SSH's 4 disabled by default)
| Layer | File | Tools | Security boundary |
|-------|------|-------|-------------------|
| 1 Filesystem | `layer1_filesystem.py` | 20 | `resolve_and_validate()` on every path |
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
   - ✅ **Every segment of a chained command is validated independently, including across newlines**: `split_command_segments()` (`shell_resolver.py`) splits on `| ; & < > `` $( and \n` before each segment's first word is checked against `allow_prefix`. Until 2026-07-04 the splitter did not treat `\n` as a boundary, so a command like `"echo hola\nWrite-Host 'INYECTADO'"` validated only against the first segment (`echo`, whitelisted) while the second statement after the newline executed unchecked — PowerShell/cmd/bash all treat a literal `\n` inside a `-Command`/`-c` argument as a statement separator. Fixed in v1.4.9 (`INJ-01`, CRITICAL). Any future change to command parsing must keep `\n` in `_SHELL_OPERATORS_RE` and in `split_command_segments()`'s boundary set — removing it silently reopens this exact bypass.
3. **No tickets on hot path**: `validate_tool_path()` returns `None` for allowed read operations, a `permission_required` JSON payload for blocked write operations, or an error string for strictly denied paths (outside `paths_allow`/`data_dir`).
4. `working_dir` prefix resolved from `shell_info.workdir_prefix` (per-shell: `Set-Location`, `cd /d`, `cd`). **Quoting inside that prefix must be escaped per-shell, not with one hardcoded style**: `_escape_workdir(working_dir, shell_name)` (`layer2_shell.py`) picks the correct quote-escape for the resolved shell (`` `" `` for powershell/pwsh, `""` for cmd, `\"` for bash). Until 2026-07-04 the PowerShell escape was applied unconditionally regardless of target shell — a `working_dir` containing a literal `"` could break out of the quoted segment on `cmd`/`bash` and inject further shell syntax. Fixed in v1.4.9 (`INJ-02`, HIGH).
5. Shell commands scanned for absolute paths (`C:\...`, `C:/...`) via `security.extract_absolute_paths()`
6. `check_granted()` now uses `Dict[str, Set[str]]` — grants are per-operation, "read" != "write"
7. **`fs_delete`** uses `operation="delete"`, fully isolated from `"read"`/`"write"` — an existing write session grant on a path does NOT authorize delete on it. `PermissionManager.approve()` forces delete tickets to `SINGLE` regardless of the level requested via `fs_approve` — no session/permanent grants are possible for delete, by design (no exceptions). `fs_delete` only supports individual files, never directories/recursion.
8. **Wrapper validates, `_impl` never re-checks permissions**: every `register_filesystem_tools()` closure calls `security.validate_tool_path(path, <real_operation>)` before invoking its `_impl`. The `_impl` functions call `security.resolve_and_validate(path)` **without** passing `operation` — the default (`"read"`) skips `check_granted()` entirely, so path resolution doesn't re-consume a grant already spent by the wrapper. `fs_delete_impl` broke this convention until 2026-07-04 (see CHANGELOG 1.4.6): it passed `"delete"` explicitly, causing a second `check_granted()` call that consumed the same `SINGLE` grant twice in one request, uncaught, surfacing as a raw exception instead of a `permission_required` response. Any new `_impl` must NOT pass the real operation to its own `resolve_and_validate()` call — that's the wrapper's job, exactly once.
9. **`fs_approve` gate de confirmación (HMAC) — implementado en v1.4.14**: `fs_approve` ahora exige un `confirm_code` obligatorio, verificado con `hmac.compare_digest()` contra un código generado por `PermissionManager` en el momento del `request()`. La clave secreta (`_confirm_secret`, 32 bytes vía `secrets.token_bytes()`) se genera en memoria al construir cada `PermissionManager` y nunca se persiste a disco ni se expone por ningún tool — es lo único que impide que un agente adivine o derive el código. El código (`_generate_confirm_code()`, 6 dígitos derivados de un HMAC-SHA256 del `ticket_id`) se muestra **solo** vía `src/confirm_popup.py::show_confirmation_code()` — un `MessageBoxW` nativo de Windows, lanzado en un hilo daemon separado para no bloquear el event loop de asyncio del servidor mientras el usuario no está frente a la pantalla. Este es el único canal donde el código es visible; no se devuelve nunca en la respuesta de ningún tool MCP (`fs_request_allow`, `security_pending`, etc.) — si en el futuro alguien lo expone ahí "para depurar", se reabre exactamente el gap que este mecanismo cierra. `show_confirmation_code()` se desactiva bajo pytest (`PYTEST_CURRENT_TEST` en el entorno) para no bloquear la suite con popups reales.
    - Reemplaza el diseño anterior documentado aquí (Token HMAC "pendiente de implementar", ver CHANGELOG 1.4.10/1.4.13). La alternativa `elicitation` evaluada en 1.4.13 sigue descartada (el cliente MCP conectado no declara esa capability) — revisar esa decisión solo si el cliente usado cambia.
    - ⚠️ **Regresión corregida en v1.4.28**: el mensaje que devuelve `request_permission()` para tickets de un solo recurso (`fs_write`/`fs_edit`/`fs_delete`/`fs_move`/`fs_create_directory`, y los tickets `execute`) nunca mencionaba `confirm_code` — decía solo `fs_approve(ticket_id=..., level='single')`, sin el parámetro obligatorio. La variante batch (`validate_tool_paths_batch`) y `fs_request_allow` sí lo tenían bien desde el principio; solo este path quedó desactualizado desde que se implementó el gate en v1.4.14. No era un hueco de seguridad (`PermissionManager.approve()` ya exigía el código igual), pero le decía al agente que llamara mal a la tool. Corregido — los tres mensajes (single/batch/request_allow) son ahora consistentes.
10. **No auto-aprobar tickets — ahora con control técnico real, no solo convención**: antes de v1.4.14 esto era solo una regla de comportamiento sin valor de seguridad (el agente podía ignorarla). Desde v1.4.14, `PermissionManager.approve()` rechaza cualquier intento sin `confirm_code` válido (`ok=False, "Invalid or missing confirmation code."`), y el código solo es visible en el popup nativo — un agente no tiene ningún canal para leerlo. La regla de convención se mantiene como buena práctica adicional, pero el gate real es la regla #9.
11. **Intérpretes de propósito general requieren ticket de `execute` antes de correr, además de estar en `allow_prefix`** (`config.security.commands.approval_required_prefix`, default `["python", "node", "bash"]`; `security.validate_shell_execution()`, v1.4.12). Esto NO contiene lo que el intérprete hace una vez aprobado — sigue siendo una caja negra frente a `paths_allow`/`deny` una vez que corre. Solo agrega una pausa antes de dejarlo arrancar, reutilizando el mismo flujo de tickets que `fs_approve` (`operation="execute"`, ya excluido del comodín `"*"`, igual que `"delete"`). Sujeto a la misma limitación de las reglas #9/#10: el agente puede aprobarse su propio ticket de `execute` igual que cualquier otro.
    - ⚠️ **Conectado solo en `sh_exec`/`sh_session_send`, NO en `sh_script`**: hoy es inofensivo porque `readonly_prefix` (regla #2) no incluye invocar un intérprete con un archivo (`python script.py`), así que `sh_script` no puede alcanzar un intérprete de propósito general de todas formas. Si en el futuro se agrega algo como `"python"` a `readonly_prefix`, `sh_script` lo ejecutaría sin pasar nunca por este control — quedaría silenciosamente sin cubrir. Cualquiera que toque `readonly_prefix` debe revisar esto primero.
    - Sin cobertura de tests: no existe ningún test para `validate_shell_execution()`, la exclusión de `"execute"` del comodín, ni el caso de `sh_script` de arriba (verificado con búsqueda, no asumido).

12. **Conector MCP Filesystem genérico (oficial) — canal paralelo sin tickets (riesgo conocido, aceptado)**: si el cliente MCP tiene también el conector oficial `Filesystem` habilitado con `C:\Repos\.personal-mcp` en sus directorios permitidos, ese conector escribe directo al disco — no pasa por `PermissionManager`, no genera tickets, no requiere `confirm_code`. El gate de la regla #9 solo protege las tools expuestas por *este* servidor (`fs_write`, `fs_edit`, etc. vía `layer1_filesystem.py`); no protege el repositorio en sí frente a cualquier otro conector con acceso de escritura al mismo path. No hay fix de código posible desde este repo — es una decisión de configuración del cliente MCP, fuera de su alcance. Usado deliberadamente en la práctica (v1.4.26, y en la sesión del 2026-07-19) cuando el propio dueño del repo lo pide explícitamente para evitar tickets repetidos en ediciones de documentación de bajo riesgo — sigue siendo el mismo bypass, la diferencia es que aquí es una decisión informada del dueño, no un descuido.

13. **`install.ps1` default `allow_prefix` endurecido (v1.4.18)**: el instalador tenía verbos de mutación de archivos (`remove-item`, `del`, `copy`, `move`, `mkdir`, `new-item`, etc.) en el `allow_prefix` por defecto de una instalación nueva — bypaseaban el sistema de tickets por completo en cualquier instalación fresca. Los 10 verbos fueron eliminados de la lista por defecto. El `~/.personal-mcp/config.json` real en uso tenía el mismo gap (`mkdir`/`rmdir`) activo ese mismo día — corregido directamente por el dueño del repo (fuera del alcance de este repo), confirmado vía el espejo de solo lectura.

14. **`paths_allow` ampliado deliberadamente a `["C:\\"]` (v1.4.26, decisión del dueño del repo)**: antes era `["C:\\Repos"]`. Las operaciones de escritura/borrado NO se ven afectadas — siguen requiriendo grant explícito vía el flujo de tickets+HMAC sin importar el alcance de `paths_allow`; solo las lecturas sin ticket (`fs_read`, `fs_list`, `fs_search`, `fs_tree`, `fs_find`, `fs_info`) quedan sin restricción en todo el disco `C:` salvo por `paths_deny`. Con `paths_allow` así de amplio, `paths_deny` es el único control real que queda para lecturas — ver `config.json` (espejo) para la lista completa (`.ssh`, `.aws`, `.azure`, `.kube`, `.gnupg`, `.env*`, `*.pem`, `id_rsa*`, `id_ed25519*`, `AppData` con wildcard, credenciales de git/npm/pip, etc., ampliada en v1.4.26/v1.4.27). Explícitamente incompleta por diseño, no un gap: es una lista de patrones conocidos, no un mecanismo general — `scan_text()` (el scanner de secretos, activo desde v1.4.9) es el respaldo para contenido en ubicaciones que `paths_deny` no anticipó. **Antes de agregar cualquier `paths_allow` nuevo o ampliar el existente, revisa primero si `paths_deny` cubre lo que se está exponiendo** — el error de v1.4.26 (AppData sin wildcard, exact-match en vez de recursivo) pasó inadvertido durante semanas precisamente porque nadie lo verificó al momento de ampliar `paths_allow`.

## Key modules
- `src/log.py` — `configure()`, `get_logger()`, `timed()` context manager; `RotatingFileHandler` via stdlib `logging`. `logging.raiseExceptions = False` set in `configure()` since v1.4.28 (hypothesis fix, see CHANGELOG 1.4.21 — not conclusively proven, low-risk regardless).
- `src/shell_resolver.py` — `ShellInfo` dataclass, `SHELL_REGISTRY` (4 shells), `resolve_shell()`, `_find_executable()`, `_find_git_bash()`. `_find_git_bash()` runs a **synchronous** `subprocess.run(timeout=5)` — any caller must wrap `resolve_shell()` in `asyncio.to_thread()` when calling from an `async def` (regression fixed v1.4.28 in `sh_exec`/`sh_script`/`sh_session_start`; if a new call site is added, check this first).
- `src/config.py:LogConfig` — `level`, `max_bytes`, `backup_count` for structured logging
- `src/config.py:ShellConfig` — `default_shell` (string), `shell_map` (dict for custom paths)
- `src/layers/layer2_shell.py` — `MAX_CAPTURE_BYTES=1MiB`, `_truncate()`, `_kill_process_tree()` (taskkill /T /F, `stdin=DEVNULL` since v1.4.19), `_reap_after_kill()` (since v1.4.20 — must be called after every `_kill_process_tree()`, or subprocess handles leak on Windows until the whole server hangs; see CHANGELOG 1.4.19/1.4.20), `_scan_command_warnings()`

## PermissionManager quirks
- `GrantLevel`: `SINGLE`, `SESSION`, `PERMANENT`
- `_session_grants` changed from `Set[str]` to `Dict[str, Set[str]]` — stores (path, operation) pairs
- `_single_grants: Dict[str, Dict[str, int]]` — single-use grants, consumed on first access. Wildcard `"*"` matches any operation.
- `check_granted(resource, operation)` verifies operation matches (or "*"); auto-grants `data_dir` paths only (not `paths_allow` — reads are handled by `resolve_and_validate()` directly)
- Permanent grants add to `paths_allow`, which auto-allows reads; writes still need session/single grant
- Tickets expire after 300s
- `grant_direct()` creates approved ticket but `fs_request_allow_impl` no longer uses it — goes through pending→approve flow
- `config.save()` writes to config_path — tests set `config_path` to temp path
- **Batch tickets (since v1.4.16)**: `PermissionTicket` has an optional `resources: List[str]` field; `request_batch()`/`approve()` bind one ticket/one `confirm_code` to an enumerated list of paths (`fs_delete_batch`). Still forced to `SINGLE` for delete, same rule as single-file delete (#7). `validate_tool_paths_batch()` peeks every path before consuming any grant.

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
- **v1.4.9 external audit (2026-07-04) — 3 more findings beyond the two already folded into rules #2 and #4 above:**
  - **`ssh_exec` validates commands only on the local `personal-mcp` host, not on the remote host the SSH session connects to** (`INJ-03`, MEDIUM). A command passing the local `allow_prefix` check is forwarded verbatim and runs with whatever privileges the remote account has — no equivalent enforcement exists remotely. Not fixable with a local code change (would require deploying a validating wrapper on every remote host); `ssh_exec_impl` now prefixes results with an explicit `[WARNING]` instead. Currently unreachable in practice: SSH is `enabled: false` by default and in this deployment.
  - **Secret scanning didn't cover `journal_add`/`note_quick`** (`INJ-04`, MEDIUM). `scan_text()` was wired into `fs_read_impl` and the shell paths but not Layer 4 — a credential pasted into a journal entry or quick note was written to disk with zero warning. Fixed via `_scan_and_append()` in `layer4_personal.py` (deliberately not shared with `layer2_shell.py`'s equivalent helper — flagged as minor DRY debt, not worth a cross-layer import for ~6 lines yet).
  - **Log injection via newline-containing arguments** (`INJ-05`, LOW). `layer2_shell.py`'s `logger.info("sh_exec command=%.200s ...", command, ...)` interpolated the raw command via `%s` with no escaping — a command containing `\n` could forge a fake log line. Fixed via `sanitize_log_value()` (`log.py`), applied at both `sh_exec`/`sh_script` logging call sites.
  - Full detail and PoC-level reasoning for all 5 findings (including the two already merged above): `CHANGELOG.md` entry `[1.4.9]`.

## Regla obligatoria antes de eliminar cualquier símbolo
Antes de eliminar una función, clase, método o constante:
1. Busca el nombre exacto del símbolo en src/ Y tests/ (no solo donde ya se sabe que se usa)
2. Pega el resultado de esa búsqueda explícitamente
3. Si aparece en un test, la eliminación requiere actualizar ese test en el mismo cambio,
   no como una tarea separada