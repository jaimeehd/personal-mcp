## [1.4.41] — 2026-07-31

### Fixed — tickets de `fs_delete_batch` perdidos silenciosamente tras reinicio del servidor
- **Incidente**: un lote de 40 archivos (`fs_delete_batch`, 09:09:41) creó su ticket en el proceso pid=10792. El servidor se reinició 4 veces (09:12:08, 10:09:37, 16:05:39, 16:06:28) y el ticket murió con el proceso. Tras el último reinicio el agente intentó `fs_deny(perm_b404cd7f)` (16:06:49) y `fs_approve(perm_7ec4b13a)` (16:07:18) — tickets que **jamás existieron en ningún proceso** según server.log. Ambos se registraron como `OK 0ms`/`OK 1ms`: el fallo fue 100% silencioso.
- **Causa raíz (observabilidad)**: `AuditedFastMCP.call_tool` registraba éxito para cualquier retorno que no lanzara excepción. `fs_approve`/`fs_deny` reportan fallas ("Ticket not found", "Invalid or missing confirmation code", etc.) como strings planos — invisibles para el log y el audit log.
- **Causa raíz (vida del ticket)**: los tickets vivían solo en memoria del proceso. Cualquier reinicio los destruía, y nada en el servidor los re-creaba ni advertía al agente.
- **Fix 1 — Logging del ciclo de vida de tickets**: `PermissionManager` ahora loguea `PENDING` (request/request_batch, incluyendo "(reused)" en dedup), `GRANTED`, `APPROVE_FAIL` (con razón: not_found/expired/status/invalid_code), `DENIED`, `DENY_FAIL`, `GRANT_DIRECT`, `EXPIRED`, `REVOKED` y `RESTORED`.
- **Fix 2 — Detección de fallo semántico**: `AuditedFastMCP._is_semantic_failure()` inspecciona el retorno de `fs_approve`/`fs_deny` (extrayendo el texto plano del contenedor que devuelve FastMCP 3.4.x, `(content_blocks, structured_dict)`) y, si coincide con prefijos de falla conocidos, loguea `WARNING FAILED <tool> <ms> <mensaje>` y registra el audit con `success=False` en vez de `OK`/`success=True`. Otras tools no se inspeccionan ("Error: path does not exist" es un resultado normal de `fs_info`).
- **Fix 3 — Dedup en `request_batch`**: reutiliza un ticket pending con la misma operación y el mismo conjunto de rutas (orden-insensible), igual que ya hacía `request()`. Post-reinicio, re-emitir el mismo `fs_delete_batch` reutiliza el ticket restaurado en vez de crear duplicados.
- **Fix 4 — Persistencia de tickets pending**: los tickets `pending` se persisten como metadatos en `tickets.jsonl` (dentro de `data_dir`). Al reiniciar, `_load_pending_tickets()` restaura los no expirados con `restored=True` y su `confirm_code` **regenerado con el secreto fresco del proceso** — nunca se lee del disco. El `confirm_code` y el secreto HMAC nunca se persisten ni se exponen por ninguna tool (el gate de v1.4.14 se mantiene intacto). Al aprobar un ticket restaurado con un código viejo pre-reinicio, se re-muestra el popup (`MessageBoxW`) con el código nuevo. Estado del ticket persistido en cada transición (approved/denied/expired/revoked) para que la restauración solo recree tickets realmente pendientes.
- **HITL preservado**: un ticket restaurado exige igualmente el `confirm_code` regenerado mostrado por el popup; el agente no puede aprobarlo solo.
- **Tests de regresión**: `tests/test_ticket_persistence.py` (17 tests) cubriendo logging del ciclo de vida, dedup de `request_batch`, persistencia/restauración tras reinicio, regeneración de código, no-persistencia de secretos, `fs_delete_batch` forzado a SINGLE, y detección de fallo semántico en el wrapper.
- Verificado: `ruff check src/ tests/` limpio, 303/303 tests (286 previos + 17 nuevos).

### Security — sin cambio de superficie
- La persistencia es de solo-metadatos; el `confirm_code` y `_confirm_secret` siguen siendo exclusivamente en memoria. `paths_allow=["C:\"]` permite lectura libre del disco, por lo que persistir códigos o el secreto reabriría el gap que v1.4.14 cerró deliberadamente.

## [1.4.47] — 2026-08-05

### Added — `fs_delete_directory`, borrado recursivo de carpetas con preview tipo Windows
- **Gap real encontrado en esta sesión, no hipotético:** `fs_delete` y `fs_delete_batch` rechazan explícitamente carpetas ("only supports individual files, not directories") — hasta esta versión, **no existía ninguna forma de borrar un árbol de carpetas completo** en `personal-mcp`. Un agente en otra sesión chocó exactamente con esto intentando borrar un `node_modules` dos veces seguidas, ambas rechazadas. No fue un crash ni datos corrompidos — el rechazo funcionó tal como estaba escrito — pero tampoco había alternativa.
- Nueva tool dedicada `fs_delete_directory(path)`, separada de `fs_delete`/`fs_delete_batch` en vez de agregarles un flag `recursive` — mismo criterio que ya se usó para separar `fs_delete_batch` de `fs_delete`: un nombre de tool explícito deja el alcance de la operación sin ambigüedad en el punto de llamada.
- **Preview antes de confirmar, igual que el diálogo de Windows al borrar una carpeta:** antes de mostrar el ticket, la tool cuenta archivos y tamaño total recursivamente (solo lectura, sin ticket) y lo muestra junto con la solicitud de confirmación — "Contains N file(s), X bytes (Y MB)". El conteo reutiliza el mismo patrón de recorrido ya validado por `fs_disk_usage`/`project_git_status` (131k entradas en ~30s sobre un árbol real).
- 4 tests nuevos en `test_filesystem.py`: borrado básico con subcarpetas, carpeta vacía, error si no es directorio, y verificación de que el conteo/tamaño reportado es exacto.
- Verificado: ruff limpio, 344/344 tests.

## [1.4.46] — 2026-08-02

### Added — `fs_compress`/`fs_extract`, con protección explícita contra zip slip
- **Cuarto y último ítem de `PLAN-NUEVAS-TOOLS.md` — plan completo.** Dos tools nuevas en Layer 1: `fs_compress(paths, output_path)` crea un zip a partir de archivos/carpetas; `fs_extract(zip_path, output_dir)` lo descomprime.
- **Riesgo de diseño identificado desde el inicio del plan (zip slip, CVE-2007-4559-style) resuelto con verificación explícita, no confiando en la protección de la librería estándar:** antes de escribir cada miembro del zip, `_safe_extract_sync()` calcula la ruta de destino resuelta y verifica con `Path.relative_to()` que caiga dentro de `output_dir` — si no, se **omite** ese miembro (no se renombra, no se trunca, se salta por completo) y se reporta en la respuesta. Un zip malicioso con un miembro `"../../escaped.txt"` no puede escribir fuera de `output_dir` bajo ninguna circunstancia.
- `fs_extract` va por Layer 1 estándar: ticket de escritura sobre `output_dir` (uno solo, cubre todos los archivos que se extraigan adentro — mismo criterio que ya usan los grants de sesión recursivos).
- 8 tests nuevos en `test_filesystem.py`, incluyendo el test de seguridad central: un zip con un miembro `../../escaped.txt` construido a propósito, verificando que el archivo objetivo de la fuga nunca se crea y que los miembros legítimos del mismo zip sí se extraen con normalidad.
- Verificado: ruff limpio, 340/340 tests.

### Plan de herramientas nuevas — cerrado
`PLAN-NUEVAS-TOOLS.md` (iniciado 2026-08-01) queda con sus 4 ítems completados: `project_git_status` (1.4.43), `fs_disk_usage` (1.4.44), `sh_spawn`+3 (1.4.45), `fs_compress`/`fs_extract` (esta entrada). 65 tools totales (61 activas), desde las 57 (53 activas) con las que arrancó el plan.

## [1.4.45] — 2026-08-02

### Added — `sh_spawn`/`sh_spawn_read`/`sh_spawn_kill`/`sh_spawn_list`, procesos de larga duración en background
- Tercer y último ítem crítico completado de `PLAN-NUEVAS-TOOLS.md` — la feature quedó bloqueada en el diseño original (`AGENTS.md`, "Feature diferida") por un problema de procesos huérfanos entre reinicios, descubierto en profundidad esta sesión: en esta máquina es **normal, no excepcional**, tener varios procesos `personal-mcp` corriendo en simultáneo (confirmado en vivo el 2026-08-02: 3 procesos para 3 ventanas/cuentas distintas de Claude Desktop).
- **Diseño que desbloqueó la feature — rastreo por `owner_pid`, no solo por el PID del proceso hijo:** cada spawn se persiste a `spawned_processes.jsonl` en `data_dir` (mismo patrón append-then-reconcile-on-boot que `tickets.jsonl`, v1.4.41) con el PID del servidor que lo creó. Al arrancar, un servidor nuevo solo actúa sobre un registro cuyo `owner_pid` está **confirmado muerto** — si el dueño original sigue vivo, el registro no se toca, sin importar que este proceso nuevo pueda ver el mismo archivo. Esto evita el error de solo revisar "¿el proceso hijo sigue vivo?", que no tiene forma de distinguir "todavía en manos de un servidor hermano que sigue corriendo" de "genuinamente huérfano".
- Los huérfanos detectados se **reportan** (`sh_spawn_list` los marca `"orphaned"`), nunca se matan automáticamente — un dev server huérfano puede seguir siendo exactamente lo que el usuario quiere que siga corriendo.
- **Requisito de seguridad #3 del diseño original ("excluido del wildcard `*` en grants") resuelto sin tocar `security.py`/`permissions.py`:** `sh_spawn` exige su propio ticket de `execute`, reutilizando el mismo mecanismo ya usado para `python`/`node`/`bash`. `PermissionManager.check_granted()` ya excluía `operation="execute"` de cualquier grant wildcard `"*"` — el requisito se cumple gratis, sin código nuevo.
- **Requisito #2 (ring buffer):** output acotado con `collections.deque(maxlen=500)` por proceso — un proceso ruidoso no puede crecer en memoria sin límite solo por leerse con poca frecuencia.
- 15 tests nuevos en `test_shell.py`: spawn/read/kill/list básicos, ticket de `execute` requerido, grant wildcard insuficiente (prueba directa de la exclusión ya existente en `check_granted`), y los 3 tests centrales de reconciliación de huérfanos (huérfano real detectado, registro con dueño vivo ignorado intacto, registro totalmente muerto descartado).
- Verificado: ruff limpio, 332/332 tests.

## [1.4.44] — 2026-08-01

### Added — `fs_disk_usage`, auditoría de espacio en disco por carpeta
- Nueva tool de solo lectura en Layer 1: dado un `path`, agrupa el tamaño de todos los archivos por carpeta ancestro a `depth` niveles (default 1) y devuelve las `top_n` (default 15) que más pesan. Complementa a `fs_find_duplicates` (2026-07-31) — esa responde "¿qué está repetido?", esta responde "¿qué carpeta específica se está comiendo el disco?", la otra mitad de la misma pregunta de auditoría de espacio.
- **Un solo recorrido del árbol** (`os.walk()`), sin importar cuántas carpetas resulten — evita recorrer subárboles compartidos una vez por cada carpeta hermana, que sería el costo de un enfoque ingenuo de "sumar el tamaño de cada subcarpeta por separado".
- Sin límite artificial de cantidad de carpetas ni de archivos escaneados — mismo principio que `fs_find_duplicates`/`project_git_status`: el costo real es cuánto árbol hay que recorrer, no algo que un límite de conteo acotaría de todas formas. Solo la salida (`top_n`) se trunca, no el cómputo.
- Segundo ítem completado de `PLAN-NUEVAS-TOOLS.md`.
- 5 tests nuevos en `test_filesystem.py`: agrupación y orden descendente, comportamiento del parámetro `depth`, truncamiento de `top_n`, carpeta vacía, y error si no es un directorio.
- Verificado: ruff limpio, 321/321 tests.

## [1.4.43] — 2026-08-01

### Added — `project_git_status`, estado de git multi-repo con descubrimiento automático
- Nueva tool de solo lectura en Layer 4 (Personal): recorre todas las raíces de `paths_allow` buscando carpetas `.git` y reporta, para cada repo encontrado, cambios sin commitear, commits sin pushear y commits del remoto sin traer.
- **Decisión de diseño explícita (2026-08-01):** descubrimiento automático (recorrido de `paths_allow`) en vez de una lista fija de repos en config. Trade-off aceptado: más lento si `paths_allow` es amplio (como `["C:\\"]` en la config real de este equipo), a cambio de no requerir mantenimiento manual. Documentado en `PLAN-NUEVAS-TOOLS.md`.
- Recorrido con `os.walk()` y poda de directorios en el propio recorrido (no `Path.rglob`, que no permite saltar subárboles una vez que decide entrar) — mismo conjunto de exclusión ya usado por `project_find` (`node_modules`, `.venv`, `AppData`, etc.), extendido con algunas carpetas más de sistema.
- Sin límite artificial de cantidad de repos — mismo principio que `fs_find_duplicates` (2026-07-31).
- `_git_project_info()` (ya existente, usada por `project_scan`) extendida para agregar `ahead`/`behind` contra el upstream, reutilizando la misma función en vez de duplicar lógica de subprocess.
- 5 tests nuevos en `test_personal.py`, incluyendo un repo con remoto real (bare repo local) para ejercitar el camino real de `git rev-list --left-right --count`, y un caso de regresión para la exclusión de `node_modules`.
- Primer ítem completado de `PLAN-NUEVAS-TOOLS.md` (documento de seguimiento nuevo, agregado en este mismo commit) — quedan pendientes `fs_disk_usage`, `sh_spawn` (bloqueada, ver el plan) y `fs_compress`/`fs_extract`.
- Verificado: ruff limpio, 316/316 tests.

## [1.4.42] — 2026-07-31

### Added — `fs_find_duplicates`, búsqueda de duplicados exactos por hash
- Nueva tool de solo lectura en Layer 1: dado un `path`, encuentra archivos con contenido byte-idéntico aunque el nombre difiera — a diferencia de una búsqueda por patrón de nombre (`archivo (1).ext`), que solo atrapa duplicados generados por descargas repetidas con el mismo nombre base.
- **Diseño de dos fases, sin límites de cantidad ni tamaño de archivo** (decisión explícita, 2026-07-31): fase 1 agrupa por tamaño exacto en bytes (case gratis, solo `stat()` — medido en 240ms para 232 archivos reales); fase 2 solo calcula SHA256 dentro de los grupos que ya comparten tamaño exacto con al menos otro archivo. Un archivo de tamaño único, por grande que sea, nunca se hashea. Se descartó un límite de `max_file_size_mb` y uno de `max_files` en el diseño porque ambos habrían excluido casos de uso reales (una carpeta Downloads real de este mismo equipo tiene 2,917 archivos en su raíz) sin ahorrar tiempo significativo, dado que el recorrido y el filtro por tamaño ya son baratos.
- Parámetro `extensions` acepta tanto `".pdf"` como `"pdf"` (normalización case-insensitive) — evita que el formato exacto del argumento sea una fuente de error silencioso.
- Parámetro `recursive` (default `False`) para incluir subcarpetas.
- No borra nada — deliberadamente separado de `fs_delete_batch`, que ya tiene su propio flujo de tickets. Mezclar "encontrar" y "borrar" en una sola tool habría complicado el modelo de permisos sin necesidad real.
- 8 tests nuevos en `test_filesystem.py`, incluyendo un caso de regresión específico para el pre-filtro de tamaño (dos archivos del mismo tamaño exacto pero contenido distinto no deben reportarse como duplicados).
- Verificado: ruff limpio, 311/311 tests.

## [1.4.40] — 2026-07-30

### Added — `gh` (GitHub CLI) agregado a `allow_prefix`/`readonly_prefix`
- La whitelist de comandos (`config.security.commands.allow_prefix`) no incluía `gh` — no por una decisión de seguridad activa, sino porque nunca se agregó al definir el conjunto original de comandos. Ausencia por omisión, no restricción deliberada.
- Agregado `gh` a `allow_prefix` (config oficial `~/.personal-mcp/config.json`, espejo del repo, y `config.demo.json`).
- Agregado `gh run list`, `gh pr view`, `gh repo view` a `readonly_prefix` (config oficial y espejo) para que también sean invocables desde `sh_script` sin ticket de escritura.
- Motivado por: no había forma de consultar el estado de GitHub Actions CI para verificar un push sin depender de capturas de pantalla del usuario.
- **Error de proceso durante esta sesión (documentado, no un bug de código)**: la edición inicial se aplicó por error al espejo de solo lectura del repo (`C:\Repos\.personal-mcp\config.json`) en vez de al config oficial (`~/.personal-mcp/config.json`) — el mismo error de proceso ya documentado en la entrada `1.4.30`. `AGENTS.md` ya tenía la advertencia en las primeras líneas del archivo; no se leyó antes de actuar. Corregido aplicando el cambio directamente al config oficial y verificando que el espejo quedara consistente.
- ⚠️ El servidor MCP en ejecución no recarga `config.json` en caliente — requiere reinicio para que `gh` esté disponible en `sh_exec`.

## [1.4.39] — 2026-07-30

### Fixed — recursión infinita en `health_processes` por shadowing de nombre
- La tool `@mcp.tool` `health_processes` (dentro de `register_health_tools()`) y la función standalone de nivel de módulo compartían el mismo nombre exacto (`health_processes`). Por las reglas de scope de Python (LEGB), la llamada dentro del closure de la tool se resolvía hacia sí misma en vez de hacia la implementación real de nivel de módulo — cada invocación lanzaba `RecursionError: maximum recursion depth exceeded`.
- **Por qué pasó inadvertido con 285 tests pasando**: `test_register_health_tools_produces_sync_tools` solo verificaba que el nombre `"health_processes"` estuviera en la lista de tools registradas — nunca invocaba la tool.
- **Fix**: función standalone renombrada a `_dispatch_processes` (consistente con la convención de prefijo `_` ya usada por `_fetch_processes_windows`/`_linux`/`_macos`, que la función original rompía). La tool ahora llama a `_dispatch_processes(top)`.
- **Test de regresión agregado**: `test_health_processes_tool_executes_without_recursion` invoca la tool real vía `app._tool_manager.call_tool("health_processes", {"top": 3})`, cerrando el hueco de cobertura que dejó pasar el bug original.
- Verificado: ruff limpio, 286/286 tests (285 + el nuevo), y confirmado en runtime real tras reiniciar el servidor MCP.

## [1.4.38] — 2026-07-29

### Fixed — lint SIM102 en `PermissionManager.revoke()`
- `ruff` (regla SIM102, "Use a single `if` statement instead of nested `if` statements") fallaba en CI sobre `src/permissions.py:262` — un `if` anidado dentro de otro, combinable con `and`.
- Combinados en una sola condición: `if (ticket.resource == resource and ticket.status == "approved" and (not operation or ticket.operation == operation))`. Sin cambio de comportamiento — mismo resultado lógico, solo estructura simplificada.
- Verificado en la sesión que llevó este cambio a `origin/main`: `ruff check src/ tests/` limpio, 285/285 tests.

## [1.4.37] — 2026-07-27

### Security — `install.ps1` defaults endurecidos (paths_allow/deny + allow_prefix)
- **`paths_allow`**: reemplazados los defaults previos por rutas convencionales de un install fresco: `%USERPROFILE%\source\repos` (default de Visual Studio, creada si no existe), `%USERPROFILE%\Documents\GitHub` (default de GitHub Desktop), `%USERPROFILE%\repos` (convención común).
- **`paths_deny`**: el instalador ahora incluye desde el default los mismos patrones de credenciales ya aplicados manualmente en la config real en uso (`**\AppData\**`, `**\.ssh\**`, `**\.aws\**`, `**\.azure\**`, `**\.kube\**`, `**\.gnupg\**`, `**\.env*`, `**\*.pem`, `**\id_rsa*`, `**\id_ed25519*`, `**\.git-credentials`, `**\.npmrc`, `**\.pypirc`, `**\.docker\config.json`). Antes solo estaban en el config real de esta instancia (ver 1.4.27); un install nuevo no los recibía.
- **`allow_prefix`**: eliminados los 10 verbos de mutación de archivos ya señalados como gap en la regla #13 de `AGENTS.md` desde v1.4.18 (`mkdir`, `ni`, `new-item`, `copy`, `cp`, `move`, `mv`, `remove-item`, `ri`, `del`) — un install fresco ahora también requiere ticket para estas operaciones, cerrando la brecha que hasta ahora solo se corregía manualmente config por config.
- `config.demo.json` sincronizado con los nuevos defaults.
- Sin cambios en `src/` — este release es exclusivamente del instalador y su plantilla de config de referencia.

## [1.4.36] — 2026-07-27

### Docs — sección "Para qué NO está listo" en README.md
- Nueva tabla con 11 limitaciones conocidas del proyecto, documentadas para que un lector humano (no solo AGENTS.md, dirigido a agentes) las vea sin tener que inferirlas: multi-usuario/multi-tenant, deployment remoto/contenedores/Kubernetes, SSH en producción, compliance estricto (SOC2/ISO27001/HIPAA), alta disponibilidad/escalado horizontal, limitaciones específicas de Linux/macOS (sesiones interactivas, `taskkill`, `MessageBoxW`), el bypass del conector MCP Filesystem oficial (ya documentado en AGENTS.md regla #12, ahora también visible para un usuario humano), gestión de secretos/Vault no integrada, ausencia de API programática/SDK propio, y falta de migración de config/versionado de esquema.
- Sin cambios de código.

## [1.4.35] — 2026-07-25

### Fixed — event loop bloqueante en `mcp_benchmark` y `mcp_log`
- **`mcp_benchmark`**: `subprocess.run()` y las operaciones de filesystem (`write_text`, `unlink`) se ejecutaban de forma bloqueante en el event loop de asyncio. Envueltos en `asyncio.to_thread()` — consistente con el resto de tools de `layer5_health.py`.
- **`mcp_log`**: `log_path.read_text()` bloqueante sobre archivos de hasta 10MB (el máximo configurado). Envuelto en `asyncio.to_thread()`.

### Fixed — `fs_batch` consumía grant de escritura en dry run
- El wrapper `fs_batch` validaba `validate_tool_path(target, "write")` antes de ejecutar, incluso con `dry_run=True`. Un grant `SINGLE` se quemaba aunque el usuario solo estuviera inspeccionando el resultado sin escribir nada. La validación de escritura ahora se omite cuando `dry_run=True`.

### Fixed — `security_revoke` / `PermissionManager.revoke()` revocaba todos los grants de un recurso
- `revoke(resource)` eliminaba el dict completo de operaciones para una ruta — un grant de `read` y uno de `write` sobre la misma ruta quedaban ambos revocados aunque el llamador solo quisiera revocar `write`.
- `revoke()` acepta ahora `operation: str | None = None`. Sin `operation`, el comportamiento previo (revocar todo) se mantiene. Con `operation`, solo se revoca esa operación.
- `security_revoke` tool actualizado: acepta `operation` opcional y lo pasa a `revoke()`.

### Fixed — documentación AGENTS.md vs código real
- Gate de `execute` para `npm`/`pnpm`: documentado incorrectamente como activo. El código no lo dispara — `validate_shell_execution()` revisa el primer token (`pnpm`/`npm`), no el intérprete interno. Corregido en la sección npm/pnpm.
- Layer 4 condicional a `journal.enabled`: `project_scan` y `project_find` también desaparecen si el journal está deshabilitado. Documentado en la tabla de arquitectura.
- `security_revoke` semántica de `operation` documentada en sección Peculiaridades de PermissionManager.

## [1.4.34] — 2026-07-25

### Added — `working_dir` en `sh_session_send`
- **`sh_session_send` ahora acepta `working_dir: str | None = None`** — paridad con `sh_exec` y `sh_script`.
- El parámetro es validado por `security.validate_tool_path()` antes de ejecutar — misma superficie de seguridad que los otros tools.
- El cambio de directorio se implementa prepending `workdir_prefix` al comando (reutiliza `_escape_workdir` con el fix INJ-02 ya aplicado) — por-comando, no persistente en la sesión.
- **Motivación:** `sh_session_send` sin `working_dir` ejecutaba en el directorio del servidor MCP; no había forma de correr `npm run dev` / `pnpm run dev` en un proyecto específico sin agregar `Set-Location` a `allow_prefix` (lo que abriría evasión de `paths_allow` en sesiones interactivas).
- Cambios: `sh_session_send_impl` (parámetro + lógica), wrapper `sh_session_send` (parámetro + validación).

## [1.4.33] — 2026-07-24

### Added — Cross-platform support (Linux/macOS) + documentation & licensing
- **OS Abstraction Layer (`src/oslayer/`)**:
  - `confirm.py`: Cross-platform confirmation code display — Windows (MessageBoxW), Linux (zenity/kdialog/notify-send/fallback), macOS (osascript). Runs in daemon thread, never returns code via MCP.
  - `system.py`: Memory info (`GlobalMemoryStatusEx` / `/proc/meminfo`), uptime (`GetTickCount64` / `/proc/uptime`), memory pressure hint — zero subprocesses.
  - `process.py`: Process tree kill + reap via `psutil` (cross-platform, replaces Windows-only `taskkill /T /F`).
- **Shell Resolver Multiplataforma (`src/shell_resolver.py`)**:
  - `SHELL_REGISTRY` now supports Linux shells (bash, zsh, fish, sh) alongside Windows (powershell, pwsh, cmd, Git Bash).
  - `_find_executable()` generic via `shutil.which()`, platform-aware `get_default_shell()`.
- **Health Tools Adaptados (`src/layers/layer5_health.py`)**:
  - `health_processes` and `mcp_benchmark` use platform-appropriate commands.
- **Instaladores**:
  - `install.sh` — Linux/macOS installer (venv, config, Claude Desktop registration).
  - `sync-config.sh` — Linux/macOS config mirror sync.
- **CI matrix** (`.github/workflows/ci.yml`): Ubuntu + Windows, Python 3.10–3.13.
- **Config defaults** (`src/config.py`): `shell.default_shell` auto-detects per platform (`bash` on Linux, `powershell` on Windows).
- Tests: 285/285 passing.

### Fixed — Process cleanup broken on timeout (regression from Phase 1)
- Four call sites in `layer2_shell.py` (lines 163-164, 277-278, 309-310, 408-409) still referenced `_kill_process_tree`/`_reap_after_kill` (old names with underscore prefix) after the functions were moved from `layer2_shell.py` to `src/oslayer/process.py` and renamed to `kill_process_tree`/`reap_after_kill` (without underscore). The import was correct; the call sites were never updated.
- **Impact**: Any timeout in `sh_exec` (both native-argv and shell-fallback paths), `sh_script`, or forced `ShellSession.close()` raised `NameError` instead of killing the process tree — leaving orphaned processes and unreleased async I/O handles, exactly the bug class fixed in v1.4.19/1.4.20.
- Verified: `grep` confirms zero remaining references to the old names in `src/`.

### Documentation
- `LINUX-PLAN.md` rewritten to reflect completed implementation — now serves as architecture reference.
- `LICENSE` added (MIT).
- `CHANGELOG.md` updated with this entry.

## [1.4.32] — 2026-07-21

### Added — Performance & Security Hardening (Subprocess Elimination, AST Script Analyzer, Remote SSH Filtering)
- **Subprocess Elimination & Performance Optimization (`src/log.py`, `src/layers/layer5_health.py`)**:
  - Replaced heavy `powershell -Command ...` subprocess invocations in `health_check()` and `_get_uptime()` with native Windows CTypes API calls (`GlobalMemoryStatusEx` and `GetTickCount64()`).
  - Added `available_memory_info()` in `src/log.py` to retrieve total/free RAM in-process with 0 spawned processes.
  - Reduced `health_check()` latency from ~1200ms to <10ms and eliminated ~50MB-100MB RAM spikes per call.
  - Wrapped `health_processes()` in `asyncio.to_thread` to prevent blocking the FastMCP event loop during process listings.
- **Python Script AST Risk Analyzer (`src/script_analyzer.py`, `src/security.py`)**:
  - Added static AST analyzer for Python scripts executed via `sh_exec`.
  - Scans Python target scripts prior to execution for risk categories: `NETWORK` (`requests`, `socket`, `urllib`), `DESTRUCTIVE_IO` (`os.remove`, `shutil.rmtree`), and `SUBPROCESS` (`exec`, `eval`, `popen`).
  - Annotates execute ticket permission requests with explicit risk descriptions if network or destructive calls are detected.
- **SSH Remote Command Whitelisting (`src/config.py`, `src/layers/layer3_ssh.py`)**:
  - Added `remote_allow_prefix` to `SSHConfig` (`["ls", "cat", "echo", "pwd", "git", "uptime", ..."]`).
  - `ssh_exec_impl` now validates every command segment against `remote_allow_prefix` prior to forwarding commands to remote SSH sessions.
- **Consolidated Secret Scanning (`src/secretscanner.py`, `src/layers/layer4_personal.py`)**:
  - Added `scan_and_warn()` helper in `src/secretscanner.py` to standardize credential scanning and format warnings uniformly across Layer 4 personal journal/notes tools.
- Verified: 285/285 tests passing in 36.81s.

## [1.4.31] — 2026-07-20


### Added — memory-pressure hint on slow/timed-out shell commands
- **Root cause of "otro agente tuvo problemas y se cayo el proceso por timeout" after 1.4.19/1.4.20/1.4.21 fixes**: those three fixed real bugs (stdin inheritance, handle leaks, log rotation crash), verified working (`git --version`, `git log`, full `pytest` suite all fast post-restart). But `server.log` still showed repeated `SLOW sh_exec` entries of 60-120s *without* a paired `kill_process_tree` — i.e. the command wasn't hung, it was just genuinely slow to spawn. Traced to the machine running ~10-12 parallel `claude.exe` processes on 7.8GB RAM, with 12-20% free memory sustained through most of this session — spawning a new subprocess under that pressure can take far longer than a typical `timeout`, so callers using the 30s default still see a kill even though nothing is actually stuck.
- **This is not fixable in this codebase** — it's the host machine being memory-constrained while running many parallel MCP server instances, one per open Claude Desktop window/session. What *is* fixable: making that diagnosis visible in the moment instead of requiring a multi-turn investigation each time it recurs.
- **`src/log.py`**: added `available_memory_pct()` (via `GlobalMemoryStatusEx`, a Windows API call — deliberately not a subprocess, so checking memory pressure never itself adds to subprocess pressure) and `memory_pressure_hint()`, which returns an appendable clause when free memory is below 25%, empty string otherwise.
- **Wired in three places**: `timed()`'s SLOW log line, `AuditedFastMCP.call_tool()`'s SLOW log line (`server.py`), and — most visibly — the actual timeout return string in `sh_exec_impl` (both code paths) and `sh_script_impl` (`layer2_shell.py`), so the calling agent sees "...may be resource contention from multiple parallel sessions rather than a hung command..." directly in the tool result, not just in a log file it may never read.
- Verified: full suite, 285/285 passing.

## [1.4.30] — 2026-07-19

### Fixed — `_deny_exception_applies()` never actually let `fs_find`/`fs_list`/`fs_tree` through
- Follow-up to `1.4.29`, same feature, found the same day while actually using it against a real project (HikBioAccess) instead of only the unit tests. `fs_find`/`fs_list`/`fs_tree` validate the **search directory itself** (e.g. `...\bin\Release`) via `validate_tool_path()` → `resolve_and_validate()`, not each file found inside it. A directory has no file extension — `resolved.suffix.lower() not in paths_deny_exception_extensions` was always true for a directory path, so the exception could only ever apply to a direct `fs_read` of an already-known exact filename, never to browsing/finding what's inside an excepted `bin`/`obj` folder in the first place. This made the whole feature effectively unusable for its actual purpose.
- **Fix**: `_deny_exception_applies()` now skips the extension check when `resolved.is_dir()` — a directory only needs to match a `paths_deny_exceptions` pattern. A file still needs both the pattern match and the extension match, unchanged. Net effect: `fs_find`/`fs_list`/`fs_tree` can enumerate names/sizes/dates inside an excepted `bin`/`obj` folder; `fs_read` on anything other than `.dll`/`.exe`/`.pdb` inside that same folder stays blocked.
- 2 new tests in `test_security.py`: directory listing allowed for a matching exception path; a non-build file inside that same directory still blocked for content read.
- Verified: full suite, 285/285 (283 + the 2 new tests above).

### Process failure, documented for the record (not a code bug)
- Spent several rounds diagnosing why `paths_deny_exceptions` had no effect after a server restart, including re-testing `fnmatch` in isolation and importing the real module directly to compare behavior — before checking the one thing that would have answered it immediately: **`AGENTS.md`'s own first 9 lines**, an unmissable warning block that the `config.json` in the repo root is a read-only mirror and the actual file the server loads is `~/.personal-mcp/config.json`. Edited the repo mirror only, restarted, confirmed no effect, repeated — twice — before this was pointed out. `CONFIG-GUIA.md` (a dedicated plain-language guide for exactly this) was also never opened.
- Once pointed at it: applied the change directly to the real `~/.personal-mcp/config.json`, then used `sync-config.ps1`'s own documented logic (validate the official file is valid JSON, copy official → mirror, never the reverse) to bring the repo mirror back in sync, instead of continuing to hand-edit both files independently.
- No code or doc change needed to close this — the warning was already maximally prominent (first thing in the file, blockquote, explicit pointer to the dedicated guide). The gap was not reading it before acting, not a documentation gap.

## [1.4.29] — 2026-07-20

### Added — narrow, read-only exception to `paths_deny` for build artifacts
- New `SecurityConfig` fields: `paths_deny_exceptions: List[str]` (explicit glob patterns, empty by default) and `paths_deny_exception_extensions: List[str]` (default `.dll`/`.exe`/`.pdb`). New `SecurityValidator._deny_exception_applies()`, checked in `resolve_and_validate()` only when a `paths_deny` pattern would otherwise reject the path.
- Motivation: `paths_deny` blanket-blocks `**\bin\**`/`**\obj\**` (vendored/build noise, `1.4.9`+), but that also blocks legitimately inspecting a project's own build output (e.g. a compiled `.dll` in a .NET project like HikBioAccess) without opening those folders in general.
- Scope, by design: only `operation="read"` (never write/delete/execute — verified by a dedicated test); only extensions explicitly in `paths_deny_exception_extensions`; only paths matching an explicit pattern in `paths_deny_exceptions` (empty by default — no behavior change until a pattern is added). Because `fnmatch`'s `**` has no true recursive semantics (it's just `*` twice), a pattern like `MyProj\**\bin\**` requires at least one intermediate subfolder and will not match `MyProj\bin\...` directly — a project needing both shapes needs two explicit patterns (documented inline in `config.py` and in the test fixtures).
- 5 new tests in `test_security.py`: nested match, direct match, non-matching extension still blocked, non-matching project still blocked, write operation still blocked even with matching extension/pattern.
- Also fixed in this release: `test_smoke_runtime.py::test_fs_read_outside_allowed_returns_error` was asserting against `C:\Windows\system.ini`, which stopped being "outside `paths_allow`" once `paths_allow` became `["C:\\"]` (`1.4.26`) — not a bug in the code, a stale assumption in the test. Now asserts against an `AppData` path, which `paths_deny` still genuinely blocks.

### Verified
- Full suite re-run 2026-07-20: **283 passed, 0 failed**. This does not match `1.4.23`'s claimed "331 tests". **Investigated same day**: compared the live tree against two independent full-repo backup copies (`.personal-mcp - copia`, a snapshot at v1.4.14, and `.personal-mcp - copia (2)`, a snapshot of the exact pre-recovery state this release's `1.4.28` entry describes — same branch name, same stash, same 8 uncommitted files). Neither copy collects more tests than the live tree (278 and fewer respectively, vs. 283 live) — both are earlier or equal states, not sources of missing work. Conclusion: no tests were lost; `1.4.23`'s "331" was never accurate (never verified again after that entry was written, per the pattern already flagged in `1.4.17`'s "Removed unverifiable '274 tests' claim"). `283` stands as the current, twice-verified ground truth.

## [1.4.28] — 2026-07-19

### Recovered — v1.4.15 through v1.4.27 committed to git (were working-tree-only edits, never committed)
- **Root cause**: `1.4.15` through `1.4.27` (below) existed only as uncommitted changes in `src/` plus a manual backup copy under `stash_dump/*.stash` — none of it was ever `git commit`-ed. A `git stash` taken separately along the way (message "pre-tool-annotations-") turned out to be unrelated, containing only one untracked test file. The actual gap was purely "edited but never committed", confirmed via `git log`, `git status`, `git diff --stat` against the `stash_dump/` copies before touching anything.
- **Also found via `git log --oneline --all --graph`**: the repository's `HEAD` was sitting on a secondary branch (`test-branch-123`), not `main` — `main` pointed at a separate, empty commit ("test") one step behind. Consolidated: `main` deleted and the working branch renamed to `main`, so there is a single branch again with the full history below.
- **Action**: reviewed `git diff --stat` (10 files, 339 insertions / 60 deletions) confirming the changes matched exactly what `1.4.15`–`1.4.27` below describe, then `git add src/ tests/test_layer5_health.py && git commit`. `stash_dump/` deleted afterward (`fs_delete_batch`, one ticket) — its content is now superseded by real git history and the entries below.

### Fixed — `request_permission()`'s single-resource ticket message never mentioned `confirm_code`
- Regression/gap independent of `1.4.15`–`1.4.27`: when the HMAC `confirm_code` gate was implemented (`1.4.14`), the message returned by `SecurityValidator.request_permission()` (used by `validate_tool_path()` for `fs_write`/`fs_edit`/`fs_delete`/`fs_move`/`fs_create_directory`, and by `validate_shell_execution()`'s `execute` tickets) was never updated to mention it — it just said `"Use fs_approve(ticket_id=..., level='single')..."`, with no `confirm_code` parameter. The batch variant (`validate_tool_paths_batch()`, added later in `1.4.16`) and `fs_request_allow` (`layer6_permissions.py`) both had the correct wording from the start; only this one path was stale. Not a security hole — `PermissionManager.approve()` already required `confirm_code` regardless of what the message said, verified before treating it as low-risk — but it told the calling agent to do the wrong thing. **Fix**: message now states the code was shown on-screen, is not visible to the agent, and must be passed as `confirm_code`, matching the other two call sites.

### Fixed — `resolve_shell()` called synchronously inside `async def` tool handlers (event-loop blocking regression)
- Found while investigating the same class of hang described in `1.4.20`/`1.4.21`. `register_shell_tools()`'s `sh_exec`, `sh_script`, and `sh_session_start` closures called `manager.resolve_shell(shell)` directly (not wrapped in `asyncio.to_thread`) whenever an explicit `shell=` argument was passed. For `shell="bash"`, `resolve_shell()` → `_find_git_bash()` runs a **synchronous** `subprocess.run(["git", "--exec-path"], timeout=5)` — blocking the entire server event loop (not just the current call) for up to 5s per invocation. Not caught by `1.4.19`/`1.4.20`'s fixes, which only covered `sh_exec_impl`/`sh_script_impl`'s own subprocess handling, not this call site. **Fix**: all three call sites now wrap the call as `await asyncio.to_thread(manager.resolve_shell, shell)`.

### Notes
- `1.4.15`–`1.4.27` below were reconstructed from the working-tree diff and `stash_dump/`'s content (deleted after this release, per above) — dates and authorship preserved from that record, not re-verified commit-by-commit since they were never actual commits until now.
- Two items documented as "hypothesis, not fully proven" in `1.4.21`'s original entry are applied as described there (see below) — this release does not add new evidence either way, only carries the fix forward into git history.

## [1.4.27] — 2026-07-17

### Security — `paths_deny` expanded with 14 credential-focused patterns
- Follow-up to `1.4.26`'s AppData fix, same day, at the repo owner's explicit request ("aplica todas" on a list of candidates proposed after the AppData gap was found). With `paths_allow` now `["C:\\"]`, `paths_deny` is the only real control left for reads, and the AppData fix only closed one specific gap.
- Added, folder-style (`**\\name\\**`, same pattern as existing entries): `.ssh`, `.aws`, `.azure`, `.kube`, `.gnupg`.
- Added, exact-file style: `**\\.docker\\config.json`, `**\\.git-credentials`, `**\\.netrc`, `**\\.npmrc`, `**\\.pypirc`.
- Added, filename-wildcard style (new pattern shape for this project): `**\\.env*`, `**\\*.pem`, `**\\id_rsa*`, `**\\id_ed25519*` — unlike every prior entry, these match by filename regardless of which folder they're in.
- Deliberately not added: browser profile directories (already covered by `**\\AppData\\**` from `1.4.26`), and `C:\\Windows\\System32\\config\\SAM` (already locked by Windows itself, a `paths_deny` entry would be redundant).
- Explicitly flagged as incomplete by design, not a gap: this is a list of known patterns, not a general mechanism. `scan_text()` (the secret scanner, wired since `1.4.9`) is the backstop for content in locations `paths_deny` didn't anticipate.
- Verified: full suite (331/331) after the change. `config.json` repo mirror re-synced to match. `AGENTS.md` rule #14 updated; `pyproject.toml` bumped to 1.4.27.

## [1.4.26] — 2026-07-17

### Security policy change (deliberate, by the repo owner) — `paths_allow` broadened to `C:\`
- `paths_allow` changed from `["C:\\Repos"]` to `["C:\\"]"` in the live config (`~/.personal-mcp/config.json`) — a deliberate decision: "eso fue una decisión porque se ha vuelto muy restrictivo para ciertas tareas que se están haciendo." Write/delete operations are unaffected — they still require an explicit grant via the ticket+HMAC flow regardless of `paths_allow` scope; only unticketed reads (`fs_read`, `fs_list`, `fs_search`, `fs_tree`, `fs_find`, `fs_info`) are now unrestricted across the whole `C:` drive except for `paths_deny`.
- Found via a separate conversation's test run: `test_fs_read_outside_allowed_returns_error` started failing after this change — not a regression, the test's assumption (a plain `C:\` path is denied) stopped being true once `paths_allow` covers the whole drive. Updated the test to assert the invariant it actually protects (`paths_deny` still wins even when `paths_allow` is this broad) against a path that is genuinely still denied.
- Found in the same pass: the `paths_deny` entry for AppData, `"C:\\Users\\User\\AppData"`, had no wildcard — unlike every other entry. `fnmatch` treats a pattern with no `*` as an exact match, so it only ever blocked that literal path, never anything inside it. With `paths_allow` now covering the whole drive, this meant every file under AppData (browser credential stores, app tokens, cached session data) was readable with zero restriction. **Fixed**: changed to `"**\\AppData\\**"`, matching the pattern style of every other deny entry. Verified via the corrected smoke test and a full run of the suite (331/331).

### Fixed — `show_confirmation_code_batch` popup unreadable for large batches
- `src/confirm_popup.py`'s batch popup listed every individual path — for a 100-file `fs_delete_batch` ticket this produced a `MessageBoxW` message of roughly 13,000 characters, unusable (confirmation code not findable on screen).
- **Fixed**: the message now previews at most `MAX_PREVIEW_FILES` (10) paths, followed by a count of the remainder and a pointer to `security_pending` for the complete list. Message size no longer scales with N. `PermissionManager.request_batch()`'s ticket/grant behavior was never affected — only the display changed.
- Applied via the generic `Filesystem` MCP connector (see rule #12) rather than this server's own `fs_edit` — using this server's own ticket flow to authorize a change to the code that generates that same ticket's popup would have been circular.

## [1.4.25] — 2026-07-10

### Docs — a security limitation only documented for AI agents, not for actual users
- The rule #12 gap in `AGENTS.md` (the generic `Filesystem` MCP connector bypasses every ticket/HMAC/audit protection this server implements, if enabled in the same client with write access to the same folders) was only written in a document meant for AI agents, never in anything a human user would read.
- Added to `README.md`: a new bullet in the Security section naming the `Filesystem` connector as the concrete example, stating there is no fix possible from within personal-mcp.
- Added to `CONFIG-GUIA.md`: a full new section in plain Spanish explaining what "bypass" means in practice and what the reader can actually do about it (check which connectors are enabled, remove write access to the same folders, or uninstall the redundant one).

## [1.4.24] — 2026-07-10

### Docs — stale claim contradicting the project's own security model
- `AGENTS.md` rule #11 stated the opposite of what rules #9/#10 (and the real code) guarantee — it described the pre-`1.4.14` state (self-approval possible for `execute` tickets) as still current. Re-verified `PermissionManager.approve()` directly: `confirm_code` is required via `hmac.compare_digest()`, shown only via the native popup, never returned by any tool. **Fix**: rule #11 corrected, with an explanation of when it was true and why it stopped being true.
- No `src/` changes in this release — documentation-only.

## [1.4.23] — 2026-07-10

### Added
- Secret scanning en `fs_read_media`: escanea el contenido decodificado antes de codificarlo a base64, mismos 12 patrones que `fs_read_impl`. No bloquea, solo advierte.
- `fs_search` salta archivos >10 MB (`_SEARCH_MAX_FILE_MB`) para evitar consumo excesivo de memoria en binarios o archivos grandes.

### Tests agregados (10 nuevos, 321 → 331 total)
- `test_layer5_health.py` (nuevo, 5 tests), `test_filesystem.py` (+3, `fs_delete_batch_impl`), `test_permissions.py` (+7, batch), `test_integration_tool_flow.py` (+6, batch delete end-to-end).

## [1.4.22] — 2026-07-10

### Fixed
- **`ShellSession.close()` no llamaba `_reap_after_kill()` — fuga de handles (regresión de v1.4.20)**: al exceder el timeout de cierre de una sesión interactiva, mataba el proceso pero luego llamaba `await self._process.wait()` sin timeout — exactamente el bug que `_reap_after_kill()` resolvió en v1.4.20 para `sh_exec_impl`/`sh_script_impl`, pero `ShellSession.close()` nunca se actualizó. Arreglado: ahora usa `_reap_after_kill()`.
- **`ShellSession.execute()` no sanitizaba el log — inyección de logs (estilo INJ-05)**: `logger.debug(...)` interpolaba el comando sin `sanitize_log_value()`, a diferencia de `sh_exec_impl`/`sh_script_impl` (desde v1.4.9). Arreglado: ahora pasa por `sanitize_log_value()`.
- **Deny list false positive: `"format"` bloqueaba `--format` flags y `git format-patch`**: el regex `\bformat\b` matcheaba en cualquier parte del comando. Refactor de `is_command_allowed()`: entradas de una sola palabra (`"format"`, `"shutdown"`) se revisan solo contra la primera palabra de cada segmento, mismo ámbito que `allow_prefix`; entradas multi-palabra (`"rm -rf"`, `"net user"`) mantienen el chequeo sobre todo el comando.

### Tests agregados (26 nuevos, 316 → 321 total)
- `split_command_segments()` (15), `_escape_workdir()` (6), `validate_shell_execution()` (6), deny list fix (5).

## [1.4.21] — 2026-07-09

### Fixed (second hang mechanism found in the same investigation as 1.4.20 — hypothesis, not fully proven)
- `mcp_log` returned no entries newer than three days despite active multi-session use. **Working hypothesis**: `configure()` in `log.py` wires a plain `RotatingFileHandler` at a single shared path across multiple server processes (one per parallel Claude session). On Windows, if one process rotates while another still has the file open, the rename raises `PermissionError`; `logging`'s default error handling can print a traceback to `stderr` on every subsequent `emit()` while the size condition persists — and on a stdio-transport MCP server, an unread `stderr` pipe can fill and block the writer, hanging the entire process.
- **Not conclusively proven**: circumstantial evidence (stale logs + a known Windows failure mode + a plausible mechanism), not a captured stack trace.
- **Fix, scoped to what's certain**: `logging.raiseExceptions = False` set in `configure()` — makes a failed rotation a silently-dropped log line instead of a potential hang. Does not fix the underlying multi-process rollover race itself.

## [1.4.20] — 2026-07-09

### Fixed (follow-up to 1.4.19 — same symptom, different root cause, confirmed still reproducing after 1.4.19's fix)
- **Root cause**: `sh_exec_impl`'s two `except asyncio.TimeoutError:` handlers and `sh_script_impl`'s handler all called `_kill_process_tree(process.pid)` and returned immediately — none ever called `process.wait()` on the original `Process` object. On Windows, this left stdout/stderr pipe transports registered with the event loop's IOCP-based subprocess watcher but never released. Confirmed independent of `1.4.19`'s fix (reproduced live with that fix already on disk). Each additional timeout leaked more handles; with enough accumulated, even trivial unrelated commands started timing out.
- **Fix** (`layer2_shell.py`): new `_reap_after_kill(process)` — `await asyncio.wait_for(process.wait(), timeout=10)` after `_kill_process_tree()`, letting asyncio release the transport. Called at all `except asyncio.TimeoutError:` sites in `sh_exec_impl`/`sh_script_impl`.

## [1.4.19] — 2026-07-09

### Fixed (server hang — reproduced live twice, root cause confirmed in source)
- **Root cause**: `src/server.py` runs `app.run(transport="stdio")` — the server's own `stdin` **is** the JSON-RPC channel to the client. None of `sh_exec_impl`'s subprocess calls specified `stdin=`, so every spawned child inherited that handle; a child that blocks on stdin can hang forever. Compounded by `_kill_process_tree()`'s `await proc.wait()` on `taskkill` having no timeout at all.
- **Fix** (`layer2_shell.py`): `sh_exec_impl`'s shared `proc_kwargs` now includes `stdin=asyncio.subprocess.DEVNULL`; `sh_script_impl`'s subprocess creation gets the same; `_kill_process_tree()`'s `taskkill` subprocess also gets `stdin=DEVNULL`, and its `await proc.wait()` is wrapped in `asyncio.wait_for(timeout=10)`.

## [1.4.18] — 2026-07-08

### Fixed (security — explicit user request: "todo lo anterior debe pasar por ticket")
- `install.ps1`'s default `allow_prefix` for a fresh install let filesystem mutations (`remove-item`, `del`, `copy`, `move`, `mkdir`, `new-item`, etc.) bypass the ticket system entirely. Removed all 10 verbs from the default list.
- Known gap surfaced same day: the real `~/.personal-mcp/config.json` in use had `mkdir`/`rmdir` in `allow_prefix` — same bypass class, already active. Fixed same day by the repo owner directly (outside this repo's reach), confirmed via the repo's read-only config mirror.

## [1.4.17] — 2026-07-08

### Context
Full re-audit against source code as ground truth. Tool counts (56 total / 52 active) re-confirmed independently.

### Fixed
- `verify.py`'s layer breakdown miscounted Layer 6 — no bucket for Permissions tools, `fs_approve`/`fs_deny`/`fs_request_allow` silently counted as Layer 1. Added a Layer 6 bucket.

### Docs
- Removed unverifiable "274 tests (all pass)" claim from `AGENTS.md`/`README.md` Quick start blocks. New `AGENTS.md` rule #13 documenting `install.ps1`'s broader-than-live `allow_prefix` gap (not fixed — policy decision flagged for the repo owner).

## [1.4.16] — 2026-07-08

### Added
- **`fs_delete_batch(paths: List[str])`** — new Layer 1 tool (18th → 19th). One ticket/one `confirm_code` bound to a specific, enumerated list of paths, instead of one popup per file. `PermissionTicket` gained an optional `resources: List[str]` field for batch tickets. `PermissionManager.request_batch()`/`approve()` extended; `confirm_popup.show_confirmation_code_batch()` new; `SecurityValidator.validate_tool_paths_batch()` peeks all paths before consuming any. Delete remains forced to `SINGLE` — no exceptions, same rule as single-file delete.

### Tests
- 16 new tests across `test_permissions.py`, `test_filesystem.py`, `test_integration_tool_flow.py`.

## [1.4.15] — 2026-07-08

### Docs — tool counts corrected against real `@mcp.tool()` decorators
- `AGENTS.md` header claimed "47 tools"; real count (by counting decorators directly) was 55 (51 active). Layer 1 was undercounted by 7 tools that existed in code but were never added to the header. `README.md`/`SEGURIDAD-COMPARATIVA.md` corrected to match.

### Fixed
- `validate_security.py` Test 3 broken by the `1.4.14` `confirm_code` gate — updated to prompt and read the code via `input()`, same as the real `fs_approve` flow, without reopening the auto-approval gap the HMAC gate exists to close.

### Notes
- `pyproject.toml` version bumped to 1.4.15 in this release — closing out the "version bump still outstanding" note carried unresolved across `1.4.7` through `1.4.14`.

## [1.4.14] — 2026-07-07

### Security (fixed — closes the gap tracked since 1.4.10)
- **Implemented the HMAC-confirm-code design (Opción C) for `fs_approve`**, closing the caller-identity gap documented in 1.4.10 and re-confirmed unavoidable via `elicitation` in 1.4.13 (the connected client doesn't declare that capability).
- **`src/permissions.py`**: `PermissionManager` now generates a 32-byte secret (`secrets.token_bytes(32)`) in memory at construction time, never persisted to disk or exposed via any tool. `PermissionTicket` gained a `confirm_code` field (6-digit, derived from `hmac.new(secret, ticket_id, sha256)` at request time via `_generate_confirm_code()`). `approve()` now requires `confirm_code` and rejects the call via `hmac.compare_digest()` if missing or incorrect, returning `(False, "Invalid or missing confirmation code.")` without touching ticket state.
- **`src/confirm_popup.py` (new module)**: `show_confirmation_code(resource, operation, code)` displays the code via a native Windows `MessageBoxW`, launched in a daemon thread so it doesn't block the server's asyncio event loop while waiting for the user. This is the only channel where the code is visible — it is never returned in any tool response (`fs_request_allow`, `security_pending`, etc.). No-ops under pytest (`PYTEST_CURRENT_TEST` env var) to avoid blocking the suite with real popups.
- **`src/layers/layer6_permissions.py`**: `fs_approve(ticket_id, confirm_code, level="single")` — `confirm_code` is now a required parameter. `fs_request_allow`'s returned message updated to state explicitly that the confirmation code is shown on-screen and is not visible to the calling agent.
- **Tests**: `tests/test_permissions.py` and `tests/test_integration_tool_flow.py` updated — every `approve()`/`fs_approve()` call site now passes `ticket.confirm_code` (or the ticket's live code fetched via `pm._tickets[ticket_id].confirm_code` where the ticket object isn't already in scope). 6 call sites updated in `test_permissions.py`, 10 in `test_integration_tool_flow.py` (including the local `_make_fs_approve` closure, which now mirrors the real `layer6_permissions.py` signature exactly).
- **274 tests total, 272 pass.** 2 known pre-existing failures, unrelated to this change (see "Known gaps" below).

### Known gaps (documented, not fixed in this release)
- **The generic `Filesystem` MCP connector bypasses this entire mechanism** if enabled alongside `personal-mcp` with write access to this repo's path — it writes directly to disk with no ticket system at all. See `AGENTS.md` rule #12. No code fix is possible from this repo; it's a client-side connector configuration concern, not a `personal-mcp` bug.
- **`test_sh_exec_shell_operators_fallback`** (`tests/test_shell.py`) — `findstr` not in `allow_prefix`; pre-existing, unrelated to this change.
- **`test_fs_read_inside_allowed_no_grant_succeeds`** (`tests/test_smoke_runtime.py`) — smoke test out of sync with the "Option C" read-auto-allow behavior (v1.4.1); pre-existing, unrelated to this change.
- `pyproject.toml` version bump still outstanding (now several versions behind, tracked since 1.4.7).

## [1.4.13] — 2026-07-05

### Investigated (no code change to the permission system — see AGENTS.md rule #9)
- **Evaluated `elicitation` (standard MCP protocol mechanism for pausing a tool call to request real human confirmation via the client's UI, with no agent mediation) as an alternative to the HMAC-confirm-code design planned for the `fs_approve` caller-identity gap (1.4.10)**. Elicitation is architecturally superior *if the client supports it*: it uses the client's native UI instead of requiring a human to read a terminal, and needs no new dependency — `Context.elicit(message, schema)` is already available in the installed FastMCP version (`mcp/server/fastmcp/server.py`).
- **Isolated test tool** (`_test_elicitation`, temporary, added and removed in this same session) called `ctx.elicit()` against the connected MCP client. **Result: `McpError: Method not found`** — the client does not declare the elicitation capability at all. This is a harder failure than the known `anthropics/claude-code#56243` bug (silent auto-cancel with a rendered-then-discarded prompt); here the RPC method itself doesn't exist from the client's perspective.
- **Conclusion**: elicitation is not viable on the current client. The HMAC-confirm-code design (Opción C, still not implemented) remains the only technical path available today. Documented in `AGENTS.md` rule #9 as a sub-finding, including the exact failure mode, so a future session doesn't re-propose elicitation without first re-running this check against whatever client is connected at that time.
- **No change to `layer6_permissions.py`'s actual `fs_approve`/`fs_request_allow` behavior in this release.** The caller-identity gap remains open and exploitable exactly as described in 1.4.10 and AGENTS.md rules #9/#10 — this entry only rules out one candidate fix, it does not close the gap.

## [1.4.12] — 2026-07-05

### Added
- **Execute-approval gate for general-purpose interpreters (`approval_required_prefix`)**: `CommandPolicy.approval_required_prefix` (default: `["python", "node", "bash"]`) plus `SecurityValidator.validate_shell_execution()` (`security.py`). Rationale: `python`/`node`/`bash` are whitelisted in `allow_prefix` because legitimate dev workflows need them, but once whitelisted by prefix, anything executed *inside* the interpreter (arbitrary code via `-c`/`-e`) is invisible to `paths_allow`/`deny` — a structural limitation of prefix-based whitelisting, not a bug. This does not close that gap (nothing running inside an already-approved interpreter is contained), it adds a checkpoint before the interpreter is allowed to run at all: the first segment of a command whose first word matches `approval_required_prefix` requires an explicit `execute` ticket on the resolved interpreter path (`shutil.which(...)`) before proceeding, reusing the existing `PermissionManager`/`fs_approve` ticket flow (`operation="execute"`, already excluded from wildcard `"*"` grants — same isolation as `"delete"`). Wired into `sh_exec` and `sh_session_send` wrappers in `layer2_shell.py`. Ticket level defaults to `SINGLE` unless the approver explicitly requests `session`/`permanent` via `fs_approve`.
- **`deny` list extended (locally, not in code defaults) with interpreter-reachable dangerous primitives**: `os.system`, `subprocess.run/Popen/call`, `shutil.rmtree`, `child_process`, `require('fs').unlink`, pipe-to-shell patterns (`curl * | `, `iex (`, etc.) — modeled after Desktop Commander's `blockedCommands` denylist approach. This is a config-level addition (the operator's own `~/.personal-mcp/config.json`), not a change to `CommandPolicy.deny`'s default in `config.py` — new installs do not get these patterns automatically. `CONFIG-GUIA.md` now documents this list as a recommended starter set.

### Known gaps (not fixed in this release — documented, not silently left undiscoverable)
- **`sh_script` does not call `validate_shell_execution()`** — only `sh_exec`/`sh_session_send` do. Currently harmless because `sh_script`'s separate, stricter `readonly_prefix` whitelist (v1.4.5) does not include any general `python <file>`/`node <file>` invocation — so `sh_script` cannot reach a general-purpose interpreter today regardless. This is a latent inconsistency: if `readonly_prefix` is ever extended to include running a python/node script, `sh_script` would execute it without ever passing through the execute-approval gate, silently. Flagged for whoever touches `readonly_prefix` next.
- **Zero test coverage** for `validate_shell_execution()` — no test in `tests/` exercises the execute-ticket flow, the wildcard exclusion for `"execute"`, or the `sh_script` gap above. Checked via search before writing this entry, not assumed.
- **Does not address the caller-identity gap already tracked in `AGENTS.md` rules #9/#10 (`CHANGELOG` 1.4.10)**: this ticket flow uses the exact same `fs_approve` mechanism, with the exact same limitation — an agent can request and then approve its own `execute` ticket, since `PermissionManager.approve()` still does not verify who is calling it. Verified live in a real session: a ticket was requested for `python.EXE`, approved via `fs_approve` (by explicit human instruction in that case, not automatically), and the subsequent command was separately caught by the new `deny` pattern (`os.system`) — confirming both layers work independently, but neither closes the self-approval gap.
- `pyproject.toml` version bump still outstanding (now three versions behind, since 1.4.7).

## [1.4.11] — 2026-07-05

### Fixed
- **`project_scan`/`project_find` blocked the entire MCP connection when scanning a directory with real projects (reproduced live: 4+ minute hang, zero response)**: both functions used blocking calls directly inside `async def` — `project_scan_impl` called `subprocess.run(["git", ...], timeout=10)` twice per subdirectory (up to 20 blocking calls scanning `C:\Repos`'s ~10 projects), and `project_find_impl` called `base.rglob(filename)`, which walks the entire tree (including `node_modules`) before the exclusion filter applies. FastMCP runs all tool calls on a single shared event loop; any synchronous blocking call inside an `async def` tool freezes every other concurrent tool call for as long as it runs, not just the one in progress. This was always present, but only became reachable once `_default_project_root()` (1.4.8) started pointing at `paths_allow[0]` — previously the default silently pointed at an empty/inaccessible folder, so the loop never had real projects to hang on.
- **Fix**: extracted `_git_project_info(entry)` and `_find_files_sync(base, filename)` — plain synchronous helpers, same responsibility as before — and call them via `asyncio.to_thread()` from `project_scan_impl`/`project_find_impl`, exact same pattern already used for `fs_search` (1.4.7) for the identical class of problem. Public tool signatures (`project_scan(path=None)`, `project_find(filename, path=None)`) are unchanged.

### Notes
- Verified before changing: `tests/test_personal.py` tests the `Journal` class directly and never calls `project_scan_impl`/`project_find_impl` — zero existing test coverage for either function, so this change carries no test-compatibility risk, but also means neither function has regression coverage. Not added in this release (out of scope for the reported bug fix; flagged as debt).
- Not addressed: individual `subprocess.run()` calls remain sequential (one project at a time) rather than parallelized via `asyncio.gather` — the reported bug (blocking *other* tool calls) is fully fixed either way; parallelizing would only reduce `project_scan`'s own wall-clock time, which wasn't the complaint. Revisit if scan latency itself becomes a problem with more projects under `C:\Repos`.
- Written concurrently with another session's 1.4.10 entry below (`fs_approve` caller-identity finding) — discovered via the mandatory re-read-before-edit check; renumbered to avoid collision rather than overwriting it.
- `pyproject.toml` version bump still outstanding (noted since 1.4.7, not yet applied — now two versions behind).

## [1.4.10] — 2026-07-05

### Security (documented risk, not fixed)
- **`fs_approve` sin caller identity**: la tool `fs_approve` nunca validó quién la invoca (presente desde v1.3.0). El agente puede auto-aprobar tickets de escritura en `paths_allow`. No se implementa fix en esta versión. La solución proyectada es un Token HMAC (Opción C): clave secreta en memoria al arrancar, código HMAC impreso en stderr, `fs_approve` requiere el código como parámetro. Pendiente de implementar. Mientras tanto, AGENTS.md documenta una regla de convención (no auto-aprobar tickets) sin valor como control de seguridad.

## [1.4.9] — 2026-07-04

### Security audit findings and fixes (external audit report, verified against source before applying)
Five findings reported by an external audit pass over v1.4.8. All five verified line-by-line against actual source before any fix was applied — two severities were adjusted based on that verification (see notes).

1. **CRITICAL — Newline bypass in command segment validation (INJ-01)**: `is_command_allowed()` splits a command into segments via `split_command_segments()` to validate each independently, but that function did not treat `\n` as a segment boundary, while Python's `str.split()` (used to extract each segment's first word) does. A command like `"echo hello\nWrite-Host 'INJECTED'"` produced one segment whose first word was `"echo"` (whitelisted) — the injected second statement was never checked against `allow_prefix`, and PowerShell/cmd/bash all treat a literal newline in a `-Command`/`-c` argument as a statement separator, so it executed. The deny-list check (`re.search` over the whole string) still caught known-bad substrings like `rm -rf` regardless of newlines, which is why the bypass required content *not* already on `deny` (the audit's own PoC used `Write-Host`, not `rm -rf`). **Fix**: `split_command_segments()` in `shell_resolver.py` now splits on `\n` in addition to `| ; & < > \` $(`; `tokenize_command()` treats `\n` as whitespace; `_SHELL_OPERATORS_RE` includes `\n` so multi-line commands correctly route to segment-validated shell execution instead of being mangled into a single corrupted argv token for native exec.
2. **HIGH — `working_dir` escaped with PowerShell syntax regardless of target shell (INJ-02)**: `safe_wd = working_dir.replace('"', '`"')` was applied unconditionally in both `sh_exec_impl` and `sh_script_impl`, before interpolating into `workdir_prefix`. That escape is correct only for `powershell`/`pwsh`; for `cmd` it needed `""` (doubled quote) and for `bash` it needed `\"`. A `working_dir` value containing a literal `"` could break out of the quoted segment on `cmd`/`bash` and inject further shell syntax. **Fix**: new `_escape_workdir(working_dir, shell_name)` in `layer2_shell.py`, used at both call sites, escaping per the actual target shell.
3. **MEDIUM — SSH command validation is local-only (INJ-03)**: `ssh_exec_impl` already validates commands against `is_command_allowed()` before sending them (added in v1.4.5, finding #5) — but that policy runs on the machine hosting `personal-mcp`, not on the remote host the SSH session connects to. A command that passes the local allowlist is still forwarded verbatim and executed with whatever privileges the remote account has, with no equivalent enforcement there. This is an inherent limitation of validating locally before a remote handoff, not a regression of the v1.4.5 fix. Severity assessed as MEDIUM rather than the audit's HIGH: `register_ssh_tools()` doesn't register any SSH tool at all unless `config.ssh.enabled=True` and `~/.ssh/config` exists — SSH is disabled by default and in this deployment, so the gap is currently unreachable. **Fix**: `ssh_exec_impl` now prefixes every result with an explicit `[WARNING]` that local validation does not bind the remote host. Full remote-side enforcement would require deploying a validating wrapper on each remote host — out of scope here (no existing mechanism to deploy anything remotely; flagged as a possible future project, not a local code fix).
4. **MEDIUM — Secret scanner didn't cover journal/notes (INJ-04)**: `scan_text()` was wired into `fs_read_impl` and the shell execution paths (v1.4.2, v1.4.5) but never into `journal_add_impl`/`note_quick_impl` — a credential pasted into a journal entry or quick note was written to disk with zero warning, unlike the same content read from a file or shell output. **Fix**: new `_scan_and_append()` helper in `layer4_personal.py` (same warn-only pattern as `layer2_shell.py`'s `_append_secret_scan`, not shared across layers to avoid a cross-layer dependency for a two-line helper — flagged as minor DRY debt below, not fixed here). `journal_add_impl` signature gained a required `config: AppConfig` parameter to reach the scanner and the `secret_scanning_enabled` flag; its only caller (`register_personal_tools`) was updated accordingly. No test in `test_personal.py` calls `journal_add_impl` directly (it tests `Journal` instead), so this signature change has no test-compatibility impact — verified before making the change.
5. **LOW — Log injection via crafted arguments (INJ-05)**: the audit report pointed at `scrub_sensitive_data()` in `log.py`, but that function only masks dict keys (`password`, `token`, etc.) and was never meant to sanitize control characters in values — and the JSON-encoded audit trail in `server.py`'s `AuditedFastMCP` is already safe, since `json.dumps()` escapes `\n` as the two-character sequence `\n`. The actual vulnerable call sites are `layer2_shell.py`'s two direct `logger.info("sh_exec command=%.200s ...", command, ...)` / `sh_script script=%.100s` calls, which interpolate the raw string via `%s` with no escaping — a command containing a literal newline could forge a fake log line (e.g. a fake `[INFO] User authenticated as admin` entry). **Fix**: new `sanitize_log_value()` in `log.py` (escapes `\n`/`\r` to literal `\n`/`\r`), applied at both call sites in `layer2_shell.py`.

### Notes
- Test coverage checked before each edit, not after: `test_shell_resolver.py` (no existing test exercises `\n` in `tokenize_command`/`has_shell_operators`), `test_shell.py` (`test_sh_exec_argv_with_working_dir` only exercises the native-exec `cwd` kwarg path, never the vulnerable `workdir_prefix` string-interpolation path — unaffected by fix #2), `test_personal.py` (tests `Journal` directly, never `journal_add_impl`), and confirmed no `tests/test_ssh.py` exists at all (SSH layer has zero test coverage, consistent with being disabled by default — flagged, not addressed here).
- Debt flagged, not fixed in this release: `_scan_and_append` in `layer4_personal.py` duplicates the same small pattern as `_append_secret_scan` in `layer2_shell.py` instead of sharing one implementation — left as-is to avoid a cross-layer import for ~6 lines; revisit if a third call site appears.
- `pyproject.toml` version bump still outstanding from 1.4.7 (noted then, not yet applied).

## [1.4.8] — 2026-07-04

### Fixed
- **`project_scan`/`project_find` defaulted to a stale path when called without an explicit `path`**: both `project_scan_impl` and `project_find_impl` used a hardcoded `Path.home() / "Repos"` (i.e. `C:\Users\User\Repos`) as the fallback root. This silently drifted from the live `paths_allow` config once it was narrowed to a single custom directory (`C:\Repos`) — calling either tool without `path` failed with `Path not in allowed directories`, even though the server had a perfectly valid allowed directory configured.
- **Fix**: new helper `_default_project_root(security)` in `layer4_personal.py`, used by both functions instead of the duplicated literal. Returns `paths_allow[0]` (the real source of truth) when available; falls back to `Path.home() / "Repos"` only if `paths_allow` is empty — a misconfigured-server case where no default could be correct anyway, and `resolve_and_validate()` already rejects it with the same clear error as before. No change in behavior for calls that already pass `path` explicitly.

### Notes
- Same operational note as 1.4.6/1.4.7: this fix (and the 1.4.7 `fs_search` fix) will not take effect until the MCP server process is restarted — Python does not hot-reload modules.

## [1.4.7] — 2026-07-04

### Fixed
- **ReDoS risk in `fs_search`**: `fs_search_impl` compiled and ran the user-supplied `pattern` directly against every line of every matched file, with no bound on execution time. A pathological pattern (catastrophic backtracking, e.g. `(a+)+$`) could hang the tool call — and, since `fs_search_impl` ran synchronously inside the async function (no `asyncio.to_thread`, unlike `fs_read_impl`/`fs_write_impl`/etc.), it also blocked the server's entire event loop while running.
- **Fix**: search logic extracted to a plain sync helper (`_fs_search_sync`) and executed via `asyncio.to_thread` wrapped in `asyncio.wait_for(timeout=_SEARCH_TIMEOUT_SECONDS)` (10s constant). A single catastrophic `regex.search()` call cannot be interrupted mid-execution in pure Python (no external timeout-capable regex engine is a dependency of this project, and none was added — YAGNI), so the orphaned thread may keep running in the background, but the MCP call itself now always returns to the caller instead of hanging indefinitely. `re.compile()` is also now wrapped in `try/except re.error`, returning a clean error message for invalid patterns instead of an uncaught exception (same failure class fixed for `fs_delete` in 1.4.6).
- Public tool signature of `fs_search` is unchanged — the timeout is an internal constant, not a new exposed parameter, since there is no evidence yet that per-call configurability is needed.
- 2 new tests: `test_search_invalid_pattern`, `test_search_timeout` (the latter uses `monkeypatch` on `_fs_search_sync`/`_SEARCH_TIMEOUT_SECONDS` rather than a real catastrophic pattern, to keep the test fast and deterministic).

### Notes
- Not addressed in this release (separate, lower-priority findings from the same review pass):
  - `pyproject.toml` version bump to match this changelog.

## [1.4.6] — 2026-07-04

### Fixed
- **`fs_delete` failed with a raw, uncaught exception instead of the expected `permission_required` JSON, even after the ticket was approved**: `fs_delete_impl` called `security.resolve_and_validate(path, "delete")` a second time after the `fs_delete` wrapper had already validated and consumed the grant via `validate_tool_path(path, "delete")`. Because delete tickets are always forced to `SINGLE` (see 1.4.5, finding #3) and `PermissionManager.check_granted()` defaults to `consume=True`, the wrapper's call consumed the only unit of the grant; the second call inside `fs_delete_impl` found no remaining grant and raised `PermissionRequiredError` uncaught, surfacing as `Error executing tool fs_delete: Access to '...' needs delete permission` in the server log instead of the graceful `permission_required` response the wrapper is supposed to produce on denial.
- **Fix**: `fs_delete_impl` now calls `security.resolve_and_validate(path)` without the `operation` argument, matching the existing convention already used by `fs_write_impl`, `fs_move_impl`, and `fs_batch_impl` — the wrapper (`fs_delete()`) is the single point where the `"delete"` operation is checked and the grant consumed; `_impl` functions only use `resolve_and_validate()` for path resolution/existence checks, never to re-check permissions.

### Notes
- No changes to `security.py` or `permissions.py`. The `consume=True` default in `check_granted()` and the "wrapper checks, impl resolves without operation" convention it depends on remain undocumented as an explicit rule — see `AGENTS.md` Gotchas.

## [1.4.5] — 2026-07-03

### Security audit findings and fixes
Full audit covering command injection, script execution, and permission bypass surfaces. Six findings identified and fixed in this release.

1. **CRITICAL — Command whitelist bypass via shell operator chaining**: `is_command_allowed()` previously validated only the first word of the *entire* command string. Any command containing `; | & < > `` or $()` fell back to real shell execution (`powershell -Command "<full string>"`), which interprets every chained segment — none of which were re-validated against the whitelist. Example verified against the live config: `git status; Copy-Item C:\Users\User\.ssh\id_rsa C:\Users\User\Desktop\x.txt` passed the whitelist (first word "git") and executed in full. **Fix**: added `split_command_segments()` (`shell_resolver.py`) to split a command on shell operators outside quotes; `is_command_allowed()` now validates every segment's first word against `allow_prefix`, not just the first one.
2. **CRITICAL — `sh_script` documented as read-only but not enforced**: `AGENTS.md` claimed scripts were "strictly limited to non-modifying actions", but `sh_script_impl` only checked `script[:100]` against the same whitelist as `sh_exec` — no real read-only restriction existed. **Fix**: new `CommandPolicy.readonly_prefix` (separate, stricter list than `allow_prefix`) and `is_script_readonly()`, which validates every non-empty, non-comment line of the script. A single non-matching line rejects the whole script before it touches disk.
3. **HIGH — `fs_delete` "no exceptions" bypassable via wildcard grants**: `fs_request_allow` creates tickets with `operation="*"`; `check_granted()` treated `"*"` as matching any operation, including `"delete"` — silently bypassing the `SINGLE`-only rule added for delete in the previous release. **Fix**: `check_granted()` now explicitly excludes `"delete"` from wildcard (`"*"`) matches, in both session and single grants — delete always requires its own explicit ticket.
4. **MEDIUM — Secret scanning didn't cover shell output**: `scan_text()` was only wired into `fs_read_impl`. A secret printed via `sh_exec("cat .env")` or `git log -p` produced no warning. **Fix**: extracted `format_findings()` as a shared helper (`secretscanner.py`) and wired it into all three result-construction paths in `sh_exec_impl`/`sh_script_impl` (native exec, shell fallback, script execution) — same warn-only behavior as `fs_read`.
5. **MEDIUM — `ssh_exec` had zero command validation**: unlike `sh_exec`, remote commands over SSH (disabled by default) were not checked against `allow_prefix`/`deny`/`require_flag_approval` at all. **Fix**: `ssh_exec_impl` now calls `is_command_allowed()` before executing, same as the local shell path.
6. **Documentation**: `AGENTS.md` rule #2 corrected to accurately describe `sh_script`'s actual (and now real) read-only enforcement.

### Added
- **`fs_delete`** (Layer 1, 18th filesystem tool): deletes a single file. Does not support directories or recursion — returns an explicit error if the target is a directory, by design (YAGNI: no batch/recursive delete until an actual need is identified).
- **`operation="delete"` is isolated from `"write"`**: an existing `write` session grant on a path does **not** grant `delete` on that same path — verified, not just assumed.
- **`delete` tickets are always forced to `SINGLE` grant**, regardless of the level requested via `fs_approve`: `PermissionManager.approve()` downgrades any `session`/`permanent` request to `single` when `ticket.operation == "delete"`, and states this explicitly in the returned message.
- **`security.commands.readonly_prefix`**: new config list (separate from `allow_prefix`) of exact read-only command prefixes (`git status`, `git log`, `ls`, `dir`, `docker ps`, `npm list`, `dotnet --version`, etc.), used exclusively by `sh_script`'s new per-line validation.

### Changed
- **`~/.personal-mcp/config.json` → `security.commands.allow_prefix`**: added `dotnet`, `node`, `pnpm`, `flutter` to support .NET Core, direct Node script execution, pnpm-based projects, and Flutter mobile development. (Applied 2026-07-03; not documented at the time — backfilled here.)

## [1.4.4] — 2026-07-02

### Fixed
- **Audit log never recorded real tool invocations (H1)**: `server.py` assigned `app.call_tool = wrapped_call_tool` *after* `FastMCP.__init__()` had already registered the original `self.call_tool` with the low-level MCP server via a closure captured at decoration time (`FastMCP._setup_handlers()` → `self._mcp_server.call_tool(validate_input=False)(self.call_tool)`). Reassigning the instance attribute afterwards had no effect on that closure, so no real client invocation ever reached the wrapper — `mcp_audit_log` reported 0 operations and `~/.personal-mcp/data/audit.json` was never created despite active shell/filesystem usage. Confirmed by direct inspection of `mcp/server/fastmcp/server.py` (installed package) and by empirical evidence during a diagnostic session (~20 real tool calls, only the tool-internal `mcp_benchmark` entry appeared in the audit log).
- **Fix — `AuditedFastMCP(FastMCP)`**: replaced the monkey-patch with a subclass that overrides `call_tool()` as a real instance method, matching `FastMCP.call_tool(self, name: str, arguments: dict[str, Any])`. `_setup_handlers()` resolves `self.call_tool` via the instance's class (MRO) at the moment it runs inside `super().__init__()`, so the override is picked up correctly for every request — no per-tool changes needed in the 6 layers.
- Removed unused `from functools import wraps` import in `server.py`.

### Notes
- Same investigation also reviewed a burst of ~27 server restarts (2026-07-02 22:43–22:47) and stale entries in `.pytest_cache/lastfailed` referencing tests since renamed/consolidated. Both were downgraded to low severity: file-modification timestamps show an active refactor session in progress at that time, not evidence of a crash-loop or a real regression. No code change was made for either; `pytest tests/ -v` should be re-run to refresh the stale cache when convenient.
- **Verified 2026-07-02**: `pytest tests/ -v` run directly in terminal (outside the MCP tool channel, which had become unresponsive during a prior attempt) — **257/257 passed in 51.49s**. `TestServerHandshake` exercises full server startup through `AuditedFastMCP`, confirming the fix doesn't break the existing contract. The stale-cache concern above is now fully resolved by this clean run.

## [1.4.3] — 2026-07-02

### Changed
- **`fs_request_allow` now creates pending tickets instead of granting directly**: Previously `fs_request_allow` bypassed the ticket system via `grant_direct()`, which contradicted HITL principles. Now it creates a pending ticket through `request_permission()`, requiring explicit `fs_approve` confirmation before access is granted. This makes the pre-authorize flow consistent with the ticket-based approval workflow used by `fs_write` and `fs_edit`.
- **Updated README**: `fs_request_allow` description and HITL section reflect the new pending→approve flow. Test count updated to 257.
- **257 tests** (all pass, up from 255).

## [1.4.2] — 2026-07-02

### Added
- **#4 — Rate limiting per-operation**: Sliding window rate limiter moved from `server.py` into `SecurityValidator._check_rate_limit()`. Applied independently per operation type (read/write) inside `validate_tool_path()`, not globally. Disabled when `rate_limit_commands_per_minute` is 0. 5 new tests.
- **#5 — Secret scanning** (`src/secretscanner.py`): New module with 12 regex patterns for common secrets (GitHub tokens, AWS keys, private keys, JWT, Slack tokens, DB connection strings, etc.). Integrated into `fs_read_impl()` — warns on detection, never blocks. Gated by `SecurityConfig.secret_scanning_enabled` (default: true). 15 new tests.

### Changed
- **Server startup simplified**: Removed `RateLimitError` class, `deque` import, and rate limiting logic from `wrapped_call_tool()` in `server.py`. Rate limiting now lives entirely in `SecurityValidator`.
- **`validate_tool_path()`**: Now calls `_check_rate_limit(operation)` before path validation. Rate limit exceeded returns an error string, consistent with all other validation errors.
- **`SecurityConfig`**: Added `secret_scanning_enabled: bool = True` field.
- **255 tests** (all pass, up from 235).

## [1.4.1] — 2026-07-02

### Changed
- **Relaxed read security model (Option C)**: Read operations in `paths_allow` now pass directly without requiring a grant ticket. Write operations still require explicit grant (session/single/permanent). This restores compatibility with AGENTS.md rule #3 ("No tickets on hot path") for reads while maintaining HITL security for writes.
- **Permanent grants**: `check_granted()` now recognizes paths added via permanent grants for write operations. Reads are auto-allowed by `resolve_and_validate()`.
- **Updated 20 tests** to reflect the new read-vs-write security boundary. Write-only grant tests now verify write behavior instead of read behavior.
- **Permanent grants removed from tool reach**: `fs_approve` and `fs_request_allow` no longer accept `level="permanent"`. Permanent grants must be configured manually in `~/.personal-mcp/config.json`. Single and session grants remain fully functional via tools — defense-in-depth against client-side config failures.

### Fixed
- **KeyError in `check_granted()`**: Resolves operation key before deletion in `_single_grants` consumption path. Single grants with `"read"` key no longer crash when the caller passes a different operation name.

## [1.4.0] — 2026-07-01

### Added
- **Structured Logging System** (`src/log.py`): New logging infrastructure with `RotatingFileHandler`, log levels (INFO, DEBUG, WARN, ERROR), and precise operation timing using `timed()` context manager.
- **Log Inspection Tool** (`mcp_log`): New tool to retrieve and filter server logs directly from the MCP interface.
- **Sensitive Data Sanitization**: Recursive scrubbing of sensitive keys (`password`, `token`, `secret`, etc.) in all server logs to prevent information leakage.
- **Interactive Path Configurator** (`configure_paths.py`): CLI utility to manage `paths_allow` without manual JSON editing.
- **Configuration Template**: `config.demo.json` added as a secure reference for new users.

### Changed
- **Hard-Lock Security Model**: 
  - **Absolute Path Lockdown**: Paths outside `paths_allow` or `data_dir` are now strictly denied immediately. No dynamic tickets can bypass this lock.
  - **Strict Command Whitelist**: Replaced the blocklist model with a mandatory whitelist (`allow_prefix`). Only explicitly approved command prefixes (e.g., `git`, `npm`, `python`) can be executed.
- **Human-in-the-Loop (HITL) Enforcement**: All read, write, and execute operations now require explicit user approval via tickets, regardless of whether the path is in the allowlist. *(Relajado en v1.4.1: reads en `paths_allow` pasan sin ticket)*
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
