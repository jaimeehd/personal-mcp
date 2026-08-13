# personal-mcp — AGENTS.md

> ⚠️ **LEE ESTO PRIMERO SI VAS A TOCAR `config.json`:**
> El `config.json` en la raíz de este repo es
> **solo un espejo de solo lectura**. NO lo edites pensando que cambia algo — no lo
> hace. El único config real que carga el servidor está en
> `~/.personal-mcp/config.json` (ver `AppConfig.default_path()` en `src/config.py`).
> Para actualizar el espejo tras editar el oficial, ejecuta `sync-config.ps1` desde
> la raíz del repo. Explicación completa en `CONFIG-GUIA.md`.

> ⚠️ **SANITIZAR ANTES DE ACTUALIZAR EL REPO — OBLIGATORIO (regla del dueño, 2026-08-13):**
> - El repo es **público** en GitHub. Todo `git push` publica contenido permanente que cualquiera puede ver.
> - **Antes de CADA `git add` + `git commit` + `git push`, correr el sweep de sanitización** y exigir **cero coincidencias fuera de AGENTS.md** (este bloque contiene la regla misma y los tokens):
>   `git grep -nE "C:\\\\Users\\\\User|C:\\\\Repos|HikBioAccess|BookStore|VisorCamara|atril|doc-pipeline|lauris|ingesoft|Bitacora|ant\\.dir\\.ant" -- . ':!AGENTS.md'`
> - Si el sweep encuentra algo, reemplazar con los placeholders estándar (`usuario`, `C:\Users\usuario\Repos`, `MiProyecto` — en CONFIG-GUIA.md: `C:\Users\TuUsuario\Repos`) **antes** de commitear, nunca después. Un commit ya pusheado queda para siempre en el historial remoto.
> - Incidente real 2026-08-13: la raíz de repos local y la carpeta `.ssh` del usuario llegaron al remoto público vía CHANGELOG.md y AGENTS.md. Corregido doble: hacia adelante (placeholders en docs) y hacia atrás (historial reescrito como único commit raíz sanitizado `2dc4817`, force-push; los 6 commits anteriores salieron de `main`). La reescritura fue aprobada explícitamente por el dueño. Lección: correr el sweep ANTES de cada push, no solo antes de cada commit — el primer `git push` de la corrección casi repite la fuga en el historial.

> ⚠️ **HISTORIAL GIT — CRÍTICO, NO TOCAR:**
> - `main` es el historial público del repo (1 commit raíz, sanitizado). Todo trabajo
>   nuevo va en `main`.
> - La rama local `historico` contiene los 65 commits previos del proyecto, con datos
>   personales y de configuración real. **Es solo local y nunca debe pushearse.**
> - **NUNCA ejecutar `git gc --prune=now` ni `git prune`** en este repo, ni borrar la
>   rama `historico`, ni los tags locales `v1.4.14`/`v1.4.33` (ni `feat/linux-support`,
>   también local-only) — todo eso destruiría el historial completo que se conserva a
>   propósito en esta máquina.
> - Para cualquier experimento de reescritura de historial, trabajar sobre una copia
>   (`git branch respaldo historico`), nunca contra `historico` misma.

## Arranque rápido
```powershell
# ejecutar desde la raíz del repo (la carpeta que contiene .venv/)
.\.venv\Scripts\python -m pytest tests/ -v       # 475 tests, verificado 2026-08-12 (0 fallidos). 1 skipped (test no-Windows, esperado en este SO).
.\.venv\Scripts\python -m src.server              # modo stdio para Claude Desktop
.\install.ps1                                     # registrar con Claude Desktop (crea el venv automáticamente)
.\sync-config.ps1                                 # refrescar el espejo de solo lectura config.json desde ~/.personal-mcp/config.json
```

## Journal — memoria de operación
Convención obligatoria: **cerrar cada sesión con `journal_add` de 1–3 líneas** (qué se hizo,
decisión clave, tags). Complementa a CHANGELOG (evolución del código) con la historia del
sistema/operación (config, limpiezas, diagnósticos, decisiones sin versión). El archivo vive
en `~/.personal-mcp/data/journal/journal.jsonl` y se crea solo al primer uso — no agregar
entradas retrospectivas salvo pedido explícito.

## Arquitectura — 6 capas hexagonales, 66 tools (62 activas — las 4 de SSH deshabilitadas por defecto)
| Capa | Archivo | Tools | Frontera de seguridad |
|------|---------|-------|------------------------|
| 1 Filesystem | `layer1_filesystem.py` | 25 | `resolve_and_validate()` en cada ruta; `fs_extract` verifica contención de rutas contra zip slip |
| 2 Shell | `layer2_shell.py` + `shell_resolver.py` | 13 | lista de denegación de comandos + escaneo de rutas + multi-shell (powershell/pwsh/cmd/bash); `sh_spawn` además exige ticket propio de `execute` |
| 3 SSH | `layer3_ssh.py` | 4 | deshabilitado por defecto (`ssh.enabled: false`) |
| 4 Personal | `layer4_personal.py` | 9 | diario, notas, escaneo de proyectos, estado git multi-repo |
| 5 Health | `layer5_health.py` | 9 | diagnóstico, auditoría, benchmark, log tail (`mcp_log`) |
| 6 Permissions | `layer6_permissions.py` | 6 | flujo de aprobación basado en tickets |

- Cada tool tiene una función `_impl` async independiente (testeable sin FastMCP)
- Los closures en `register_*()` envuelven `_impl` con verificaciones de seguridad/permisos
- `sys.path.insert(0, ...)` al inicio de `server.py` y `conftest.py` — ejecutar siempre desde la raíz del repo
- **Layer 4 completa es condicional a `config.journal.enabled`**: si es `false`, `register_personal_tools()` retorna inmediatamente y las 9 tools del layer — incluyendo `project_scan`, `project_find` y `project_git_status` — no se registran. El acoplamiento es total por diseño actual; no hay forma de tener `project_scan` sin el journal habilitado.
- **`fs_find_duplicates` (Layer 1, v1.4.42)**: búsqueda de duplicados exactos por contenido (SHA256) dentro de un `path`, a diferencia de buscar por patrón de nombre. Diseño de dos fases sin límite de cantidad ni tamaño de archivo (decisión explícita, 2026-07-31): fase 1 agrupa por tamaño exacto en bytes (`stat()`, prácticamente gratis — medido en 240ms para 232 archivos reales); fase 2 solo calcula hash dentro de los grupos que ya comparten tamaño con al menos otro archivo. Un archivo de tamaño único, por grande que sea, nunca se hashea — así se evita tanto el coste de hashear innecesariamente como el error de excluir archivos grandes que es justamente lo que se busca auditar. Parámetro `extensions` acepta `".pdf"` o `"pdf"` indistintamente (normalización case-insensitive). Solo lectura, no borra nada — deliberadamente separada de `fs_delete_batch`.
- **`project_git_status` (Layer 4, v1.4.43, `path` opcional desde v1.4.48)**: estado de git para los repos encontrados bajo `paths_allow`, o bajo un `path` puntual si se pasa uno (validado con `security.resolve_and_validate()`, mismo mecanismo que `project_scan`/`project_find`). Descubrimiento vía `os.walk()` con poda de directorios (`node_modules`, `.venv`, `AppData`, etc.) — no `Path.rglob`, que no permite saltar subárboles completos una vez que entra. Sin límite de cantidad de repos, mismo principio que `fs_find_duplicates`. Reutiliza `_git_project_info()` (ya usada por `project_scan`), extendida con `ahead`/`behind` contra el upstream — `None` en esos campos significa "sin upstream configurado", distinto de `0` ("sincronizado"). **Guard v1.4.48**: si se omite `path` y alguna raíz de `paths_allow` es una raíz de disco completa (`_is_filesystem_root()`), no escanea — devuelve un mensaje pidiendo un `path` puntual, en vez de colgarse recorriendo todo el disco (incidente real: 4+ min de timeout con `paths_allow=["C:\\"]`, ver CHANGELOG 1.4.48). Las llamadas git por repo siguen siendo secuenciales, no paralelizadas — deuda conocida desde v1.4.11, sin resolver todavía. Esta es la primera de cuatro tools nuevas agregadas en la misma tanda (las tres siguientes abajo).
- **`fs_disk_usage` (Layer 1, v1.4.44)**: agrupa el tamaño de todos los archivos bajo un `path` por carpeta ancestro a `depth` niveles, devuelve las `top_n` que más pesan. Complementa a `fs_find_duplicates` (esa responde "qué está repetido", esta responde "qué carpeta pesa más"). Un solo `os.walk()` sobre todo el árbol, atribuyendo cada archivo a su ancestro correspondiente en un solo pase — evita recorrer subárboles compartidos una vez por carpeta hermana. Sin límite de cantidad de carpetas ni de archivos escaneados, mismo principio que las dos anteriores; solo la salida (`top_n`) se trunca. Segunda de cuatro de la misma tanda.
- **`sh_spawn`/`sh_spawn_read`/`sh_spawn_kill`/`sh_spawn_list` (Layer 2, v1.4.45)**: procesos de larga duración en background (dev servers, watchers). Desbloqueada tras resolver el problema de huérfanos entre reinicios — ver sección dedicada más abajo. Tercera de cuatro de la misma tanda.
- **`fs_compress`/`fs_extract` (Layer 1, v1.4.46)**: crear/descomprimir zips. `fs_extract` verifica explícitamente, con `Path.relative_to()`, que cada miembro del zip caiga dentro de `output_dir` antes de escribirlo — protección contra zip slip (CVE-2007-4559-style), sin confiar en la protección de `zipfile` de la librería estándar por sí sola. Miembros que fallan la verificación se omiten (no se renombran, no se truncan) y se reportan en la respuesta. Cuarta y última de la tanda.
- **`fs_delete_directory` (Layer 1, v1.4.47)**: borrado recursivo de carpetas — gap real encontrado en sesión, no hipotético (`fs_delete`/`fs_delete_batch` rechazan directorios explícitamente, y hasta esta versión no había alternativa). Antes de mostrar el ticket, cuenta archivos y tamaño recursivamente (solo lectura, sin ticket) y lo muestra junto con la confirmación — mismo tipo de preview que el diálogo de Windows al borrar una carpeta.
- **Layer 2 nunca tuvo 10 tools — la tabla decía 10 por un error de doc introducido en 2026-07-25** (commit `2784539`, la sesión anterior de "corregir discrepancias AGENTS.md vs código"): esa sesión subió Layer 2 de 9→10 al mismo tiempo que corregía el total general (56→57), pero el código en ese mismo commit ya tenía 9 tools — las mismas de siempre (`sh_exec`, `sh_session_start/list/send/read/interrupt/close`, `sh_script`, `sh_history`). Nunca existió una décima tool ni se eliminó ninguna; fue un desliz aritmético al mover dos números a la vez. Verificado el 2026-08-01 contando `@mcp.tool` tanto en el código actual como en el código histórico de ese commit — 9 en ambos casos. Lección: al corregir un total agregado, verificar cada fila por separado, no solo que la suma final "se vea bien".

## Reglas de seguridad (no violar)
1. **Todas las rutas** pasan por `security.resolve_and_validate()`. Las operaciones de lectura en `paths_allow` o `data_dir` pasan directamente. Las operaciones de escritura en `paths_allow` requieren grant explícito (session/single/permanent) vía `check_granted()`. Las rutas fuera de ambos lanzan `PathNotAllowedError`.
2. **Comandos de shell** validados mediante una whitelist estricta definida en `config.security.commands.allow_prefix`. Los comandos que no coinciden con la whitelist o están explícitamente denegados son bloqueados.
   - ✅ **`sh_script` es genuinamente de solo lectura, aplicado segmento por segmento**: `CommandPolicy.is_script_readonly()` divide CADA línea no vacía y no comentada con `split_command_segments()` y valida CADA segmento contra `security.commands.readonly_prefix` (una lista separada y más estricta que `allow_prefix`). Además rechaza `$()`/backticks en comillas dobles (C-1/C-2, auditoría 2026-08-11, v1.4.64). Una sola línea con un operador inline (`echo hi; Remove-Item ...`) o con un segmento fuera de la whitelist rechaza el script completo antes de que se escriba a disco o se ejecute. (Historia: 2026-07-03 pasó de "primeros 100 caracteres" a "startswith por línea"; 2026-08-11 pasó de "startswith por línea" a "segmento por segmento", porque el startswith dejaba pasar operadores inline.)
   - ✅ **Cada segmento de un comando encadenado se valida independientemente, incluso a través de saltos de línea**: `split_command_segments()` (`shell_resolver.py`) divide en `| ; & < > `` $( y \n` antes de verificar la primera palabra de cada segmento contra `allow_prefix`. Hasta 2026-07-04 el splitter no trataba `\n` como separador, por lo que un comando como `"echo hola\nWrite-Host 'INYECTADO'"` se validaba solo contra el primer segmento (`echo`, en whitelist) mientras la segunda instrucción después del salto de línea se ejecutaba sin verificación — PowerShell/cmd/bash tratan un `\n` literal dentro de un argumento `-Command`/`-c` como separador de instrucciones. Corregido en v1.4.9 (`INJ-01`, CRÍTICO). Cualquier cambio futuro en el parseo de comandos debe mantener `\n` en `_SHELL_OPERATORS_RE` y en el conjunto de separadores de `split_command_segments()` — eliminarlo reabre silenciosamente este mismo bypass.
3. **Sin tickets en el hot path**: `validate_tool_path()` devuelve `None` para lecturas permitidas, un payload JSON `permission_required` para escrituras bloqueadas, o un string de error para rutas estrictamente denegadas (fuera de `paths_allow`/`data_dir`).
4. El prefijo `working_dir` se resuelve desde `shell_info.workdir_prefix` (por shell: `Set-Location`, `cd /d`, `cd`). **El quoting dentro de ese prefijo debe escaparse por shell, no con un estilo hardcodeado**: `_escape_workdir(working_dir, shell_name)` (`layer2_shell.py`) elige el escape de comillas correcto para el shell resuelto (`` `" `` para powershell/pwsh, `""` para cmd, `\"` para bash). Hasta 2026-07-04 el escape de PowerShell se aplicaba incondicionalmente sin importar el shell destino — un `working_dir` con una `"` literal podía escapar del segmento entrecomillado en `cmd`/`bash` e inyectar más sintaxis de shell. Corregido en v1.4.9 (`INJ-02`, ALTO). **Desde v1.4.64 (C-3, auditoría 2026-08-11)** además escapa los metadatos de sustitución por shell (`$`, backtick; `%`/`^` en cmd) — un `working_dir` con `$(...)` ya no se expande en el prefijo.
5. Los comandos de shell se escanean en busca de rutas absolutas (`C:\...`, `C:/...`) vía `security.extract_absolute_paths()`
6. `check_granted()` ahora usa `Dict[str, Set[str]]` — los grants son por operación, "read" != "write"
7. **Audit log registra BLOCKED (v1.4.61)**: operaciones bloqueadas por tickets se registran como `BLOCKED` en el audit log (antes `OK`). Nuevo metodo `_is_permission_blocked()` distingue bloqueo por tickets (`BLOCKED`) de falla semantica (`FAILED`). `_SEMANTIC_FAILURE_TOOLS` cubre todas las tools destructivas (fs_write, fs_edit, fs_delete, fs_delete_directory, fs_delete_batch, fs_move, fs_create_directory, fs_snapshot, fs_compress, fs_extract, fs_batch, sh_exec, sh_script, sh_session_send, sh_spawn).
8. **`fs_delete`** usa `operation="delete"`, completamente aislado de `"read"`/`"write"` — un grant de sesión de escritura existente sobre una ruta NO autoriza delete sobre ella. `PermissionManager.approve()` fuerza los tickets de delete a `SINGLE` sin importar el nivel solicitado vía `fs_approve` — no son posibles grants de sesión ni permanentes para delete, por diseño (sin excepciones). `fs_delete` solo soporta archivos individuales, nunca directorios/recursión.
9. **El wrapper valida, `_impl` nunca re-verifica permisos**: cada closure de `register_filesystem_tools()` llama a `security.validate_tool_path(path, <operación_real>)` antes de invocar su `_impl`. Las funciones `_impl` llaman a `security.resolve_and_validate(path)` **sin** pasar `operation` — el default (`"read"`) omite `check_granted()` completamente, así que la resolución de ruta no re-consume un grant ya gastado por el wrapper. `fs_delete_impl` rompió esta convención hasta 2026-07-04 (ver CHANGELOG 1.4.6): pasaba `"delete"` explícitamente, causando una segunda llamada a `check_granted()` que consumía el mismo grant `SINGLE` dos veces en una misma solicitud, sin ser detectado, manifestándose como una excepción cruda en vez de una respuesta `permission_required`. Cualquier nuevo `_impl` NO debe pasar la operación real a su propia llamada a `resolve_and_validate()` — ese es el trabajo del wrapper, exactamente una vez.
10. **`fs_approve` gate de confirmación (HMAC) — implementado en v1.4.14**: `fs_approve` ahora exige un `confirm_code` obligatorio, verificado con `hmac.compare_digest()` contra un código generado por `PermissionManager` en el momento del `request()`. La clave secreta (`_confirm_secret`, 32 bytes vía `secrets.token_bytes()`) se genera en memoria al construir cada `PermissionManager` y nunca se persiste a disco ni se expone por ningún tool — es lo único que impide que un agente adivine o derive el código. El código (`_generate_confirm_code()`, 6 dígitos derivados de un HMAC-SHA256 del `ticket_id`) se muestra **solo** vía `src/confirm_popup.py::show_confirmation_code()` — un `MessageBoxW` nativo de Windows, lanzado en un hilo daemon separado para no bloquear el event loop de asyncio del servidor mientras el usuario no está frente a la pantalla. Este es el único canal donde el código es visible; no se devuelve nunca en la respuesta de ningún tool MCP (`fs_request_allow`, `security_pending`, etc.) — si en el futuro alguien lo expone ahí "para depurar", se reabre exactamente el gap que este mecanismo cierra. `show_confirmation_code()` se desactiva bajo pytest (`PYTEST_CURRENT_TEST` en el entorno) para no bloquear la suite con popups reales. **Desde v1.4.67 (M-H3)**: el fallback de Linux sin display ya no imprime el código a stderr (podía filtrarse a `server.log`) — escribe a un archivo `0600` y reporta solo la ruta. En macOS, el mensaje se escapa para AppleScript (M-H4).
    - Reemplaza el diseño anterior documentado aquí (Token HMAC "pendiente de implementar", ver CHANGELOG 1.4.10/1.4.13). La alternativa `elicitation` evaluada en 1.4.13 sigue descartada (el cliente MCP conectado no declara esa capability) — revisar esa decisión solo si el cliente usado cambia.
    - ⚠️ **Regresión corregida en v1.4.28**: el mensaje que devuelve `request_permission()` para tickets de un solo recurso (`fs_write`/`fs_edit`/`fs_delete`/`fs_move`/`fs_create_directory`, y los tickets `execute`) nunca mencionaba `confirm_code` — decía solo `fs_approve(ticket_id=..., level='single')`, sin el parámetro obligatorio. La variante batch (`validate_tool_paths_batch`) y `fs_request_allow` sí lo tenían bien desde el principio; solo este path quedó desactualizado desde que se implementó el gate en v1.4.14. No era un hueco de seguridad (`PermissionManager.approve()` ya exigía el código igual), pero le decía al agente que llamara mal a la tool. Corregido — los tres mensajes (single/batch/request_allow) son ahora consistentes.
11. **No auto-aprobar tickets — ahora con control técnico real, no solo convención**: antes de v1.4.14 esto era solo una regla de comportamiento sin valor de seguridad (el agente podía ignorarla). Desde v1.4.14, `PermissionManager.approve()` rechaza cualquier intento sin `confirm_code` válido (`ok=False, "Invalid or missing confirmation code."`), y el código solo es visible en el popup nativo — un agente no tiene ningún canal para leerlo. La regla de convención se mantiene como buena práctica adicional, pero el gate real es la regla #10.
12. **Intérpretes de propósito general requieren ticket de `execute` antes de correr, además de estar en `allow_prefix`** (`config.security.commands.approval_required_prefix`, default `["python", "node", "bash"]`; `security.validate_shell_execution()`, v1.4.12). Esto NO contiene lo que el intérprete hace una vez aprobado — sigue siendo una caja negra frente a `paths_allow`/`deny` una vez que corre. Solo agrega una pausa antes de dejarlo arrancar, reutilizando el mismo flujo de tickets que `fs_approve` (`operation="execute"`, ya excluido del comodín `"*"`, igual que `"delete"`). Sujeto a la misma limitación de las reglas #9/#10: el agente puede aprobarse su propio ticket de `execute` igual que cualquier otro.
    - ⚠️ **Conectado solo en `sh_exec`/`sh_session_send`, NO en `sh_script`**: hoy es inofensivo porque `readonly_prefix` (regla #2) no incluye invocar un intérprete con un archivo (`python script.py`), así que `sh_script` no puede alcanzar un intérprete de propósito general de todas formas. Si en el futuro se agrega algo como `"python"` a `readonly_prefix`, `sh_script` lo ejecutaría sin pasar nunca por este control — quedaría silenciosamente sin cubrir. Cualquiera que toque `readonly_prefix` debe revisar esto primero.
    - ✅ **Escaneo AST pre-ejecución de scripts Python (v1.4.32)**: `validate_shell_execution()` analiza el árbol sintáctico (AST) con `script_analyzer.py` en scripts `.py` para detectar importaciones de red (`requests`, `socket`, `urllib`), funciones destructivas (`os.remove`, `shutil.rmtree`) o subprocesos dinámicos (`exec`, `eval`), anotando la solicitud de ticket con los riesgos detallados antes de requerir aprobación.
    - ✅ **Lista blanca remota SSH (`remote_allow_prefix`, v1.4.32)**: `ssh_exec_impl` valida los segmentos de comandos remotos contra `remote_allow_prefix` además de la lista blanca local.

13. **Conector MCP Filesystem genérico (oficial) — canal paralelo sin tickets (riesgo conocido, aceptado)**: si el cliente MCP tiene también el conector oficial `Filesystem` habilitado con este repo (o su carpeta padre) en sus directorios permitidos, ese conector escribe directo al disco — no pasa por `PermissionManager`, no genera tickets, no requiere `confirm_code`. El gate de la regla #10 solo protege las tools expuestas por *este* servidor (`fs_write`, `fs_edit`, etc. vía `layer1_filesystem.py`); no protege el repositorio en sí frente a cualquier otro conector con acceso de escritura al mismo path. No hay fix de código posible desde este repo — es una decisión de configuración del cliente MCP, fuera de su alcance. Usado deliberadamente en la práctica (v1.4.26, y en la sesión del 2026-07-19) cuando el propio dueño del repo lo pide explícitamente para evitar tickets repetidos en ediciones de documentación de bajo riesgo — sigue siendo el mismo bypass, la diferencia es que aquí es una decisión informada del dueño, no un descuido.
    - **Para enforcement real**: quitar este repo de los `allowed_directories` de la extensión Filesystem, o deshabilitarla. No es un fix de código — es configuración del cliente.


14. **`install.ps1` default `allow_prefix` endurecido (v1.4.18)**: el instalador tenía verbos de mutación de archivos (`remove-item`, `del`, `copy`, `move`, `mkdir`, `new-item`, etc.) en el `allow_prefix` por defecto de una instalación nueva — bypaseaban el sistema de tickets por completo en cualquier instalación fresca. Los 10 verbos fueron eliminados de la lista por defecto. El `~/.personal-mcp/config.json` real en uso tenía el mismo gap (`mkdir`/`rmdir`) ese mismo día — corregido en el config real (fuera del alcance de este repo), confirmado vía el espejo de solo lectura.

15. **`paths_allow` puede ampliarse hasta una raíz de disco completa (ej. `["C:\\"]`, v1.4.26)**: en un deployment real se configuró así, partiendo de un valor más acotado (`["C:\\Users\\usuario\\Repos"]`). Las operaciones de escritura/borrado NO se ven afectadas — siguen requiriendo grant explícito vía el flujo de tickets+HMAC sin importar el alcance de `paths_allow`; solo las lecturas sin ticket (`fs_read`, `fs_list`, `fs_search`, `fs_tree`, `fs_find`, `fs_info`) quedan sin restricción en todo el disco `C:` salvo por `paths_deny`. Con `paths_allow` así de amplio, `paths_deny` es el único control real que queda para lecturas — ver `config.json` (espejo) para la lista completa (`.ssh`, `.aws`, `.azure`, `.kube`, `.gnupg`, `.env*`, `*.pem`, `id_rsa*`, `id_ed25519*`, `AppData` con wildcard, credenciales de git/npm/pip, etc., ampliada en v1.4.26/v1.4.27). Explícitamente incompleta por diseño, no un gap: es una lista de patrones conocidos, no un mecanismo general — `scan_text()` (el scanner de secretos, activo desde v1.4.9) es el respaldo para contenido en ubicaciones que `paths_deny` no anticipó. **Antes de agregar cualquier `paths_allow` nuevo o ampliar el existente, revisa primero si `paths_deny` cubre lo que se está exponiendo** — el error de v1.4.26 (AppData sin wildcard, exact-match en vez de recursivo) pasó inadvertido durante semanas precisamente porque nadie lo verificó al momento de ampliar `paths_allow`.

## Módulos clave
- `src/log.py` — `configure()`, `get_logger()`, context manager `timed()`; `RotatingFileHandler` vía `logging` de stdlib. `logging.raiseExceptions = False` configurado en `configure()` desde v1.4.28 (fix de hipótesis, ver CHANGELOG 1.4.21 — no probado concluyentemente, bajo riesgo de todas formas). `scrub_sensitive_data()` (usada por `AuditedFastMCP.call_tool()` en `server.py` para las líneas `CALL`/`FAILED` de `server.log`) escanea el **valor** de cada argumento string con `secretscanner.scan_text()` desde v1.4.63, no solo el nombre de la clave — es el gemelo de `audit.py::AuditEntry._sanitize()` (que protege `audit.json`, arreglada antes en v1.4.58) para un destino distinto. Deliberadamente NO unificadas en un helper compartido — `log.py` es más base que `audit.py`, importar audit.py ahí invertiría esa dependencia sin necesidad real; duplicación de ~15 líneas aceptada a propósito, mismo criterio ya usado para `journal_add`/`note_quick` (ver más abajo).
- `src/shell_resolver.py` — dataclass `ShellInfo`, `SHELL_REGISTRY` (4 shells), `resolve_shell()`, `_find_executable()`, `_find_git_bash()`. `_find_git_bash()` ejecuta un `subprocess.run(timeout=5)` **síncrono** — cualquier llamador debe envolver `resolve_shell()` en `asyncio.to_thread()` al llamar desde un `async def` (regresión corregida en v1.4.28 en `sh_exec`/`sh_script`/`sh_session_start`; si se agrega un nuevo punto de llamada, verificar esto primero). shell_subprocess_env() devuelve un env con PATHEXT corregido para spawns que invocan un shell real (fix de PATHEXT roto); retorna None en no-Windows.
- `src/config.py:LogConfig` — `level`, `max_bytes`, `backup_count` para logging estructurado
- `src/config.py:ShellConfig` — `default_shell` (string), `shell_map` (dict para rutas personalizadas)
- `src/layers/layer2_shell.py` — `MAX_CAPTURE_BYTES=1MiB`, `_truncate()`. Limpieza de procesos delegada a `src/oslayer/process.py` desde v1.4.33 (`kill_process_tree` vía psutil, `reap_after_kill` — debe llamarse después de cada `kill_process_tree()` o los handles se fugan; ver CHANGELOG 1.4.19/1.4.20/1.4.33). Spawning centralizado en `run_subprocess()` (helper que aplica `stdin=DEVNULL` + `env=shell_subprocess_env()` por defecto, ver 1.4.62).
- **`src/oslayer/system.py:uptime_seconds()`**: devuelve `time.time() - psutil.boot_time()` — el uptime del **sistema operativo desde el último boot**, NO el tiempo de vida del proceso `personal-mcp`. El campo `uptime` que reporta `health_check` refleja esto. No sirve para verificar si el servidor MCP fue reiniciado — solo si la máquina lo fue. Para eso, comparar el timestamp de la línea `Server starting pid=...` más reciente en `server.log`, o verificar directamente si una tool agregada en el código nuevo aparece en el tool-list (ver siguiente punto sobre `server.log` compartido).

## Peculiaridades de PermissionManager
- `GrantLevel`: `SINGLE`, `SESSION`, `PERMANENT`
- `_session_grants` cambió de `Set[str]` a `Dict[str, Set[str]]` — almacena pares (ruta, operación)
- `_single_grants: Dict[str, Dict[str, int]]` — grants de un solo uso, consumidos en el primer acceso. El comodín `"*"` coincide con cualquier operación.
- `check_granted(resource, operation)` verifica que la operación coincida (o "*"); auto-otorga solo rutas en `data_dir` (no `paths_allow` — las lecturas son manejadas por `resolve_and_validate()` directamente)
- Los grants permanentes se agregan a `paths_allow`, lo que auto-permite lecturas; las escrituras siguen necesitando grant de sesión/single
- Los tickets expiran después de 300s
- **Rate-limiting de confirm_code (v1.4.61)**: _MAX_APPROVE_ATTEMPTS = 10. Tras 10 intentos fallidos de confirm_code, el ticket se auto-deniega. Sin esto, un agente podria hacer fuerza bruta sobre el codigo de 6 digitos dentro del TTL de 300s. Contador es por-proceso (cada proceso tiene su propio HMAC secret).
- **`security_revoke(resource, operation=None)`**: si `operation` se omite, revoca TODOS los grants del recurso. Pasar `operation` (ej. `"write"`) revoca solo esa operación sin afectar otras grants sobre la misma ruta. Preferir siempre pasar `operation` cuando se conoce.
- `config.save()` escribe en config_path — los tests configuran `config_path` en una ruta temporal
- **Tickets batch (desde v1.4.16)**: `PermissionTicket` tiene un campo opcional `resources: List[str]`; `request_batch()`/`approve()` vinculan un ticket/un `confirm_code` a una lista enumerada de rutas (`fs_delete_batch`). Forzado a `SINGLE` para delete, misma regla que delete de un solo archivo (#7). `validate_tool_paths_batch()` verifica cada ruta antes de consumir cualquier grant.
- **Persistencia de tickets pending (v1.4.41)**: los tickets `pending` se persisten como **metadatos** en `tickets.jsonl` (en `data_dir`) y se restauran al reiniciar el servidor con `restored=True`. El `confirm_code` se **regenera** con el secreto del proceso al restaurar — nunca se lee del disco; el secreto HMAC tampoco se persiste (regla #10 intacta). Si el agente aprueba un ticket restaurado con un código viejo pre-reinicio, `approve()` re-muestra el popup con el código nuevo. `request_batch()` hace dedup orden-insensible por operación+rutas, así que re-emitir el mismo `fs_delete_batch` tras un reinicio reutiliza el ticket restaurado en vez de crear duplicados. Antes de v1.4.41 un reinicio destruía los tickets y `fs_approve`/`fs_deny` sobre ids muertos se registraban como `OK` en el log (fallo silencioso); desde v1.4.41 el wrapper de `AuditedFastMCP` detecta esas fallas semánticas y las registra como `FAILED` con `success=False` en el audit log.

## Testing
- `asyncio_mode = "auto"` — los tests `async def` se ejecutan automáticamente (no se necesita marcador)
- Los tests importan `_impl` directamente (no a través de FastMCP) — este es el patrón esperado
- `conftest.py` provee: `temp_home` (tmp_path), `test_config`, `security`, `sample_file`, `sample_dir`
- `tests/test_shell_resolver.py` — 27 tests para resolución de shell, búsqueda de ejecutables, `shell_subprocess_env()` (PATHEXT)
- Siempre crear un `SecurityValidator` nuevo por test — `_resolved_allowed` cachea valores viejos
- El `ResourceWarning` sobre `_ProactorBasePipeTransport.__del__` es limpieza inofensiva de asyncio en Windows

## Gotchas
- **`config.json` en la raíz del repo es un espejo, no el config real** — editarlo no tiene efecto. El real está en `~/.personal-mcp/config.json`. Ver nota al inicio de este archivo y `CONFIG-GUIA.md`.
- **Historial local `historico` (no pushear, no prunear)**: el historial completo previo vive solo en la rama local `historico` (65 commits, con datos personales). Nunca pushearla y nunca correr `git gc --prune=now`/`git prune` sobre este repo — destruiría ese historial. Ver advertencia al inicio de este archivo.
- `Path.resolve()` en Windows normaliza mayúsculas/minúsculas (ej. `Temp` → `temp`) — usar el helper `self._resolve()` en PermissionManager
- El constructor de FastMCP 3.x solo acepta `name`
- **Interceptar cada llamada de tool (ej. para auditoría) requiere hacer subclase de FastMCP, no `app.call_tool = wrapper`**: `FastMCP._setup_handlers()` (llamado dentro de `FastMCP.__init__()`) hace `self._mcp_server.call_tool(validate_input=False)(self.call_tool)` — esto registra el método bound con el servidor MCP de bajo nivel mediante un closure en el momento en que `app = FastMCP(...)` se ejecuta, *antes* de que cualquier reasignación de atributos post-construcción pudiera tener efecto. Reasignar `app.call_tool` después es silenciosamente un no-op para invocaciones reales de clientes (bug confirmado en v1.4.3 y anteriores: `mcp_audit_log` se quedaba vacío y `audit.json` nunca se creaba a pesar de actividad real de tools — corregido en v1.4.4). Patrón correcto: hacer subclase de `FastMCP` y sobrescribir `call_tool()` como un método de instancia real (ver `AuditedFastMCP` en `server.py`) — Python resuelve `self.call_tool` por la clase de la instancia (MRO) en el momento en que `_setup_handlers()` se ejecuta, que es después de que `self` ya es la instancia de la subclase.
- `config.data_dir` sobrescrito en `server.py:32` a `~/.personal-mcp/data`
- `sh_script` escribe archivo temporal con extensión según el shell (`.ps1`/`.bat`/`.sh`) en `~/.personal-mcp/data/`
- `sh_session_start` devuelve error si el shell no soporta sesiones interactivas (cmd, bash tienen `session_args=[]`)
- **Cambio de shell**: `sh_exec`, `sh_script`, `sh_session_start` aceptan el parámetro opcional `shell` — se resuelve en runtime vía `ShellManager.resolve_shell()`
- La salida de shell se trunca a 1 MiB — se agrega un mensaje si fue truncada
- La limpieza por timeout usa `taskkill /pid /T /F` (recursivo, solo Windows)
- La capa SSH es opt-in — `ssh.enabled: false` por defecto
- **`server.log` es compartido entre TODOS los procesos `personal-mcp` que corran en la máquina, incluyendo instancias efímeras** (ej. una suite de `pytest`/smoke-test arranca y cierra un proceso nuevo por test, cada uno con su propio PID) — no solo el proceso interactivo de Claude Desktop. Verificado el 2026-07-31: se observaron líneas `Server starting pid=...` con PIDs distintos intercaladas cada 1-2 segundos en el mismo archivo. Implicación real: **los tickets y grants viven en memoria por-proceso** (ver "Peculiaridades de PermissionManager" arriba) — un ticket aprobado en un proceso NO es consumible desde otro, aunque ambos escriban al mismo log y parezca, por cercanía temporal en las líneas, que pertenecen a la misma sesión. Para reconstruir qué pasó a partir de `mcp_log`, hay que anclar cada entrada al `Server starting pid=...` más reciente que la precede, no asumir que el log completo pertenece a un único proceso lineal.
- **Instancias de Claude Desktop registradas con `"command": "python"` a secas corren el servidor con el Python del sistema, no con el venv** (incidente real 2026-08-13: instancias multi-cuenta lanzaban un `python.exe` fuera de `.venv\Scripts\`). El instalador (`install.ps1`) siempre escribe la ruta absoluta del venv cuando existe — si un `claude_desktop_config.json` dice `"command": "python"`, no fue escrito por `install.ps1` (o fue sobreescrito a mano). Diagnóstico rápido: comparar el `ExecutablePath` del proceso `python.exe` contra `.venv\Scripts\python.exe`. Fix: apuntar `command` a `C:\Users\usuario\Repos\.personal-mcp\.venv\Scripts\python.exe` (ver CHANGELOG 1.4.73).
- `import sys; sys.path.insert(0, ...)` requerido en cada punto de entrada para imports de `src.`
- Todas las funciones `_impl` aceptan `security` como parámetro — los closures lo vinculan en el momento del registro
- **Auditoría externa v1.4.9 (2026-07-04) — 3 hallazgos adicionales más allá de los dos ya incorporados en las reglas #2 y #4 arriba:**
  - **`ssh_exec` valida comandos solo en el host local `personal-mcp`, no en el host remoto al que se conecta la sesión SSH** (`INJ-03`, MEDIO). Un comando que pasa la verificación local de `allow_prefix` se reenvía textualmente y se ejecuta con los privilegios que tenga la cuenta remota — no existe enforcement equivalente remotamente. **Mitigado en v1.4.32**: se añadió `remote_allow_prefix` en `SSHConfig` (`config.py`) y validación por-segmento en `ssh_exec_impl` (`layer3_ssh.py:109-120`) contra esa lista blanca remota dedicada (default: `ls`, `cat`, `echo`, `pwd`, `git`, `uptime`, `whoami`, `uname`, `df`, `free`, `ps`, `top`). El warning explícito `[WARNING]` se mantiene como defensa en profundidad. La limitación fundamental persiste (no hay enforcement remoto real sin deployar wrapper en el host destino), pero el bypass sin validación local ya no existe. Actualmente inalcanzable en práctica: SSH está `enabled: false` por defecto en el deployment estándar.
  - **El escaneo de secretos no cubría `journal_add`/`note_quick`** (`INJ-04`, MEDIO). `scan_text()` estaba conectado en `fs_read_impl` y en las rutas de shell pero no en la Capa 4 — una credencial pegada en una entrada del diario o nota rápida se escribía a disco sin ninguna advertencia. Corregido vía `_scan_and_append()` en `layer4_personal.py` (deliberadamente no compartido con el helper equivalente de `layer2_shell.py` — marcado como deuda menor de DRY, no vale un import entre capas por ~6 líneas todavía).
  - **Inyección de log vía argumentos con saltos de línea** (`INJ-05`, BAJO). `logger.info("sh_exec command=%.200s ...", command, ...)` de `layer2_shell.py` interpolaba el comando crudo vía `%s` sin escape — un comando con `\n` podía falsificar una línea de log. Corregido vía `sanitize_log_value()` (`log.py`), aplicado en ambos puntos de log de `sh_exec`/`sh_script`.
  - Detalle completo y razonamiento a nivel PoC para los 5 hallazgos (incluyendo los dos ya incorporados arriba): entrada `[1.4.9]` en `CHANGELOG.md`.

## npm / pnpm run dev — flujo de ejecución y gate de aprobación

`npm` y `pnpm` están en `allow_prefix` — pasan la whitelist de comandos sin ticket.

Sin embargo, ambos lanzan Node internamente al ejecutar scripts como `run dev`.
`node` está en `approval_required_prefix` (default del código, no sobreescrito en el
config actual) → `sh_exec`/`sh_session_send` generan un ticket de `execute` antes de
que el proceso arranque.

**Flujo recomendado (Opción A — sin cambio de config):**
1. `sh_session_start(shell="powershell")` → obtén el `session_id`
2. `sh_session_send(session_id, "npm run dev", working_dir="C:\\Users\\usuario\\Repos\\TuProyecto")` (o `pnpm run dev`)
   — `cd` NO está en `allow_prefix` y sería bloqueado; usar `working_dir` es el único canal correcto
3. **No hay ticket de `execute`** — `npm`/`pnpm` no están en `approval_required_prefix` (solo `python`, `node`, `bash`);
   el gate no dispara porque el validador revisa el primer token del comando (`pnpm`/`npm`), no el intérprete
   que estos invocan internamente. Si se quiere cubrir este caso, agregar `npm` y `pnpm` a `approval_required_prefix`.
4. `sh_session_read(session_id)` para leer output cuando se necesite

⚠️ **Limitación conocida (verificada 2026-07-25):** PowerShell en modo sesión interactiva
(`-NoExit -Command -`) bufferiza stdout internamente y no lo flushea al pipe línea a línea.
`sh_session_read` devuelve `(no output)` aunque el proceso esté corriendo. El log del servidor
confirma que el comando se entrega (`OK 315ms`) pero el reader nunca recibe líneas.
Para dev servers de larga duración, arrancar desde la terminal propia es más confiable
que depender de `sh_session_read`. Ver idea diferida `sh_spawn` más abajo.

**Opción B (cambio de config):** eliminar `node` de `approval_required_prefix` en
`~/.personal-mcp/config.json` — elimina el gate para todo lo que arranque Node.
No recomendado si se ejecutan scripts arbitrarios además de comandos conocidos.

## sh_spawn — implementada (v1.4.45)

Procesos de larga duración en background (dev servers, watchers), con lectura
de output posterior sin que el proceso muera al cumplirse el timeout de `sh_exec`.

**Cuatro tools:** `sh_spawn(command, working_dir?, shell?)` → `spawn_id`;
`sh_spawn_read(spawn_id, n?)`; `sh_spawn_kill(spawn_id)`; `sh_spawn_list()`.

**Bloqueador que retrasó la implementación desde 2026-07-25 hasta 2026-08-02:**
en esta máquina es normal, no excepcional, tener varios procesos `personal-mcp`
corriendo en simultáneo (confirmado en vivo: 3 procesos para 3 ventanas/cuentas
distintas de Claude Desktop). Un proceso lanzado por `sh_spawn` en un servidor
que luego se reinicia (o coexiste con otro proceso efímero, ej. una corrida de
pytest) quedaría huérfano — corriendo, sin nadie que sepa de su PID.

**Diseño que lo desbloqueó — rastreo por `owner_pid`:** cada spawn se persiste
a `spawned_processes.jsonl` en `data_dir` (mismo patrón append-then-reconcile-
on-boot que `tickets.jsonl`, v1.4.41) junto con el PID del servidor que lo creó.
Al arrancar, un servidor nuevo solo actúa sobre un registro cuyo `owner_pid` está
**confirmado muerto** — si el dueño original sigue vivo, el registro se deja
intacto, aunque este proceso nuevo pueda ver el mismo archivo. Revisar solo "¿el
hijo sigue vivo?" no distinguiría "todavía en manos de un servidor hermano que
sigue corriendo" de "genuinamente huérfano". Los huérfanos se **reportan**
(`sh_spawn_list` los marca `"orphaned"`), nunca se matan automáticamente.

**Requisito de seguridad "excluido del wildcard `*`" resuelto sin tocar
`security.py`/`permissions.py`:** `sh_spawn` exige su propio ticket de
`execute` (`_check_spawn_permission()`, `layer2_shell.py`), reutilizando el
mismo mecanismo ya usado para `python`/`node`/`bash`. `check_granted()` ya
excluía `operation="execute"` de cualquier grant wildcard — el requisito se
cumple gratis.

**Ring buffer:** output acotado con `collections.deque(maxlen=500)` por
proceso — evita que un proceso ruidoso crezca en memoria sin límite solo por
leerse con poca frecuencia.

Detalle completo de diseño y tests: entrada `[1.4.45]` en `CHANGELOG.md`.

## Regla obligatoria antes de eliminar cualquier símbolo
Antes de eliminar una función, clase, método o constante:
1. Busca el nombre exacto del símbolo en src/ Y tests/ (no solo donde ya se sabe que se usa)
2. Pega el resultado de esa búsqueda explícitamente
3. Si aparece en un test, la eliminación requiere actualizar ese test en el mismo cambio,
   no como una tarea separada
