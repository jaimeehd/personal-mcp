# Plan de nuevas herramientas — personal-mcp

> ✅ **Plan cerrado el 2026-08-02** — los 4 ítems completados. Si estás
> retomando trabajo relacionado en otra sesión, este documento queda como
> referencia histórica del proceso de diseño (decisiones, bloqueadores
> encontrados y cómo se resolvieron), no como lista de pendientes.
>
> Iniciado 2026-08-01. Si estás retomando esto en otra sesión, leé este archivo
> antes de tocar código — evita el mismo problema que tuvimos hoy con trabajo
> paralelo sin coordinar (ver CHANGELOG 1.4.41, persistencia de tickets,
> construida por otra sesión en simultáneo sin que ninguna de las dos lo supiera).

## Orden de prioridad (mayor beneficio → menor)

| # | Tool | Beneficio | Riesgo | Estado |
|---|------|-----------|--------|--------|
| 1 | `project_git_status` | Alto — evidencia directa de la sesión del 2026-08-01 | Bajo | ✅ Completado (v1.4.43) |
| 2 | `fs_disk_usage` | Alto — complementa `fs_find_duplicates` | Bajo | ✅ Completado (v1.4.44) |
| 3 | `sh_spawn` | Medio — ya diseñado en `AGENTS.md` | Alto — resuelto vía `owner_pid`, ver diseño | ✅ Completado (v1.4.45) |
| 4 | `fs_compress`/`fs_extract` | Bajo — sin evidencia de necesidad real | Medio — zip slip, resuelto con `Path.relative_to()` | ✅ Completado (v1.4.46) |

## 1. `project_git_status`

**Decisión de diseño (2026-08-01, confirmada por el usuario):** descubrimiento
automático vía recorrido de `paths_allow` buscando carpetas `.git`, no una
lista fija en config. Trade-off aceptado explícitamente: más lento si
`paths_allow` es amplio (ej. `C:\` completo, como en la config real de este
equipo) a cambio de no requerir mantenimiento manual de una lista de repos.

**Diseño:**
- Reutiliza `_git_project_info()` (ya existe en `layer4_personal.py`, usada por
  `project_scan`), extendida para agregar `ahead`/`behind` contra el upstream
  — antes solo devolvía `branch` + `uncommitted_changes`.
- Nueva función `_discover_git_repos_sync()`: recorre cada raíz de
  `paths_allow` con `os.walk()` (poda de directorios en el propio recorrido,
  no `rglob` — permite saltar `node_modules`/`.venv`/etc. sin descender a
  ellos, mismo criterio ya usado en `_find_files_sync` para `project_find`).
- Sin límite artificial de cantidad de repos — mismo principio que
  `fs_find_duplicates` (2026-07-31): el costo real es de recorrido, no de
  cuántos resultados hay.
- Registrada en Layer 4, junto a `project_scan`/`project_find`.

**Estado:** ✅ Completado — v1.4.43, commit incluye implementación + 5 tests + docs
(README/AGENTS/CHANGELOG). Ver `layer4_personal.py::project_git_status_impl`.

## 2. `fs_disk_usage`

**Diseño:** tool de solo lectura en Layer 1. `fs_disk_usage(path, top_n=15, depth=1)`
— suma tamaños por subcarpeta a `depth` niveles, devuelve las `top_n` más pesadas.
No baja a nivel de archivo individual (para eso ya existe `fs_find_duplicates`
y `fs_list_with_sizes`).

**Estado:** ✅ Completado — v1.4.44. Ver `layer1_filesystem.py::fs_disk_usage_impl`.

## 3. `sh_spawn`

**Diseño original en `AGENTS.md`** (sección "Feature diferida"). Tres
requisitos de seguridad establecidos desde el inicio: registro de PIDs en
`data_dir`, ring buffer en la cola de output, exclusión explícita del
wildcard `"*"` en grants.

**Bloqueador encontrado el 2026-08-01, resuelto el 2026-08-02:** puede haber
múltiples procesos `personal-mcp` corriendo en paralelo (confirmado en vivo:
3 procesos para 3 ventanas/cuentas distintas de Claude Desktop). Un proceso
lanzado por `sh_spawn` en un servidor que luego se reinicia quedaría huérfano.

**Diseño que lo desbloqueó — rastreo por `owner_pid`:** cada spawn se persiste
a `spawned_processes.jsonl` en `data_dir` junto con el PID del servidor que lo
creó. Al arrancar, un servidor nuevo solo actúa sobre un registro cuyo
`owner_pid` está confirmado muerto — si el dueño sigue vivo, no se toca.
Huérfanos reales se reportan (`sh_spawn_list`, status `"orphaned"`), nunca se
matan automáticamente. El requisito del wildcard se resolvió gratis: `execute`
ya estaba excluido de los grants `"*"` en `PermissionManager.check_granted()`.

**Estado:** ✅ Completado — v1.4.45, 4 tools (`sh_spawn`/`sh_spawn_read`/
`sh_spawn_kill`/`sh_spawn_list`) + 15 tests, incluyendo los 3 tests centrales
de reconciliación de huérfanos. Ver `layer2_shell.py::SpawnManager`.

## 4. `fs_compress` / `fs_extract`

**Diseño:** `fs_compress(paths, output_path)` → zip. `fs_extract(zip_path, output_dir)` → unzip.

⛔ **Riesgo de diseño no trivial, identificado desde el inicio del plan:**
`fs_extract` es la única de las 4 que crea archivos cuyo contenido no se
controla de antemano — un zip puede contener rutas con `../` (zip slip,
CVE-2007-4559-style).

**Cómo se resolvió:** `_safe_extract_sync()` no confía en la protección de
`zipfile` de la librería estándar por sí sola (sus garantías han variado
entre versiones). Antes de escribir cada miembro, calcula la ruta de destino
resuelta y verifica con `Path.relative_to()` que caiga dentro de `output_dir`
— si no, `ValueError`, el miembro se **omite** (no se renombra, no se trunca)
y se reporta en la respuesta de la tool. `fs_extract` va por el flujo estándar
de Layer 1: un ticket de escritura sobre `output_dir`, mismo criterio que
cualquier otra operación que crea archivos dentro de un directorio aprobado.

**Estado:** ✅ Completado — v1.4.46, 8 tests incluyendo el test de seguridad
central (zip malicioso con miembro `../../escaped.txt`, verificando que el
archivo objetivo de la fuga nunca se crea). Ver
`layer1_filesystem.py::_safe_extract_sync`.
