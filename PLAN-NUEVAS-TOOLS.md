# Plan de nuevas herramientas — personal-mcp

> Iniciado 2026-08-01. Si estás retomando esto en otra sesión, leé este archivo
> antes de tocar código — evita el mismo problema que tuvimos hoy con trabajo
> paralelo sin coordinar (ver CHANGELOG 1.4.41, persistencia de tickets,
> construida por otra sesión en simultáneo sin que ninguna de las dos lo supiera).

## Orden de prioridad (mayor beneficio → menor)

| # | Tool | Beneficio | Riesgo | Estado |
|---|------|-----------|--------|--------|
| 1 | `project_git_status` | Alto — evidencia directa de la sesión del 2026-08-01 | Bajo | ✅ Completado (v1.4.43) |
| 2 | `fs_disk_usage` | Alto — complementa `fs_find_duplicates` | Bajo | ✅ Completado (v1.4.44) |
| 3 | `sh_spawn` | Medio — ya diseñado en `AGENTS.md` | Alto — huérfanos entre reinicios, ver nota | ⏳ Pendiente, bloqueado |
| 4 | `fs_compress`/`fs_extract` | Bajo — sin evidencia de necesidad real | Medio — zip slip | ⏳ Pendiente |

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

**Diseño ya documentado en `AGENTS.md`** (sección "Feature diferida"). Tres
requisitos de seguridad ya establecidos: registro de PIDs en `data_dir`, ring
buffer en la cola de output, exclusión explícita del wildcard `"*"` en grants.

⛔ **Bloqueador nuevo, encontrado el 2026-08-01, no estaba en el diseño original:**
puede haber múltiples procesos `personal-mcp` corriendo en paralelo (confirmado
hoy vía `server.log` compartido con PIDs distintos intercalados). Un proceso
lanzado por `sh_spawn` en un servidor que luego se reinicia quedaría huérfano
— corriendo, pero sin nadie que lo controle. Hay que resolver esto en el diseño
antes de implementar, no después.

**Estado:** no iniciado, diseño incompleto.

## 4. `fs_compress` / `fs_extract`

**Diseño:** `fs_compress(paths, output_path)` → zip. `fs_extract(zip_path, output_dir)` → unzip.

⛔ **Riesgo de diseño no trivial:** `fs_extract` es la única de las 4 que crea
archivos cuyo contenido no se controla de antemano — un zip puede contener
rutas con `../` (zip slip). Necesita validación explícita de que cada archivo
extraído cae dentro de `output_dir` antes de escribirlo.

**Estado:** no iniciado.
