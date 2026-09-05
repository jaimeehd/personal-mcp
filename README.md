# personal-mcp

Servidor MCP personalizado para orquestación de estaciones de trabajo Windows/Linux/macOS. Seguridad basada en listas blancas con aprobación HITL para escrituras, escaneo de secretos, rate limiting por operación, I/O completamente asíncrono, sesiones persistentes de shell.

## Arquitectura

```
6 capas, diseño hexagonal:
  Capa 1: Filesystem      — 27 tools (read, write, edit, edit-batch, write-batch, delete, delete-batch, delete-directory, list, tree, search, find, find-duplicates, disk-usage, info, diff, batch, snapshot, create-dir, move, read-multi, list-allowed, list-with-sizes, read-media, edit-advanced, compress, extract)
  Capa 2: Shell           — 13 tools (exec, sesiones persistentes, ejecución de scripts, historial, shell configurable, procesos en background)
  Capa 3: SSH             — 4 tools (listar hosts, conectar, ejecutar, desconectar) [deshabilitado por defecto]
  Capa 4: Personal        — 9 tools (journal CRUD, notas rápidas, escaneo de proyectos, búsqueda en proyectos, estado git multi-repo)
  Capa 5: Health/Diagnóstico — 9 tools (health check, disco, procesos, configuración, diag, audit log, lista de tools, benchmark, log tail)
  Capa 6: Permissions     — 6 tools (aprobar, denegar, pre-autorizar, listar pendientes, revocar, estadísticas)
```

68 tools en total, 64 activas (las 4 de SSH deshabilitadas por defecto).

## Tools

### Capa 1 — Filesystem (restringido a allowed_paths del config)
| Tool | Descripción |
|------|-------------|
| `fs_read` | Leer contenido de archivo (detección automática de binarios) |
| `fs_write` | Escribir contenido en archivo |
| `fs_write_batch` | Escribir varios archivos en una sola llamada, con un solo ticket/código de confirmación para la lista completa. Misma ruta repetida con contenido idéntico dedup sin error; con contenido distinto, el batch completo se rechaza antes de tocar el disco. Resumen `N/M files written` con resultados y fallos por archivo |
| `fs_edit` | Reemplazar texto en archivo con vista previa de diff |
| `fs_edit_batch` | Editar `old_string`→`new_string` en varios archivos en una sola llamada, con un solo ticket/código de confirmación para la lista completa. Misma ruta repetida con `(old_string, new_string)` idéntico dedup sin error; con un par distinto, el batch completo se rechaza antes de tocar el disco (instrucción ambigua). Resumen `N/M files edited` con resultados y fallos por archivo; archivo inexistente reporta "does not exist", no el engañoso "old_string not found" |
| `fs_delete` | Eliminar un solo archivo (sin directorios/recursión — usar `fs_delete_directory` para borrar una carpeta completa). Los tickets `delete` son siempre de un solo uso — no se permiten grants de sesión ni permanentes, por diseño |
| `fs_delete_batch` | Eliminar múltiples archivos listados explícitamente bajo un solo ticket/código de confirmación, en vez de un popup por archivo. Tampoco borra directorios — usar `fs_delete_directory`. Misma regla de solo-uso-único que `fs_delete` |
| `fs_list` | Listar directorio con filtros |
| `fs_tree` | Árbol de directorio con límite de profundidad |
| `fs_search` | Búsqueda tipo grep con regex en archivos (omite archivos >10MB) |
| `fs_find` | Buscar archivos y carpetas por nombre, tamaño, antigüedad |
| `fs_info` | Metadatos de archivo incluyendo hash SHA256 |
| `fs_diff` | Diff entre dos archivos o archivo vs snapshot |
| `fs_batch` | Copiar/mover/renombrar en lote con dry-run |
| `fs_snapshot` | Snapshot del estado de un directorio a JSON |
| `fs_create_directory` | Crear un directorio (y padres si es necesario) |
| `fs_move` | Mover/renombrar un archivo |
| `fs_read_multi` | Leer varios archivos en una sola llamada |
| `fs_list_allowed` | Listar los directorios configurados en `paths_allow` |
| `fs_list_with_sizes` | Listar entradas de directorio con tamaños, ordenable |
| `fs_read_media` | Leer una imagen/binario como base64, con escaneo de secretos en el contenido decodificado |
| `fs_edit_advanced` | Múltiples reemplazos find/replace en un archivo en una sola llamada, con dry-run |
| `fs_find_duplicates` | Buscar archivos con contenido idéntico (SHA256) dentro de una carpeta, aunque el nombre difiera — a diferencia de `fs_find`, que busca por nombre/tamaño/antigüedad. Sin límite de cantidad ni tamaño de archivo por defecto: agrupa primero por tamaño exacto (gratis, sin leer contenido) y solo calcula hash dentro de esos grupos; los archivos vacíos (size 0) se ignoran siempre. Parámetros: `path`, `recursive?` (default `false`), `extensions?` (acepta `".pdf"` o `"pdf"` indistintamente), `exclude?` (patrones fnmatch estilo `paths_deny` — ej. `"**/node_modules/**"`, `"node_modules"`, `".venv"`, `"*.tmp"` — que PODA los directorios matcheados del recorrido y omite los archivos matcheados), `min_size?` (default `0` — ignora archivos menores; pasa `1024` para filtrar todo lo inferior a 1 KB), `max_size?` (default `None` — ignora archivos mayores, sin tope por defecto). Solo lectura — no borra nada. |
| `fs_disk_usage` | Auditoría de espacio en disco: agrupa el tamaño de todos los archivos bajo `path` por carpeta ancestro a `depth` niveles, devuelve las `top_n` que más pesan, cada una con tamaño, porcentaje y número de archivos. Complementa a `fs_find_duplicates` — esa responde "qué está repetido", esta responde "qué carpeta pesa más". Parámetros: `path`, `top_n?` (default `15`), `depth?` (default `1`), `exclude?` (lista de patrones fnmatch estilo `paths_deny` — ej. `"**/node_modules/**"`, `"node_modules"`, `".venv"` — que PODA los directorios matcheados del recorrido y omite los archivos matcheados; un patrón desnudo como `"node_modules"` matchea cualquier carpeta con ese nombre a cualquier profundidad), `min_size?` (default `0` — ignora archivos menores; pasa `1024` para filtrar todo lo inferior a 1 KB), `max_size?` (default `None` — ignora archivos mayores, sin tope por defecto). Los archivos vacíos (size 0) se ignoran siempre — el conteo significa "archivos que ocupan espacio". Solo lectura. |
| `fs_compress` | Crear un zip a partir de una lista de archivos/carpetas. Parámetros: `paths` (lista), `output_path` |
| `fs_extract` | Descomprimir un zip a `output_dir`. Verifica explícitamente que cada archivo del zip caiga dentro de `output_dir` antes de escribirlo (protección contra zip slip) — un miembro con ruta `../../algo` se omite y se reporta, nunca se escribe fuera del destino |
| `fs_delete_directory` | Borrar una carpeta completa, recursivamente — la única tool de Layer 1 que sí borra directorios. Antes de mostrar el ticket de confirmación, cuenta archivos y tamaño total y lo muestra junto con la solicitud (mismo tipo de preview que el diálogo de Windows al borrar una carpeta). Parámetro: `path` |

**Ejemplo de uso — `fs_find_duplicates`:**
```
fs_find_duplicates(path="C:\\Users\\usuario\\Downloads")
```
Busca duplicados exactos en la raíz de esa carpeta (no entra a subcarpetas por defecto).

```
fs_find_duplicates(
    path="C:\\Users\\usuario\\Downloads",
    recursive=True,
    extensions=["pdf", "docx"]
)
```
Igual, pero recorriendo subcarpetas y limitado a `.pdf`/`.docx`.

```
fs_find_duplicates(
    path="C:\\Users\\usuario\\Repos\\MiProyecto",
    recursive=True,
    exclude=["node_modules", ".venv", ".git"],
    min_size=1024
)
```
Busca duplicados reales en un proyecto sin el ruido de las dependencias: los directorios que matchean se podan del recorrido (no se desciende a ellos — no se pierde tiempo hasheando miles de librerías repetidas), y `min_size=1024` ignora todo lo inferior a 1 KB. Los archivos vacíos (size 0) se ignoran siempre. Para acotar archivos enormes (ej. imágenes de VM de varios GB), pasar `max_size`.

Salida (ejemplo):
```
2 duplicate group(s) found. Recoverable space: 5,632,000 bytes (5.4 MB)

[3 copies, 2,492,300B each, sha256 a1b2c3d4e5f6...]
    ORIGINAL (oldest): C:\Users\usuario\Downloads\informe.docx
    duplicate: C:\Users\usuario\Downloads\informe (1).docx
    duplicate: C:\Users\usuario\Downloads\informe_copia.docx
```
Solo encuentra — no borra. Para limpiar, pasar las rutas marcadas como `duplicate` a `fs_delete_batch`.

**Prompt sugerido para flujo buscar → confirmar → borrar:**
```
Busca archivos duplicados exactos en [RUTA], usando fs_find_duplicates.
[Opcional: recursivo=true / extensions=[".pdf", ".docx"]]

Cuando tengas el resultado:
1. Muéstrame un resumen legible: cuántos grupos, cuánto espacio se
   recuperaría en total, y para cada grupo el archivo ORIGINAL vs
   los duplicados.
2. NO uses fs_delete_batch todavía. Pregúntame explícitamente si
   quiero borrar los duplicados antes de tocar cualquier archivo.
3. Si confirmo, borra únicamente los archivos marcados como
   "duplicate" en cada grupo — nunca el ORIGINAL — usando
   fs_delete_batch, y sigue el flujo normal de ticket/confirm_code.
```
El paso 2 es la línea que realmente importa: sin ella, un agente proactivo podría encadenar búsqueda y borrado en el mismo turno. El sistema de tickets igual exigiría confirmación por popup antes de cualquier borrado real, pero esta instrucción evita que el agente *intente* hacerlo sin pedirlo primero — es una capa de intención, no solo de permiso técnico.

**Ejemplo de uso — `fs_disk_usage`:**
```
fs_disk_usage(path="C:\\Users\\usuario\\Downloads")
```
Agrupa por subcarpeta inmediata (`depth=1`), muestra las 15 que más pesan (`top_n=15`, ambos defaults).

```
fs_disk_usage(path="C:\\Users\\usuario\\Repos", top_n=5, depth=2)
```
Agrupa dos niveles de profundidad (ej. `Repos\Proyecto\subcarpeta`), muestra solo las 5 más pesadas. Nota: con `depth>1` los ancestros intermedios NO aparecen como bucket propio — el archivo en `Proyecto\subcarpeta\x` se atribuye a `Proyecto\subcarpeta`, no a `Proyecto`.

```
fs_disk_usage(path="C:\\Users\\usuario\\Repos", top_n=5, depth=1,
              exclude=["node_modules", ".venv", ".git"])
```
Ignora dependencias y metadatos al decidir "qué carpeta pesa más": los directorios que matchean se podan del recorrido (no se desciende a ellos), así que además de no aparecer, no consumen tiempo de escaneo. Un patrón desnudo como `"node_modules"` matchea cualquier carpeta con ese nombre a cualquier profundidad.

```
fs_disk_usage(path="C:\\Users\\usuario\\Downloads", top_n=5,
              min_size=1024, max_size=1073741824)
```
Límites opcionales (misma semántica que `fs_find_duplicates`): `min_size=1024` ignora todo lo inferior a 1 KB, `max_size` ignora archivos mayores — ej. `1073741824` (1 GB) responde "qué pesa más, ignorando los ISOs enormes que ya sé que existen". Los archivos vacíos (size 0) se ignoran siempre: el conteo significa "archivos que ocupan espacio".

Salida (ejemplo):
```
Uso de disco bajo C:\Users\usuario\Downloads — total 17,038,532,030 bytes (15.87 GB)

   8,542,210,304 B  (  8146.5 MB,  50.1%)  128 archivo(s)  C:\Users\usuario\Downloads\videos
   3,221,225,472 B  (  3072.0 MB,  18.9%)   42 archivo(s)  C:\Users\usuario\Downloads\instaladores
     830,472,192 B  (   792.1 MB,   4.9%)  2,311 archivo(s)  C:\Users\usuario\Downloads\documentos
... y 12 carpeta(s) más, 4,444,624,062 bytes (4238.5 MB) en total
```
Solo lee — no borra ni mueve nada. Útil junto con `fs_find_duplicates` para decidir dónde limpiar primero.

**Ejemplo de uso — `fs_compress` / `fs_extract`:**
```
fs_compress(
    paths=["C:\\Users\\usuario\\Repos\\MiProyecto\\src"],
    output_path="C:\\Users\\usuario\\Desktop\\backup_src.zip"
)
```
Devuelve algo como `"Created C:\...\backup_src.zip (48,230 bytes, 12 file(s))"`.

```
fs_extract(
    zip_path="C:\\Users\\usuario\\Desktop\\backup_src.zip",
    output_dir="C:\\Users\\usuario\\Repos\\restaurado"
)
```
Devuelve `"Extracted 12 file(s) to C:\Users\usuario\Repos\restaurado"`. Si el zip fuera malicioso (ej. un miembro con ruta `../../algo.txt`), la respuesta incluiría una advertencia con los miembros omitidos, y esos archivos **nunca** se escriben fuera de `output_dir`.

**Ejemplo de uso — `fs_delete_directory`:**
```
fs_delete_directory(path="C:\\Users\\usuario\\Repos\\mi-proyecto\\node_modules")
```
Primera llamada (sin ticket todavía) devuelve algo como:
```
About to delete directory: C:\Users\usuario\Repos\mi-proyecto\node_modules
Contains 14,832 file(s), 287,450,112 bytes (274.1 MB)

{"status": "permission_required", "ticket": "perm_...", ...}
```
El conteo aparece **antes** de que confirmes — igual que el diálogo de Windows al borrar una carpeta. Tras aprobar el ticket con el código del popup y repetir la misma llamada, borra la carpeta completa y confirma cuántos archivos se eliminaron.

**Ejemplos de uso — herramientas básicas:**
```
fs_edit(
    path="C:\\Users\\usuario\\Repos\\MiProyecto\\README.md",
    old_string="version 1.0",
    new_string="version 1.1"
)
```
Reemplazo de texto con vista previa de diff. Sin grant activo, devuelve un ticket de escritura (ver "Flujo de aprobación" abajo) en vez de ejecutar.

```
fs_batch(
    operations=[
        {"action": "copy", "source": "C:\\Users\\usuario\\Repos\\A\\a.txt", "destination": "C:\\Users\\usuario\\Repos\\B\\a.txt"},
        {"action": "move", "source": "C:\\Users\\usuario\\Repos\\A\\b.txt", "destination": "C:\\Users\\usuario\\Repos\\B\\b.txt"}
    ],
    dry_run=True
)
```
Copiar/mover/renombrar en lote. `dry_run=True` valida la lista sin tocar nada — ejecutar después sin el flag.

```
fs_list(path="C:\\Users\\usuario\\Repos", pattern="*.py", max_results=10)
fs_search(path="C:\\Users\\usuario\\Repos", pattern="def main", extensions=[".py"])
fs_find(path="C:\\Users\\usuario\\Repos", pattern="*test*", recursive=True)
```
Trío rápido de inspección: listar entradas, buscar contenido (grep con regex, omite archivos >10 MB) y buscar por nombre.

```
fs_edit_advanced(
    path="C:\\Users\\usuario\\Repos\\MiProyecto\\config.yaml",
    edits=[
        {"old_string": "debug: false", "new_string": "debug: true"},
        {"old_string": "port: 8080", "new_string": "port: 9090"}
    ],
    dry_run=True
)
```
Múltiples reemplazos find/replace en una sola llamada; `dry_run=True` previsualiza el diff completo antes de escribir.

### Capa 2 — Shell (ejecución multi-shell, cambio de shell en runtime)
| Tool | Descripción |
|------|-------------|
| `sh_exec` | Ejecutar comando one-shot. Parámetros: `command`, `timeout`, `working_dir?`, `shell?` (powershell/pwsh/cmd/bash) |
| `sh_session_start` | Crear sesión de shell persistente (solo powershell/pwsh). Parámetros: `timeout?`, `shell?` |
| `sh_session_list` | Listar sesiones activas |
| `sh_session_send` | Enviar comando a sesión |
| `sh_session_read` | Leer salida pendiente de sesión |
| `sh_session_interrupt` | Enviar Ctrl+C a sesión |
| `sh_session_close` | Cerrar sesión |
| `sh_script` | Ejecutar script multi-línea desde archivo temporal. Parámetros: `script`, `timeout`, `working_dir?`, `shell?` |
| `sh_history` | Historial de sesiones activas: `session_id` (truncado), comandos ejecutados y uptime de cada una |
| `sh_spawn` | Arrancar un proceso de larga duración en background (dev server, watcher) — a diferencia de `sh_exec`, que muere al cumplirse el timeout. Devuelve `spawn_id`. Exige su propio ticket de `execute` (nunca satisfecho por un grant wildcard `"*"`, igual que `python`/`node`/`bash`). Parámetros: `command`, `working_dir?`, `shell?` |
| `sh_spawn_read` | Leer el output acumulado de un proceso en background (buffer circular de las últimas 500 líneas). Parámetros: `spawn_id`, `n?` (default `100`) |
| `sh_spawn_kill` | Terminar un proceso en background y su árbol de procesos hijos |
| `sh_spawn_list` | Listar procesos en background activos — incluye los que quedaron huérfanos de un servidor `personal-mcp` anterior que ya no está corriendo (marcados `"orphaned"`, nunca matados automáticamente) |

**Ejemplo de uso — `sh_spawn`:**
```
sh_spawn(command="npm run dev", working_dir="C:\\Users\\usuario\\Repos\\MiProyecto")
```
Devuelve algo como `{"spawn_id": "a1b2c3d4-...", "pid": 12345, "message": "Spawned a1b2c3d4... (pid=12345)..."}`.

```
sh_spawn_read(spawn_id="a1b2c3d4-...")
```
Devuelve el output acumulado hasta ahora, sin bloquear ni esperar a que el proceso termine.

```
sh_spawn_kill(spawn_id="a1b2c3d4-...")
```
Termina el proceso (y sus hijos) cuando ya no se necesita.

```
sh_spawn_list()
```
Salida (ejemplo, con un huérfano detectado de un servidor anterior):
```
[
  {"spawn_id": "a1b2c3d4", "pid": 12345, "command": "npm run dev", "status": "running", "uptime_seconds": 340},
  {"spawn_id": "f9e8d7c6", "pid": 9876, "command": "npm run watch", "status": "orphaned",
   "note": "owner pid 5432 no longer running -- use sh_spawn_kill to stop it"}
]
```
⚠️ Un proceso huérfano sigue corriendo de verdad — no se mata solo. Si aparece uno que ya no necesitas, usa `sh_spawn_kill` con su `spawn_id` para pararlo.

**Ejemplos de uso — `sh_exec` / `sh_script` / `sh_session`:**
```
sh_exec(command="git status", working_dir="C:\\Users\\usuario\\Repos\\MiProyecto", timeout=30)
```
Comando one-shot en el directorio indicado; si excede el timeout se mata el árbol de procesos (con su salida parcial). `python`/`node`/`bash` exigen además un ticket de `execute` antes de arrancar (ver "Flujo de aprobación" abajo). ⚠️ `cd` no está en la whitelist — `working_dir` es el único canal correcto para cambiar de directorio.

```
sh_script(
    script="""$files = Get-ChildItem *.py
$files | ForEach-Object { $_.Length }""",
    working_dir="C:\\Users\\usuario\\Repos\\MiProyecto",
    timeout=30
)
```
Script multi-línea ejecutado desde un archivo temporal (`.ps1`/`.bat`/`.sh` según el shell). Cada línea se valida segmento por segmento contra la whitelist de solo lectura — una línea que intente mutar algo rechaza el script completo antes de ejecutarse.

```
sh_session_start(shell="powershell")        # → {"session_id": "ses_..."}
sh_session_send(session_id="ses_...", command="npm run dev",
                working_dir="C:\\Users\\usuario\\Repos\\MiProyecto")
sh_session_read(session_id="ses_...")       # lee la salida pendiente
sh_session_interrupt(session_id="ses_...")  # Ctrl+C
sh_session_close(session_id="ses_...")
```
Sesión persistente: el estado (directorio, variables) sobrevive entre comandos. ⚠️ Limitación conocida: PowerShell en modo sesión bufferiza stdout — para dev servers de larga duración usar `sh_spawn` (arriba) en vez de depender de `sh_session_read`. `sh_history()` lista las sesiones activas con su uptime y conteo de comandos.

### Capa 3 — SSH (condicional, deshabilitado por defecto)
| Tool | Descripción |
|------|-------------|
| `ssh_list_hosts` | Listar hosts desde ~/.ssh/config |
| `ssh_connect` | Abrir sesión SSH |
| `ssh_exec` | Ejecutar comando en host remoto |
| `ssh_disconnect` | Cerrar sesión SSH |

> Nota: la capa SSH está **deshabilitada por defecto** (`ssh.enabled: false`). Sin ejemplos de uso hasta habilitarla y endurecer el host remoto.

### Capa 4 — Personal
| Tool | Descripción |
|------|-------------|
| `journal_add` | Agregar entrada al diario con tags/categoría |
| `journal_list` | Listar entradas con filtros |
| `journal_search` | Búsqueda full-text en el diario |
| `journal_stats` | Estadísticas de entradas por tag/categoría |
| `journal_export` | Exportar diario como JSON o Markdown |
| `note_quick` | Nota rápida a archivo inbox |
| `project_scan` | Escanear repos: rama, cambios sin commit |
| `project_find` | Buscar archivo en todos los repos permitidos |
| `project_git_status` | Estado de git para los repos encontrados bajo `paths_allow` (o bajo un `path` puntual si se especifica), descubrimiento automático (recorre las carpetas buscando `.git`, saltando `node_modules`/`.venv`/etc.). Reporta cambios sin commitear, commits sin pushear y commits del remoto sin traer. Parámetro: `path?` (opcional). Si se omite y `paths_allow` incluye una raíz de disco completa (ej. `C:\`), no escanea — devuelve un mensaje pidiendo un `path` puntual, en vez de colgarse recorriendo todo el disco. |

**Ejemplo de uso — `project_git_status` (recomendado: pasar siempre `path` puntual):**
```
project_git_status(path="C:\Users\usuario\Repos")
```
Con `path` se acota el recorrido a esa carpeta puntual (debe estar dentro de `paths_allow`), evitando el recorrido de disco completo. Salida (ejemplo):
```
2 repo(s) con cambios pendientes:
  MiProyecto                     [main]  3 sin commitear
  personal-mcp                   [main]  2 sin pushear

7 repo(s) sin cambios pendientes: RepoA, RepoB, RepoC, RepoD, RepoE, RepoF, RepoG
```
Sin `path`, recorre automáticamente todas las raíces de `paths_allow` — solo funciona si estas están acotadas.
⚠️ Si alguna raíz de `paths_allow` es una raíz de disco completa (ej. `["C:\\"]`), `project_git_status()` sin `path` no escanea — devuelve directamente:
```
paths_allow incluye una raiz de disco completa (C:\) - recorrerla puede tardar varios minutos y agotar el timeout del cliente MCP.
Pasa un path puntual dentro de las rutas permitidas, ej.: project_git_status(path="C:\\Users\\usuario\\Repos").
```
Ese mensaje no es un error de la tool: es el guard de seguridad por diseño. Reintenta con un `path` puntual.

**Ejemplos de uso — diario y notas:**
```
journal_add(content="Instalado el nuevo SSD en el portátil", tags=["hardware", "mantenimiento"])
journal_list(tag="hardware", limit=10)
journal_search(query="SSD")
journal_stats()                     # estadísticas por tag/categoría
journal_export(format="markdown")   # o "json"
```
Diario con tags, búsqueda full-text y exportación.

```
note_quick(content="Comprar cable HDMI para la oficina")
```
Nota rápida al archivo inbox — la forma más corta de guardar algo sin estructura.

```
project_scan()
project_find(pattern="*.env.example")
```
Escaneo de repos (rama, cambios sin commitear) y búsqueda de archivos en todos los repos permitidos.

### Capa 5 — Health y Diagnóstico
| Tool | Descripción |
|------|-------------|
| `health_check` | Resumen completo de salud del sistema |
| `health_disk` | Uso de disco para rutas especificadas |
| `health_processes` | Top procesos por CPU |
| `health_config` | Configuración actual (validada) |
| `mcp_diag` | Reporte completo de diagnóstico |
| `mcp_audit_log` | Registro de auditoría de operaciones recientes |
| `mcp_list_tools` | Listar todas las tools registradas |
| `mcp_benchmark` | Benchmarks de rendimiento |
| `mcp_log` | Leer el archivo de log del servidor, filtrable por nivel |

**Ejemplos de uso — diagnóstico:**
```
health_check()                    # resumen completo de salud del sistema
health_disk()                     # uso de disco de las rutas configuradas
health_processes(top=5)           # top procesos por CPU
mcp_log(level="WARNING", n=50)    # últimas 50 líneas de log, filtradas por nivel
mcp_audit_log(n=20)               # últimas 20 operaciones auditadas
mcp_list_tools()                  # inventario de las tools registradas
```

### Capa 6 — Permissions
| Tool | Descripción |
|------|-------------|
| `fs_approve` | Aprobar un ticket de permiso pendiente (single/session) |
| `fs_deny` | Denegar explícitamente un ticket |
| `fs_request_allow` | Crear un ticket de permiso pendiente; usar `fs_approve` para confirmar |
| `security_pending` | Listar todas las solicitudes de permiso pendientes |
| `security_revoke` | Revocar un grant activo de sesión/permanente |
| `security_stats` | Estadísticas del sistema de permisos |

**Flujo de aprobación — tickets + popup (ejemplo completo):**
```
fs_write(path="C:\\Users\\usuario\\Repos\\MiProyecto\\notas.txt", content="...")
```
Primera llamada (sin grant activo) devuelve un ticket — no ejecuta nada:
```
{"status": "permission_required", "ticket": "perm_...", "operation": "write",
 "message": "fs_approve(ticket_id='perm_...', level='session'|'single', confirm_code='<popup>')"}
```
En paralelo, un popup nativo muestra el código de confirmación de 6 dígitos — el **único** canal donde es visible; nunca viene en la respuesta de ninguna tool. Confirmas con:
```
fs_approve(ticket_id="perm_...", confirm_code="123456", level="session")
```
- `level='session'`: autoriza el directorio (con subdirectorios) para toda la sesión — "ask once, session-scoped". Recomendado para write/edit.
- `level='single'`: autoriza una sola operación.
- Los borrados (`fs_delete*`) son **siempre** `single` por diseño — nunca session ni permanente.

Tras aprobar, repites la llamada original y se ejecuta. Para un lote de rutas (`fs_delete_batch`/`fs_write_batch`/`fs_edit_batch`) se genera **un solo ticket** para toda la lista, con preview acotado — la lista completa viaja en el campo `resources`, no en el mensaje. Regla de oro: pedir siempre el código del popup antes de aprobar — nunca aprobar con un código inventado.

## Seguridad

- **Human-in-the-Loop (HITL) con confirmación HMAC**: Las operaciones de escritura/borrado y ejecuciones de shell requieren aprobación explícita del usuario mediante tickets. `fs_approve` requiere un `confirm_code` — un código de 6 dígitos mostrado *solo* mediante un popup nativo en la pantalla del usuario, nunca devuelto en la respuesta de ninguna tool. Un agente no tiene ningún canal para leerlo o adivinarlo (verificación `hmac.compare_digest()` contra un secreto en memoria). Usar `fs_request_allow` para crear un ticket pendiente, luego `fs_approve(ticket_id, confirm_code, level)` para confirmar. Las lecturas dentro de `paths_allow` pasan directamente (sin ticket).
- **Gate de aprobación `execute` para intérpretes de propósito general**: `python`/`node`/`bash` están en la whitelist para workflows legítimos de desarrollo, pero ejecutarlos es una caja negra una vez aprobados — se requiere un ticket explícito de `execute` (mismo flujo con confirmación HMAC) antes de permitir que el intérprete arranque, además de la whitelist de comandos.
- **Operaciones batch usan un solo ticket, no uno por archivo**: `fs_delete_batch` vincula un solo ticket/código de confirmación a una lista explícita de rutas.
- **Hard-Lock estricto de rutas**: Solo las rutas definidas en `security.paths_allow` (y el `data_dir` interno) son accesibles para lecturas sin ticket; las rutas fuera son denegadas. Escritura/borrado siempre requieren grant explícito sin importar el alcance de `paths_allow`.
- **Whitelist de comandos**: La ejecución de shell está restringida a una whitelist estricta de prefijos de comandos aprobados (ej. `git`, `npm`, `python`, `ls`). Comandos no incluidos en la whitelist, o explícitamente denegados, son bloqueados.
- **Grants de sesión recursivos**: Aprobar un directorio para una sesión (`level='session'`) automáticamente otorga acceso a todos sus subdirectorios y archivos, reduciendo la fricción de aprobación para proyectos complejos.
- **Lista negra de rutas**: Las rutas que coinciden con patrones de `security.paths_deny` (ej. `**\node_modules\**`, `**\.git\**`, `**\.ssh\**`, `**\.env*`, `**\*.pem`, archivos de credenciales de git/npm/pip/docker/aws/azure/kube) son bloqueadas incluso si están bajo un directorio permitido. Existe una excepción limitada, explícita y de solo-lectura para inspeccionar los artefactos de build de un proyecto propio (`.dll`/`.exe`/`.pdb` bajo `**\bin\**`/`**\obj\**`) sin abrir esas carpetas en general — deshabilitada por defecto, opt-in por proyecto vía `security.paths_deny_exceptions`. **Desde v1.4.83**, `paths_deny` se chequea por archivo dentro de TODOS los walks recursivos (`fs_search`/`fs_find`/`fs_compress`/`fs_batch`/`fs_list`/`fs_tree`/`fs_snapshot`/`fs_disk_usage`/`fs_find_duplicates`) — antes validar el directorio base bastaba, así que un archivo `.env` podía ser ex-filtrado vía `fs_search` aunque `fs_read` lo bloqueara. Ahora cada walk omite los archivos denied por entrada y reporta un sufijo `[skipped N denied file(s) by paths_deny: patrón×N]` (conteo por patrón, sin rutas). La excepción de solo-lectura sigue aplicando. **Desde v1.4.85**, los directorios denied se podan del recorrido por su nombre ("core" del patrón, ej. `node_modules`) — el walk no desciende, contándolos como 1 (antes N archivos); la excepción de solo-lectura evita la poda de `bin`/`obj` exceptuados.
- **`validate_tool_path()`**: Todas las tools de la capa 1 validan rutas mediante este método. Para operaciones de escritura/borrado sin grant, se devuelve un ticket JSON `permission_required`. Las lecturas en `paths_allow` pasan directamente (sin ticket).
- **Rate limiting por operación**: Rate limiter de ventana deslizante (`security.rate_limit_commands_per_minute`) aplicado a operaciones de archivo (lectura/escritura) en `validate_tool_path()` y a comandos de shell en `validate_command()` (`sh_exec`/`sh_session_send`/`sh_spawn`). Deshabilitado cuando se configura en 0.
- **Escaneo de secretos**: Contenido de archivos y medios escaneado en busca de credenciales (tokens de GitHub, claves AWS, claves privadas, cadenas de conexión de BD, etc.) en `fs_read`/`fs_read_media`/salida de shell/entradas del diario — solo advierte, nunca bloquea. Configurable vía `security.secret_scanning_enabled`. **Desde v1.4.85** el escaneo corre fuera del event loop y acotado a los primeros 1 MB de archivos grandes (se anexa un aviso `[secret scan limited...]`); los archivos con un secreto muestran un bloque `--- Security Scan ---` al final de la lectura.
- **Errores de escritura limpios (v1.4.86)**: si el OS rechaza la escritura (archivo con atributo read-only en Windows, ACL, archivo bloqueado), `fs_write`/`fs_edit`/`fs_edit_advanced`/`fs_edit_batch` devuelven `Error: cannot write <path>: ...` (con hint `attrib -r` en Windows si es read-only) en vez de un error JSON-RPC, y el grant `single` ya consumido se **reembolsa** — reintentar no exige un nuevo ticket/popup. `fs_edit` nunca reporta éxito si la escritura falló.
- **Truncado de salida**: Toda la salida de shell está limitada a 1 MiB para prevenir problemas de memoria — el límite se aplica *durante* la lectura (en chunks, `_read_stream_capped`), no después de bufferear toda la salida. La salida truncada se marca con un aviso.
- **Cotas anti-DoS configurables (v1.4.83)**: topes por defecto seguros para `fs_extract` (zip-bomb), `fs_read_media`/`fs_read_multi`, `sh_exec`/`sh_session_send`/`sh_script` (`max_timeout_seconds`, `max_sessions`, `max_spawns`) y `mcp_log` (`mcp_log_max_lines`/`mcp_log_max_bytes`). Si tu config viejo no los tiene, pydantic aplica los defaults automáticamente — ver `CONFIG-GUIA.md` para la tabla completa.
- **Limpieza de árbol de procesos**: Los comandos que exceden el timeout usan `taskkill /T /F` para terminar recursivamente todos los procesos hijos, seguido de un reap del handle del proceso original para evitar fugas de recursos de I/O asíncrono a nivel OS.
- **Registro de auditoría**: Cada operación se registra (buffer circular, 10k entradas) con datos sensibles automáticamente ofuscados.
- **Limitación conocida — el conector MCP `Filesystem` genérico (oficial), si también está habilitado con acceso de escritura a la carpeta de este repo, evade todas las protecciones anteriores.** Escribe directamente al disco sin tickets, sin `confirm_code`, sin registro de auditoría — el modelo de seguridad de este servidor solo cubre las tools que *este* servidor expone, no el repositorio como archivo en disco. No hay fix de código posible desde este proyecto; si también usas el conector oficial `Filesystem` en el mismo cliente MCP, evita darle acceso de escritura a la ruta de este repo, o acepta que es un canal de escritura paralelo sin protección hacia tu propia configuración de seguridad.

#### Auditoría de seguridad 2026-08-11

Se realizó una auditoría completa del repo (58 hallazgos). **46 quedaron cerrados** (CHANGELOG 1.4.64 → 1.4.70), incluidos 3 CRÍTICOS de ejecución arbitraria en el pipeline de comandos (sustitución `$()`/backticks en comillas, bypass de `sh_script` por operadores inline, inyección vía `working_dir`) y 6 ALTOS. Quedan **5 diferidos, aceptados deliberadamente**:

- **Sesiones shell interactivas (`sh_session`)** — el corte de lectura a ~0.3 s de silencio y `Ctrl+C` por pipe no son confiables (PowerShell bufferiza stdout; `\x03` por pipe no es tty). Inherente al diseño; documentado en AGENTS.md.
- **Race multi-proceso en `journal.jsonl`** — probabilidad baja; no hay lock cross-platform seguro en la stdlib.
- **SSH** (`M-SSH2`/`M-SSH3`) — capa deshabilitada por defecto (`ssh.enabled: false`); sin superficie real.

## ⚠️ Para qué NO está listo (sin trabajo extra)

| Caso de uso | Qué falta / Limitación |
|-------------|------------------------|
| **Multi-usuario / Multi-tenant** | Sin autenticación, sin aislamiento de datos, config single-user. Cada usuario necesitaría su propia instancia. |
| **Deployment remoto / Contenedor / Kubernetes** | Solo transporte **stdio local**. Sin HTTP, SSE, ni WebSocket. No hay health endpoint HTTP para probes. |
| **SSH en producción** | Capa deshabilitada por defecto (`ssh.enabled: false`). Requiere hardening remoto, auditoría de `remote_allow_prefix`, y deploy de wrapper en host destino para enforcement real. |
| **Compliance estricto (SOC2, ISO27001, HIPAA, etc.)** | Sin cifrado en reposo, sin RBAC, sin audit trail inmutable (logs rotativos, sobrescribibles), sin tamper-evidence. |
| **High Availability / Escalado horizontal** | Proceso único, sin clustering, sin leader election, sin shared state. Reinicio = downtime. |
| **Entorno no Windows (Linux/macOS) — Limitaciones** | `sh_session` solo soporta `powershell`/`pwsh` (sin sesiones interactivas en `cmd`/`bash`). Limpieza de procesos usa `taskkill` (Windows-only). `confirm_code` popup usa `MessageBoxW` (solo Windows — desactivado en pytest, pero no hay equivalente nativo en Linux/macOS). |
| **Protección contra conector MCP Filesystem oficial paralelo** | Si el cliente MCP tiene *también* el conector oficial `Filesystem` habilitado con acceso de escritura a la misma ruta, **este escribe directo al disco sin tickets, sin confirm_code, sin auditoría**. Es una decisión de configuración del usuario, no un bug de este servidor. Ver "Limitación conocida" en sección Seguridad. |
| **Gestión de secretos / Vault integrado** | No hay integración con HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, etc. Los secretos en config.json están en texto plano. |
| **API programática / SDK** | Solo interfaz MCP (stdio). No hay REST/gRPC/GraphQL para integrar desde otros servicios. |
| **Migración de config / Versionado de esquema** | `config.json` no tiene versión de esquema ni migración automática. Cambios breaking en config requieren edición manual. |

## Configuración de Shell

La capa de shell soporta múltiples shells configurados vía `~/.personal-mcp/config.json`:

| Shell | Valor de config | Sesiones interactivas | Ejecución de scripts | Ruta auto-detectada |
|-------|-----------------|----------------------|---------------------|---------------------|
| PowerShell (default) | `"powershell"` | Sí | Sí (`.ps1`) | `%PATH%` |
| PowerShell Core | `"pwsh"` | Sí | Sí (`.ps1`) | `%PATH%` o ruta personalizada |
| CMD | `"cmd"` | No | Sí (`.bat`) | `%COMSPEC%` |
| Git Bash / bash | `"bash"` | No | Sí (`.sh`) | `git --exec-path` o `PERSONAL_MCP_GIT_BASH_PATH` |

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

El agente también puede cambiar de shell en runtime por comando mediante el parámetro `shell` en `sh_exec`, `sh_script` y `sh_session_start`. Ejemplo:

```
sh_exec("echo hola", shell="cmd")
sh_script("echo hola", shell="cmd")
sh_session_start(shell="pwsh")
```

Cuando se omite `shell`, se usa el `default_shell` configurado. Nombres de shell inválidos devuelven un mensaje de error claro.

## Instalación

### Windows (PowerShell)
```powershell
.\install.ps1
```

Para instancias adicionales de Claude Desktop (multi-cuenta, ej. `Claude-Cuenta2`/`Claude-Cuenta3`):
```powershell
.\install.ps1 -UserDataDirs "C:\Users\user\Claude-Cuenta2", "C:\Users\user\Claude-Cuenta3"
```
El instalador escribe la ruta absoluta del Python del venv (`command`) — una instalación registrada con `"command": "python"` a secas corre con el Python del sistema, no con el venv (ver CHANGELOG 1.4.73).

### Linux / macOS (bash)
```bash
chmod +x install.sh
./install.sh
```

Ambos instaladores:
1. Verifican Python 3.10+
2. Crean entorno virtual (`.venv`)
3. Crean estructura de directorios
4. Instalan dependencias de Python en el venv
5. Generan config por defecto con rutas de workspace auto-detectadas
6. Registran con Claude Desktop usando el Python del venv

### Instalación manual (todas las plataformas)
```bash
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
# Windows: pip install pywin32
python -m src.server  # prueba de ejecución
```

Luego configurar Claude Desktop manualmente:
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

Agregar a `mcpServers`:
```json
{
  "mcpServers": {
    "personal-mcp": {
      "command": "/ruta/completa/a/.venv/bin/python",
      "args": ["/ruta/completa/a/run_server.py"]
    }
  }
}
```

## Configuración

Edita `~/.personal-mcp/config.json` para personalizar. Se mantiene un espejo de solo lectura de este archivo en la raíz del repo (`config.json`) por conveniencia — ejecuta `sync-config.ps1` para refrescarlo desde la copia oficial. Ver [`CONFIG-GUIA.md`](CONFIG-GUIA.md) para una explicación en lenguaje simple, no técnica, de cada campo.

- **Configuración interactiva**: Usá `python configure_paths.py` para gestionar tus directorios permitidos sin editar el JSON manualmente.
- **Configuración de ejemplo**: Ver `config.demo.json` para una plantilla segura y optimizada para productividad.
- `security.paths_allow`: Directorios accesibles para lecturas sin ticket. Si se amplía hasta una raíz de disco completa (ej. `["C:\\"]`), las escrituras/borrados siguen requiriendo ticket explícito, pero `paths_deny` se convierte en tu único control real de lectura. El default para una instalación nueva es acotado (ej. `~/Repos`, `~/Desktop`, `~/OneDrive`, `~/.personal-mcp`); amplía solamente si entiendes las implicaciones.
- `security.paths_deny`: Patrones de rutas bloqueadas (default: `**\node_modules\**`, `**\.git\**`, `**\bin\**`, `**\obj\**`, `**\AppData\**`, más patrones enfocados en credenciales: `.ssh`, `.aws`, `.azure`, `.kube`, `.gnupg`, `.env*`, `*.pem`, `id_rsa*`, `id_ed25519*`, archivos de credenciales de git/npm/pip/docker)
- `security.paths_deny_exceptions` / `paths_deny_exception_extensions`: excepción limitada, de solo-lectura, opt-in a `paths_deny` para inspeccionar artefactos de build de un proyecto propio (ver sección Seguridad arriba). Vacío por defecto.
- `security.commands.allow_prefix`: Whitelist obligatoria de prefijos de comandos permitidos (ej. `git`, `npm`, `python`).
- `security.rate_limit_commands_per_minute`: Máximo de comandos por minuto (default: 60, 0 = deshabilitado)
- `security.secret_scanning_enabled`: Escanear contenido de archivos en busca de secretos en fs_read (default: true)
- `shell.session_timeout_seconds`: Timeout de inactividad de sesión (default: 600)
- `ssh.enabled`: Configurar en `true` para habilitar la capa SSH (requiere ~/.ssh/config)

## Desarrollo

```bash
# Windows
.\.venv\Scripts\python -m pytest tests/ -v
.\.venv\Scripts\python -m src.server

# Linux / macOS
source .venv/bin/activate
python -m pytest tests/ -v
python -m src.server
```

### Sincronizar espejo del config (repo → config de usuario)
```bash
# Windows
.\sync-config.ps1

# Linux / macOS
./sync-config.sh
```
