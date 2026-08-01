# personal-mcp

Servidor MCP personalizado para orquestación de estaciones de trabajo Windows/Linux/macOS. Seguridad basada en listas blancas con aprobación HITL para escrituras, escaneo de secretos, rate limiting por operación, I/O completamente asíncrono, sesiones persistentes de shell.

## Arquitectura

```
6 capas, diseño hexagonal:
  Capa 1: Filesystem      — 21 tools (read, write, edit, delete, delete-batch, list, tree, search, find, find-duplicates, info, diff, batch, snapshot, create-dir, move, read-multi, list-allowed, list-with-sizes, read-media, edit-advanced)
  Capa 2: Shell           — 9 tools (exec, sesiones persistentes, ejecución de scripts, historial, shell configurable)
  Capa 3: SSH             — 4 tools (listar hosts, conectar, ejecutar, desconectar) [deshabilitado por defecto]
  Capa 4: Personal        — 8 tools (journal CRUD, notas rápidas, escaneo de proyectos, búsqueda en proyectos)
  Capa 5: Health/Diagnóstico — 9 tools (health check, disco, procesos, configuración, diag, audit log, lista de tools, benchmark, log tail)
  Capa 6: Permissions     — 6 tools (aprobar, denegar, pre-autorizar, listar pendientes, revocar, estadísticas)
```

57 tools en total, 53 activas (las 4 de SSH deshabilitadas por defecto).

## Tools

### Capa 1 — Filesystem (restringido a allowed_paths del config)
| Tool | Descripción |
|------|-------------|
| `fs_read` | Leer contenido de archivo (detección automática de binarios) |
| `fs_write` | Escribir contenido en archivo |
| `fs_edit` | Reemplazar texto en archivo con vista previa de diff |
| `fs_delete` | Eliminar un solo archivo (sin directorios/recursión). Los tickets `delete` son siempre de un solo uso — no se permiten grants de sesión ni permanentes, por diseño |
| `fs_delete_batch` | Eliminar múltiples archivos listados explícitamente bajo un solo ticket/código de confirmación, en vez de un popup por archivo. Misma regla de solo-uso-único que `fs_delete` |
| `fs_list` | Listar directorio con filtros |
| `fs_tree` | Árbol de directorio con límite de profundidad |
| `fs_search` | Búsqueda tipo grep con regex en archivos (omite archivos >10MB) |
| `fs_find` | Buscar archivos por nombre, tamaño, antigüedad |
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
| `fs_find_duplicates` | Buscar archivos con contenido idéntico (SHA256) dentro de una carpeta, aunque el nombre difiera — a diferencia de `fs_find`, que busca por nombre/tamaño/antigüedad. Sin límite de cantidad ni tamaño de archivo: agrupa primero por tamaño exacto (gratis, sin leer contenido) y solo calcula hash dentro de esos grupos. Parámetros: `path`, `recursive?` (default `false`), `extensions?` (acepta `".pdf"` o `"pdf"` indistintamente). Solo lectura — no borra nada. |

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

### Capa 3 — SSH (condicional, deshabilitado por defecto)
| Tool | Descripción |
|------|-------------|
| `ssh_list_hosts` | Listar hosts desde ~/.ssh/config |
| `ssh_connect` | Abrir sesión SSH |
| `ssh_exec` | Ejecutar comando en host remoto |
| `ssh_disconnect` | Cerrar sesión SSH |

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

### Capa 6 — Permissions
| Tool | Descripción |
|------|-------------|
| `fs_approve` | Aprobar un ticket de permiso pendiente (single/session) |
| `fs_deny` | Denegar explícitamente un ticket |
| `fs_request_allow` | Crear un ticket de permiso pendiente; usar `fs_approve` para confirmar |
| `security_pending` | Listar todas las solicitudes de permiso pendientes |
| `security_revoke` | Revocar un grant activo de sesión/permanente |
| `security_stats` | Estadísticas del sistema de permisos |

## Seguridad

- **Human-in-the-Loop (HITL) con confirmación HMAC**: Las operaciones de escritura/borrado y ejecuciones de shell requieren aprobación explícita del usuario mediante tickets. `fs_approve` requiere un `confirm_code` — un código de 6 dígitos mostrado *solo* mediante un popup nativo en la pantalla del usuario, nunca devuelto en la respuesta de ninguna tool. Un agente no tiene ningún canal para leerlo o adivinarlo (verificación `hmac.compare_digest()` contra un secreto en memoria). Usar `fs_request_allow` para crear un ticket pendiente, luego `fs_approve(ticket_id, confirm_code, level)` para confirmar. Las lecturas dentro de `paths_allow` pasan directamente (sin ticket).
- **Gate de aprobación `execute` para intérpretes de propósito general**: `python`/`node`/`bash` están en la whitelist para workflows legítimos de desarrollo, pero ejecutarlos es una caja negra una vez aprobados — se requiere un ticket explícito de `execute` (mismo flujo con confirmación HMAC) antes de permitir que el intérprete arranque, además de la whitelist de comandos.
- **Operaciones batch usan un solo ticket, no uno por archivo**: `fs_delete_batch` vincula un solo ticket/código de confirmación a una lista explícita de rutas.
- **Hard-Lock estricto de rutas**: Solo las rutas definidas en `security.paths_allow` (y el `data_dir` interno) son accesibles para lecturas sin ticket; las rutas fuera son denegadas. Escritura/borrado siempre requieren grant explícito sin importar el alcance de `paths_allow`.
- **Whitelist de comandos**: La ejecución de shell está restringida a una whitelist estricta de prefijos de comandos aprobados (ej. `git`, `npm`, `python`, `ls`). Comandos no incluidos en la whitelist, o explícitamente denegados, son bloqueados.
- **Grants de sesión recursivos**: Aprobar un directorio para una sesión (`level='session'`) automáticamente otorga acceso a todos sus subdirectorios y archivos, reduciendo la fricción de aprobación para proyectos complejos.
- **Lista negra de rutas**: Las rutas que coinciden con patrones de `security.paths_deny` (ej. `**\node_modules\**`, `**\.git\**`, `**\.ssh\**`, `**\.env*`, `**\*.pem`, archivos de credenciales de git/npm/pip/docker/aws/azure/kube) son bloqueadas incluso si están bajo un directorio permitido. Existe una excepción limitada, explícita y de solo-lectura para inspeccionar los artefactos de build de un proyecto propio (`.dll`/`.exe`/`.pdb` bajo `**\bin\**`/`**\obj\**`) sin abrir esas carpetas en general — deshabilitada por defecto, opt-in por proyecto vía `security.paths_deny_exceptions`.
- **`validate_tool_path()`**: Todas las tools de la capa 1 validan rutas mediante este método. Para operaciones de escritura/borrado sin grant, se devuelve un ticket JSON `permission_required`. Las lecturas en `paths_allow` pasan directamente (sin ticket).
- **Rate limiting por operación**: Rate limiter de ventana deslizante (`security.rate_limit_commands_per_minute`) aplicado independientemente por tipo de operación (lectura/escritura) en `validate_tool_path()`. Deshabilitado cuando se configura en 0.
- **Escaneo de secretos**: Contenido de archivos y medios escaneado en busca de credenciales (tokens de GitHub, claves AWS, claves privadas, cadenas de conexión de BD, etc.) en `fs_read`/`fs_read_media`/salida de shell/entradas del diario — solo advierte, nunca bloquea. Configurable vía `security.secret_scanning_enabled`.
- **Truncado de salida**: Toda la salida de shell está limitada a 1 MiB para prevenir problemas de memoria. La salida truncada se marca con un aviso.
- **Limpieza de árbol de procesos**: Los comandos que exceden el timeout usan `taskkill /T /F` para terminar recursivamente todos los procesos hijos, seguido de un reap del handle del proceso original para evitar fugas de recursos de I/O asíncrono a nivel OS.
- **Registro de auditoría**: Cada operación se registra (buffer circular, 10k entradas) con datos sensibles automáticamente ofuscados.
- **Limitación conocida — el conector MCP `Filesystem` genérico (oficial), si también está habilitado con acceso de escritura a la carpeta de este repo, evade todas las protecciones anteriores.** Escribe directamente al disco sin tickets, sin `confirm_code`, sin registro de auditoría — el modelo de seguridad de este servidor solo cubre las tools que *este* servidor expone, no el repositorio como archivo en disco. No hay fix de código posible desde este proyecto; si también usás el conector oficial `Filesystem` en el mismo cliente MCP, evitá darle acceso de escritura a la ruta de este repo, o aceptá que es un canal de escritura paralelo sin protección hacia tu propia configuración de seguridad.

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
| Git Bash / bash | `"bash"` | No | Sí (`.sh`) | `git --exec-path` o `OPENCODE_GIT_BASH_PATH` |

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

Editá `~/.personal-mcp/config.json` para personalizar. Se mantiene un espejo de solo lectura de este archivo en la raíz del repo (`config.json`) por conveniencia — ejecutá `sync-config.ps1` para refrescarlo desde la copia oficial. Ver [`CONFIG-GUIA.md`](CONFIG-GUIA.md) para una explicación en lenguaje simple, no técnica, de cada campo.

- **Configuración interactiva**: Usá `python configure_paths.py` para gestionar tus directorios permitidos sin editar el JSON manualmente.
- **Configuración de ejemplo**: Ver `config.demo.json` para una plantilla segura y optimizada para productividad.
- `security.paths_allow`: Directorios accesibles para lecturas sin ticket. En este deployment, deliberadamente configurado como `["C:\\"]` (todo el disco) — escritura/borrado sigue requiriendo ticket explícito. El default para una instalación nueva es acotado (ej. `~/Repos`, `~/Desktop`, `~/OneDrive`, `~/.personal-mcp`); ampliá solamente si entendés que `paths_deny` se convierte en tu único control real de lectura.
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
