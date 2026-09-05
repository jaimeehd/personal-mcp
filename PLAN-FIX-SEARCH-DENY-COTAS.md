# PLAN-FIX — Bypass `paths_deny` en walks + cotas anti-DoS

> Documento de ejecución para cualquier agente. Sin ambigüedad: qué tocar, cómo, qué tests agregar, cómo verificar.
> Alcance decidido por el dueño (2026-09-04): **conteo por patrón (no rutas), cotas configurables con default, alcance completo**.
> Repo: `personal-mcp` v1.4.82. Ejecutar siempre desde la raíz del repo (carpeta que contiene `.venv/`).

---

## 0. Cómo usar este documento

1. Implementar en orden: **Fase 1 → Fase 2 → Fase 3 → Fase 4**.
2. No hacer nada fuera de `Alcance`. Lo listado en `No-hacer` está prohibido en este cambio.
3. Cada fase termina con sus tests en verde antes de pasar a la siguiente.
4. Al final: `pytest` completo + `ruff` + actualización de `CHANGELOG.md` (una entrada).

---

## 1. Objetivo y alcance

### 1.1. Problemas a cerrar

**P1 — Bypass `paths_deny` en herramientas recursivas.**
`fs_search_impl` (`src/layers/layer1_filesystem.py:293`) valida solo el directorio base con `security.resolve_and_validate(path)`. `_fs_search_sync` (`:263-290`) itera cada archivo con `_walk_files_no_symlinks` sin chequeo deny por archivo y devuelve contenido (`:283` → `f"{rel}:{lineno}: {line[:120]}"`).
Consecuencia: `fs_read(<repo>/.env)` se bloquea por `**/.env*`, pero `fs_search(path="<repo>", pattern="password")` devuelve el contenido de ese mismo `.env`. Mismo defecto en los 9 walks de §4.3.

**P2 — Falta de cotas (DoS accidental o inducido).**
7 vectores sin límite en §5 (timeout shell, sesiones/spawns, zip-bomb, media, read_multi, conteo pre-ticket, `mcp_log`).

### 1.2. Decisiones ya tomadas (no re-discutir)

- **D1 — Semántica deny:** omitir el archivo + **reportar conteo por patrón**, sin rutas. Ej: `[skipped 3 denied file(s) by paths_deny: **/.env*×2, **/.ssh/**×1]`. Ni silencio total ni fail-closed total ni listado de rutas.
- **D2 — Cotas configurables** en `src/config.py` con defaults seguros. Nada hardcodeado sin knob. Config vieja sin esos campos debe cargar con defaults (pydantic lo hace solo; no escribir migración manual).
- **D3 — Alcance completo:** los 9 walks + las 7 cotas en un mismo cambio, no solo el mínimo de exfiltración.

### 1.3. No-hacer en este cambio

- No tocar `permissions.py` (grants, HMAC, TTL), `audit.py`, `log.py`, `script_analyzer.py`, capa SSH, `sh_session` interactiva, Job Objects, multi-proceso.
- No renombrar tools ni cambiar firmas existentes salvo agregar el helper nuevo y los campos de config nuevos.
- No exponer rutas absolutas resueltas en mensajes nuevos (usar relativo o conteo).

---

## 2. Prerrequisitos y baseline

- Python del venv: `.\.venv\Scripts\python` (Windows) / `.venv/bin/python` (Linux/macOS). Nunca el `python` del sistema.
- Baseline antes de tocar nada (guardar salida):
  ```powershell
  .\.venv\Scripts\python -m pytest tests/ -q
  # esperado: ~536 passed, 1 skipped (ResourceWarning preexistente en test_shell_resolver.py)
  ```
- Archivos clave:
  - `src/security.py` — `SecurityValidator._matched_deny_pattern:76`, `_deny_exception_applies:85`, `resolve_and_validate:116`, `validate_file_count:263`.
  - `src/config.py` — `SecurityConfig:171`, `ShellConfig:193`, `LogConfig:209`, `CommandPolicy.is_script_readonly:130`.
  - `src/layers/layer1_filesystem.py` — walks §4.3.
  - `src/layers/layer2_shell.py` — `sh_exec_impl:724`, `ShellManager`, `SpawnManager`.
  - `src/layers/layer5_health.py:248` — `mcp_log`.
  - `tests/conftest.py` — fixtures `test_config`, `security`, `temp_home` (`paths_deny` de test: `["**\\node_modules\\**", "**\\.git\\**"]`).

---

## 3. Fase 1 — Helper central `is_denied_fast` (obligatorio primero)

### 3.1. Dónde

`src/security.py`, dentro de `class SecurityValidator`, junto a `_matched_deny_pattern`.

### 3.2. Firma exacta

```python
def is_denied_fast(self, candidate: str | Path, operation: str = "read") -> str | None:
```

- `candidate`: ruta ya resuelta o sin resolver del archivo encontrado en el walk. NO llamar a `Path.resolve()`, `os.path.realpath()`, ni `check_granted()` aquí (caro ×10k archivos).
- Retorna: el patrón `paths_deny` que matchea (str) si está denegado y NO aplica excepción; `None` si está permitido.
- Implementación obligatoria (reusar, no duplicar):
  ```python
  p = Path(candidate) if isinstance(candidate, str) else candidate
  denied = self._matched_deny_pattern(p)
  if not denied:
      return None
  if self._deny_exception_applies(p, operation):
      return None
  return denied
  ```
- Nota: `_matched_deny_pattern` hace `str(resolved).replace("\\","/")` + `fnmatch` puro. No cambiar su semántica en este cambio (la divergencia con el `core`-strip de `layer1:1113` se documenta, no se unifica aquí).

### 3.3. Tests Fase 1 (`tests/test_security.py`)

- `test_is_denied_fast_env`: config con `paths_deny=["**/.env*"]`; `is_denied_fast("/repo/.env")` → `"**/.env*"`; `is_denied_fast("/repo/app.py")` → `None`.
- `test_is_denied_fast_exception_read_vs_delete`: con `paths_deny=["**/bin/**"]`, `paths_deny_exceptions=["**/bin/**"]`, ext `.dll`: `is_denied_fast(".../bin/a.dll","read")` → `None`; con `"delete"` → patrón (la excepción solo vale para `read`).
- `test_is_denied_fast_no_resolve_cost`: mock `Path.resolve` para asegurar que el helper no lo llama (o al menos no llama a `perm_manager.check_granted`).

---

## 4. Fase 2 — Aplicar filtro deny a los 9 walks

### 4.1. Patrón de código obligatorio (igual en los 9)

En cada loop de walk, antes de `stat()/read/hash/copy`:

```python
from collections import Counter
denied_counter: Counter[str] = Counter()
# ... dentro del loop, con `f: Path` del archivo candidato:
deny_pat = security.is_denied_fast(f, "read")  # "read" salvo que el impl sea delete (ver 4.3)
if deny_pat:
    denied_counter[deny_pat] += 1
    continue
```

Al final, si `denied_counter` no vacío, anexar al retorno (nunca rutas):

```python
if denied_counter:
    parts = ", ".join(f"{pat}×{n}" for pat, n in denied_counter.most_common())
    result += f"\n[skipped {sum(denied_counter.values())} denied file(s) by paths_deny: {parts}]"
```

Para funciones que retornan lista/str multi-línea, el sufijo va como última línea. Para `fs_compress` va en el mensaje `Created ... (N file(s), skipped M denied)`.

### 4.2. Regla `operation` por tool

- Lectura/contenido/nombres: `"read"` → `search, find, list, tree, snapshot, disk_usage, duplicates, compress` (comprimir es lectura del origen; el destino ya se valida con `resolve_and_validate(output,"write")`).
- Destructivo: `fs_batch` con `operation in ("copy","move")` usa `deny_operation` real al filtrar origen: `security.is_denied_fast(f, "read")` para listar + validación de destino ya existente (`M-F6`) intacta. No cambiar lógica de grants de batch.

### 4.3. Los 9 sitios (archivo `src/layers/layer1_filesystem.py`)

1. **`_fs_search_sync:263`** — filtro antes de `:279` (`stat`) y `:281` (`read_text`). El `exclude_patterns` param existente se mantiene; deny es adicional y siempre activo.
2. **`_fs_find_sync:315`** — además **migrar `rpath.rglob(:320)` → `_walk_files_no_symlinks(rpath)`**. Hoy `find` no tiene el fix A-1 de symlinks. Mantener filtros `min_size/max_size/days_old/max_results`. No exponer contenido, pero sí filtrar nombres denied.
3. **`_fs_list_sync:95`** — solo rama `recursive=True` (`os.walk(:99)`). Rama `scandir` no-recursiva también filtra por archivo (barato, 1 nivel).
4. **`_fs_tree_sync:158` / `_tree:164`** — filtrar archivos y podar directorios denied (`dirnames[:]` si el dir matchea deny y no aplica excepción).
5. **`_fs_snapshot_sync:453`** — filtrar antes de agregar al dict snapshot.
6. **`fs_batch_impl:409`** — descubrimiento `:420-422` (`iterdir` + `is_file()` sigue symlinks): agregar `not f.is_symlink()` + `is_denied_fast(f,"read")`. `validate_file_count` se mantiene después del filtrado.
7. **`_compress_sync:1186`** — en rama archivo `:1195` y en loop `:1201`: `is_denied_fast(f,"read")` → skip + contador. Mantener skip `M-F8` del output-sobre-sí-mismo. Mensaje final incluye `skipped M denied`.
8. **`_disk_usage_sync:1007`** — skip antes de `stat`/atribución a bucket. El total y conteos no incluyen denied.
9. **`_find_duplicates_sync:874`** — skip en fase 1 antes de agrupar por tamaño (ahorro real, no cosmético).

### 4.4. Tests Fase 2 (`tests/test_filesystem.py`)

Fixture común (crear en cada test, no global): bajo `temp_home/Repos/proj/`: `app.py` (`"hello"`), `.env` (`"SECRET=abc123"`), `.ssh/id_rsa` (`"private"`), `node_modules/dep/index.js`.
Config de test con `paths_deny` ampliado a `["**/node_modules/**","**/.git/**","**/.env*","**/.ssh/**"]` (los fixtures `conftest.py:36` no traen `.env`/`.ssh`; construir `SecurityValidator` propio en el test).

- `test_search_skips_denied_no_leak`: `fs_search_impl(proj,"SECRET")` → assert `"abc123" not in out`, `"app.py" in out` o `"No matches"`, y `"skipped" in out` + `"**/.env*"` en el sufijo.
- `test_find_skips_denied`: `fs_find_impl(proj)` → `".env" not in out`, `"id_rsa" not in out`.
- `test_compress_skips_denied`: `fs_compress_impl([proj], out.zip)` → `out.zip` existe; abrir con `zipfile` y assert ningún miembro termina en `.env` ni contiene `.ssh`.
- `test_batch_skips_denied`: `fs_batch_impl(proj,"copy",dest)` con `dry_run=True` → ningún `Would copy .env`.
- `test_tree_list_snapshot_skip_denied`: uno por función, assert de ausencia + sufijo `skipped`.
- `test_find_no_symlink_follow`: crear symlink a archivo fuera de allow (skip si sin permisos, patrón existente `:1232`); assert no aparece.

Criterio de aceptación Fase 2: el PoC `fs_search` sobre repo con `.env` ya no devuelve el secreto, con y sin `recursive`.

---

## 5. Fase 3 — Las 7 cotas (todas configurables)

### 5.1. Nuevos campos en `src/config.py` (nombres exactos, defaults exactos)

```python
class SecurityConfig:
    max_extract_bytes: int = 500 * 1024 * 1024   # 500 MB descomprimido total
    max_extract_files: int = 5000
    max_extract_ratio: float = 100.0              # suma uncompressed / suma compressed
    max_media_bytes: int = 20 * 1024 * 1024      # 20 MB
    max_read_multi_bytes: int = 20 * 1024 * 1024 # 20 MB acumulado

class ShellConfig:
    max_timeout_seconds: int = 300
    max_sessions: int = 10
    max_spawns: int = 20

class LogConfig:
    mcp_log_max_lines: int = 1000
    mcp_log_max_bytes: int = 2 * 1024 * 1024     # 2 MB ventana de cola
```

Validación: `max_* >= 1`, `max_extract_ratio >= 1.0` (pydantic `ge=1`). `load()` sin cambios — pydantic aplica defaults a config vieja.

### 5.2. Especificación por cota

**C1 — `sh_exec`/`sh_script`/`ssh_exec` timeout máx.**
Dónde: `sh_exec_impl (layer2_shell.py:724)`, wrapper `sh_script`, `ssh_exec_impl (layer3_ssh.py:119)`.
Lógica primera línea del impl: `timeout = max(1, min(int(timeout), security.config.shell.max_timeout_seconds))`.
Mensaje de timeout existente intacto.

**C2 — Tope sesiones y spawns.**
Dónde: `ShellManager.start()` (usa `config.shell.session_timeout_seconds` en `server.py:249`) y `SpawnManager.spawn()`.
Lógica: `if len(active) >= max: return "Error: too many active shell sessions (max N)"` / `"Error: too many spawned processes (max N)"`. Contar solo vivos (`psutil.pid_exists` para spawns, `get_session` no expirada para sesiones). No matar nada automáticamente.

**C3 — `fs_extract` zip-bomb.**
Dónde: `_safe_extract_sync (layer1:1224)` + `fs_extract_impl:1266`.
Lógica: antes de escribir, iterar `zf.infolist()`: `total_c = sum(i.compress_size)`, `total_u = sum(i.file_size)`, `n = len(infolist no-dir)`. Si `n > max_extract_files` → `return "Error: zip has N files (max M)"`. Si `total_u > max_extract_bytes` → `Error`. Si `total_c > 0 and total_u/total_c > max_ratio` → `Error: zip ratio suspicious (...)`. Además durante la escritura llevar acumulado y abortar si se supera `max_extract_bytes` (el header puede mentir).
Tests: zip con 6000 archivos vacíos → rechazado; zip 1KB→50MB ceros → rechazado por ratio.

**C4 — `fs_read_media` tope.**
Dónde: `fs_read_media_impl:833`. Antes de `read_bytes(:841)`: `size = stat().st_size; if size > max_media_bytes: return f"Error: media file too large ({size:,} bytes, max {max:,} bytes)"`.

**C5 — `fs_read_multi` límites.**
Dónde: `fs_read_multi_impl:777`. Primera línea: `security.validate_file_count(len(paths))` (reusa `rate_limit_files_per_operation=100`). Acumular bytes leídos; si supera `max_read_multi_bytes` → cortar y anexar `"[truncated: cumulative limit ...]"`. Cada archivo sigue pasando por `fs_read_impl` (deny intacto).

**C6 — `fs_delete_directory` conteo post-ticket.**
Dónde: wrapper `fs_delete_directory (layer1:1470-1485)`. Hoy: `validate(read)` → `_count_dir_contents_sync` → `validate(delete)`. Nuevo orden: `validate(read)` → `validate(delete)`; si delete devuelve ticket/error → retornar preview SIN conteo + ticket (mensaje: `"Contains: unknown (approve first to preview)"` + ticket). Solo si delete ya autorizado → correr `_count_dir_contents_sync` con timeout 10s (`asyncio.wait_for`); si timeout → proceder sin conteo (`"Contains: too large to preview"`). Nunca hacer walk costoso sin autorización.
Preservar mensaje existente cuando hay grant: `About to delete... Contains N file(s), M bytes`.

**C7 — `mcp_log` clamp + tail.**
Dónde: `mcp_log (layer5_health.py:248)`. Lógica: `if not level: level="INFO"` (fix IndexError `level[0]` en `:256`); `lines = max(1, min(int(lines), config.log.mcp_log_max_lines))`; no `read_text()` completo de 10MB: abrir en binario, `seek` desde el final hasta `mcp_log_max_bytes`, decodificar `errors="replace"`, filtrar por `level[0]`, devolver últimas `lines`. Firma `(lines=50, level="INFO")` intacta.

**Extra — `fs_info` hash por chunks.**
`_fs_info_sync:353` hoy `read_bytes()` de golpe hasta 100MB (`:368-369`). Cambiar a `hashlib.sha256` por chunks 64KB con `open(rb)`. Mismo mensaje `(skipped...)` sobre 100MB.

### 5.3. Tests Fase 3

- `tests/test_shell.py`: `test_exec_timeout_clamped` (timeout 99999 → efectivo 300, mock `asyncio.wait`), `test_max_sessions`, `test_max_spawns`.
- `tests/test_filesystem.py`: `test_extract_rejects_bomb_ratio`, `test_extract_rejects_too_many_files`, `test_read_media_too_large`, `test_read_multi_file_count`, `test_delete_directory_no_prewalk_without_ticket` (assert `_count_dir_contents_sync` no llamado cuando no hay grant, via monkeypatch).
- `tests/test_config.py`: defaults nuevos presentes; config vieja (sin campos) carga OK.
- `tests/test_layer5_health.py`: `test_mcp_log_clamp` (`lines=0` → 1000, `lines=999999` → 1000, `level=""` no lanza).

---

## 6. Fase 4 — Docs, CHANGELOG, verificación

1. `README.md` § Seguridad: 2 líneas (deny ahora aplica por archivo en walks + sufijo `skipped`; cotas configurables tabla).
2. `AGENTS.md`: actualizar conteo tests y regla de walks (deny por archivo obligatorio para todo walk nuevo futuro).
3. `CONFIG-GUIA.md`: nuevos campos con defaults y efecto.
4. `CHANGELOG.md`: una entrada `[1.4.83]` con `Added/Fixed/Tests` (seguir estilo existente: Causa raíz → Fix → Tests → Verificado).
5. Verificación final obligatoria:
   ```powershell
   .\.venv\Scripts\python -m pytest tests/ -q
   .\.venv\Scripts\python -m ruff check src/ tests/
   .\.venv\Scripts\python -c "import sys; sys.path.insert(0,'.'); from src.server import create_app; create_app(); print('Server OK')"
   ```
   Criterio: `pytest` 0 fallos (1 skipped permitido), `ruff` limpio, smoke `Server OK`.

---

## 7. Checklist de aceptación (todo debe ser SÍ)

- [ ] `fs_search` sobre repo con `.env` con secreto no devuelve el secreto y reporta `skipped ... **/.env*`.
- [ ] `fs_find/list/tree/snapshot/batch/compress/disk_usage/duplicates` omiten denied + sufijo conteo, sin rutas.
- [ ] Excepción `bin/*.dll` en `read` sigue visible; en `delete` sigue bloqueada.
- [ ] `sh_exec(timeout=99999)` se clampa a 300; sesiones 11ª rechazada; spawn 21º rechazado.
- [ ] Zip-bomb por ratio / por archivos / por bytes rechazado antes de escribir.
- [ ] `fs_read_media` 30MB → `Error: media file too large`; `read_multi` 150 paths → `Exceeds max files`.
- [ ] `fs_delete_directory` sin grant no hace walk (verificado con monkeypatch).
- [ ] `mcp_log(lines=0)` → ≤1000 líneas; `level=""` no crashea.
- [ ] Config vieja carga con defaults; `pytest` + `ruff` + smoke verdes.
- [ ] `CHANGELOG/README/AGENTS/CONFIG-GUIA` actualizados. Sweep de sanitización antes de commit (`git grep` de rutas personales) limpio.

---

## 8. Notas de implementación (trampas conocidas)

- `Path.resolve()` en Windows normaliza mayúsculas (`Temp`→`temp`); en `is_denied_fast` NO resolver (solo match string). El `resolve()` real ya ocurrió en el dir base del walk.
- `os.walk(followlinks=False)` + filtro `is_symlink()` ya existe en `_walk_files_no_symlinks:244` — reusar en `find` (no inventar otro walker).
- `_SEMANTIC_FAILURE_TOOLS` en `server.py`: si agregás tool nueva no aplica; estos son impls existentes, no agregar nada ahí.
- `check_granted()` consume grants `SINGLE` — por eso `is_denied_fast` jamás lo llama; el walk es `read` y no debe gastar grants.
- `tickets.jsonl`/`audit.json`/`server.log` son multi-proceso; no asumir estado en memoria entre procesos en los tests (crear `SecurityValidator` nuevo por test, como indica `conftest.py`).
