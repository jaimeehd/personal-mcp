# Plan de soporte Linux para personal-mcp

## Estado actual: **Solo Windows** (v1.4.32)

### Dependencias hard-coded Windows
| Archivo | Qué hace | Bloqueador Linux |
|---------|----------|------------------|
| `src/confirm_popup.py` | `ctypes.windll.user32.MessageBoxW` — popup nativo para confirm_code | **Crítico**: sin esto no hay HITL |
| `src/log.py` | `ctypes.windll.kernel32.GlobalMemoryStatusEx` + `_MEMORYSTATUSEX` struct | Health check memory info |
| `src/log.py` | `ctypes.windll.kernel32.GetTickCount64` | Uptime en health_check |
| `src/layers/layer5_health.py` | `_get_uptime()` usa `ctypes.windll.kernel32.GetTickCount64` | Uptime |
| `src/layers/layer2_shell.py` | `_kill_process_tree()` usa `taskkill /pid /T /F` | Mata procesos en timeout |
| `src/layers/layer2_shell.py` | `SHELL_REGISTRY` solo tiene `powershell`/`pwsh`/`cmd`/`bash` (Git Bash) | Shells |
| `src/shell_resolver.py` | `_find_git_bash()` busca `bash.exe` en rutas Windows | Resolución bash |
| `install.ps1` / `sync-config.ps1` | Scripts PowerShell para instalar/configurar | Instalación |

---

## Estrategia: **Capa de abstracción OS** (no fork)

Crear `src/oslayer.py` con implementaciones Windows/Linux detrás de interfaz común.

---

## Fase 1: Abstracciones críticas (HITL + Health) — **Bloqueante**

### 1.1 `confirm_popup.py` → `src/oslayer/confirm.py`

```python
# Interfaz
def show_confirmation_code(resource: str, operation: str, code: str) -> None: ...
def show_confirmation_code_batch(resources: list[str], operation: str, code: str) -> None: ...

# Windows: ctypes.MessageBoxW (actual)
# Linux: 
#   - zenity --info --text="..." (GNOME)
#   - kdialog --msgbox "..." (KDE)  
#   - notify-send + archivo temporal + xdg-open (fallback)
#   - Si no hay display: escribir a /tmp/confirm_<ticket>.txt + log warning
```

**Regla de oro**: El código **nunca** se devuelve por MCP, solo se muestra al humano.

### 1.2 `log.py` memory/uptime → `src/oslayer/system.py`

```python
def available_memory_info() -> dict | None:  # total_gb, free_gb, free_pct
def uptime_seconds() -> float | None:        # segundos desde boot
def memory_pressure_hint() -> str:            # string para log si <25% libre
```

- **Linux**: leer `/proc/meminfo` + `/proc/uptime` (cero subprocess, puro I/O)
- **Windows**: `GlobalMemoryStatusEx` + `GetTickCount64` (actual)

### 1.3 `layer2_shell.py` process kill → `src/oslayer/process.py`

```python
async def kill_process_tree(pid: int) -> None:  # mata árbol de procesos
async def reap_after_kill(process: asyncio.Process) -> None:  # espera reap
```

- **Linux**: `os.killpg(os.getpgid(pid), signal.SIGKILL)` + `await process.wait()`
- **Windows**: `taskkill /T /F` (actual)

---

## Fase 2: Shells + Resolver — **Requerido para Layer 2**

### 2.1 `shell_resolver.py` → `SHELL_REGISTRY` multiplataforma

```python
SHELL_REGISTRY = {
    # Windows
    "powershell": ShellInfo(..., executable="powershell.exe", ...),
    "pwsh": ShellInfo(..., executable="pwsh.exe", ...),
    "cmd": ShellInfo(..., executable="cmd.exe", ...),
    # Linux
    "bash": ShellInfo(
        name="bash", executable="bash",
        command_args=["-c"], session_args=[], script_args=["-c"],
        workdir_prefix='cd "{wd}" && ',
    ),
    "zsh": ShellInfo(...),
    "fish": ShellInfo(...),
    "sh": ShellInfo(...),  # POSIX sh
}
```

### 2.2 `_find_executable()` genérico

```python
def _find_executable(name: str, shell_map: dict) -> str | None:
    if shell_map and name in shell_map: ...
    return shutil.which(name)  # funciona en ambos OS
```

**Eliminar** `_find_git_bash()` — en Linux `bash` está en PATH.

### 2.3 `workdir_prefix` escaping por shell

```python
def escape_workdir(path: str, shell_name: str) -> str:
    if shell_name in ("bash", "zsh", "sh", "fish"):
        return path.replace('"', '\\"')  # bash-style
    if shell_name == "cmd":
        return path.replace('"', '""')
    return path.replace('"', '`"')  # powershell
```

---

## Fase 3: Health tools (Layer 5) — **Adaptar commands**

### 3.1 `health_processes` (top processes)

```python
# Windows actual: powershell Get-Process | Sort-Object CPU -Descending | Select-Object -First N
# Linux: ps aux --sort=-%cpu | head -n $((N+1))
```

### 3.2 `mcp_benchmark` shell_exec test

```python
# Windows: powershell -Command "echo test"
# Linux: bash -c "echo test"
```

---

## Fase 4: Instalación + Config — **UX Linux**

### 4.1 `install.sh` (equivalente a `install.ps1`)

```bash
#!/bin/bash
# 1. Check python3.10+
# 2. python3 -m venv .venv
# 3. .venv/bin/pip install -r requirements.txt
# 4. Crear ~/.personal-mcp/config.json con paths_allow=$HOME
# 5. Registrar en Claude Desktop:
#    ~/.config/Claude/claude_desktop_config.json (Linux)
#    ~/Library/Application Support/Claude/claude_desktop_config.json (macOS)
```

### 4.2 `sync-config.sh` (equivalente a `sync-config.ps1`)

```bash
#!/bin/bash
# Copia ~/.personal-mcp/config.json -> repo/config.json (mirror)
```

### 4.3 `config.json` defaults Linux

```json
{
  "security": {
    "paths_allow": ["$HOME"],
    "paths_deny": ["**/node_modules/**", "**/.git/**", "**/.ssh/**", "**/.aws/**", "**/.env*"]
  },
  "shell": {
    "default_shell": "bash",
    "shell_map": {}
  }
}
```

---

## Fase 5: Tests + CI

### 5.1 `tests/conftest.py` — fixtures OS-aware

```python
@pytest.fixture
def shell_name():
    return "bash" if sys.platform != "win32" else "powershell"
```

### 5.2 GitHub Actions matrix

```yaml
strategy:
  matrix:
    os: [ubuntu-latest, windows-latest]
    python-version: ["3.10", "3.11", "3.12"]
```

---

## Archivos a crear/modificar (resumen)

### Nuevos
| Archivo | Propósito |
|---------|-----------|
| `src/oslayer/__init__.py` | Exports públicos |
| `src/oslayer/confirm.py` | Popup confirm_code (Windows/Linux/fallback) |
| `src/oslayer/system.py` | memory_info, uptime, memory_pressure_hint |
| `src/oslayer/process.py` | kill_process_tree, reap_after_kill |
| `install.sh` | Instalador Linux/macOS |
| `sync-config.sh` | Sync config mirror |

### Modificar
| Archivo | Cambios |
|---------|---------|
| `src/confirm_popup.py` | Delegar a `oslayer.confirm` |
| `src/log.py` | Delegar a `oslayer.system` |
| `src/layers/layer2_shell.py` | Delegar kill/reap a `oslayer.process`; shells dinámicos |
| `src/layers/layer5_health.py` | Delegar uptime/memory a `oslayer.system`; health_processes multiplataforma |
| `src/shell_resolver.py` | Registry multiplataforma; `_find_executable` genérico |
| `src/config.py` | Defaults `shell.default_shell` según OS |
| `requirements.txt` | Añadir `psutil` (ya opcional, hacer obligatorio) |

---

## Estimación de esfuerzo

| Fase | Días | Riesgo |
|------|------|--------|
| 1. Abstracciones HITL + Health | 2-3 | Alto (popup Linux sin display) |
| 2. Shells + Resolver | 1-2 | Medio |
| 3. Health tools | 1 | Bajo |
| 4. Instalación + Config | 1 | Bajo |
| 5. Tests + CI | 1 | Medio |
| **Total** | **6-8 días** | |

---

## Decisiones abiertas

1. **macOS**: ¿soportar? (misma base Linux, solo paths config distintos)
2. **Wayland vs X11**: `zenity`/`kdialog` funcionan en ambos, pero `notify-send` requiere daemon
3. **Headless servers**: Si no hay `$DISPLAY`/`$WAYLAND_DISPLAY`, fallback a archivo en `/tmp` + log warning
4. **systemd integration**: ¿ofrecer unit file para auto-start?

---

## Próximo paso inmediato

Crear `src/oslayer/` con stubs tipados y tests de contrato, luego implementar Windows (mover código actual) y Linux en paralelo.