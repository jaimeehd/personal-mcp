# Soporte Linux/macOS para personal-mcp ✅ COMPLETADO

> **Estado: COMPLETADO** — implementado en los 5 commits de la rama `feat/linux-support`,
> mergeados a `main` en v1.4.33 (2026-07-24). Este archivo se mantiene como referencia
> de arquitectura.

## Resumen de implementación

| Fase | Descripción | Archivos | Estado |
|------|-------------|----------|--------|
| 1 | OS abstraction layer (oslayer) | `src/oslayer/` (confirm, system, process) | ✅ |
| 2 | Shells + Resolver multiplataforma | `src/shell_resolver.py`, `src/config.py` | ✅ |
| 3 | Health tools cross-platform | `src/layers/layer5_health.py` | ✅ |
| 4 | Instalación + Config | `install.sh`, `sync-config.sh` | ✅ |
| 5 | Tests + CI | `.github/workflows/ci.yml`, `tests/conftest.py` | ✅ |

## Arquitectura final

### `src/oslayer/` — Capa de abstracción OS

Cada archivo expone funciones con interfaz idéntica en ambos OS:

| Archivo | Windows | Linux | macOS |
|---------|---------|-------|-------|
| `confirm.py` | `MessageBoxW` (ctypes) | zenity → kdialog → notify-send → /tmp file | `osascript` |
| `system.py` | `GlobalMemoryStatusEx` + `GetTickCount64` | `/proc/meminfo` + `/proc/uptime` | `sysctl` hw.memsize + `ctypes` (Darwin) |
| `process.py` | `psutil.Process.children().kill()` | `psutil.Process.children().kill()` | `psutil.Process.children().kill()` |

### Shell Registry (`src/shell_resolver.py`)

| Shell | Windows | Linux | macOS |
|-------|---------|-------|-------|
| powershell | ✅ | — | — |
| pwsh | ✅ | ✅ | ✅ |
| cmd | ✅ | — | — |
| bash | ✅ (Git Bash) | ✅ | ✅ |
| zsh | — | ✅ | ✅ |
| fish | — | ✅ | — |
| sh | — | ✅ | ✅ |

## Dependencias

- `psutil` — ahora obligatorio (reemplaza `taskkill` para matar procesos, y se usa en health)
- `pywin32` — **opcional** (solo Windows, para funcionalidad específica de ese OS)

## CI

Matriz de GitHub Actions: `ubuntu-latest` + `windows-latest`, Python 3.11–3.13, más un job
de lint (`ruff`) y uno de security-audit.

## Notas para mantenimiento futuro

- Al agregar una nueva shell al registry, actualizar `SHELL_REGISTRY` en `shell_resolver.py`
  y `get_default_shell()`.
- Al agregar una nueva tool que dependa del OS, agregar la abstracción en `oslayer/` y
  llamarla desde la tool, no con conditionales `sys.platform` en la capa de herramienta.
- `confirm_popup.py` ahora delega a `oslayer/confirm.py` — tocar solo `oslayer/` para
  nuevos métodos de notificación.
- Para headless Linux (sin `$DISPLAY`), el popup cae a archivo en `/tmp` + log warning.
