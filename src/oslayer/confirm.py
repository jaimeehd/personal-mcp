"""Confirmation popup abstraction — Windows + Linux.

This is the ONLY channel where the confirmation code is visible to the user.
It is NEVER returned in any MCP tool response.
"""

import os
import sys
import threading
from typing import List

# Threshold for preview in batch popups
MAX_PREVIEW_FILES = 10


def _detect_display() -> bool:
    """Check if we have a graphical display available."""
    if sys.platform == "win32":
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def _show_windows(resource: str, operation: str, code: str, batch: bool, files: List[str] | None = None) -> None:
    """Windows native MessageBoxW implementation."""
    import ctypes

    MB_ICONINFORMATION = 0x40
    MB_TOPMOST = 0x00040000

    if batch and files:
        if len(files) <= MAX_PREVIEW_FILES:
            file_list = "\n".join(f"  - {r}" for r in files)
        else:
            shown = files[:MAX_PREVIEW_FILES]
            remaining = len(files) - MAX_PREVIEW_FILES
            file_list = "\n".join(f"  - {r}" for r in shown)
            file_list += f"\n  ... y {remaining} archivo(s) más (lista completa: tool security_pending)"

        message = (
            f"Solicitud de permiso pendiente ({len(files)} archivos)\n\n"
            f"Operacion: {operation}\n\n"
            f"Archivos:\n{file_list}\n\n"
            f"Codigo de confirmacion: {code}\n\n"
            f"Este codigo autoriza exactamente los {len(files)} archivos de "
            f"la solicitud original (ver security_pending para la lista completa "
            f"si no se muestran todos arriba), nada mas. "
            f"Usalo en fs_approve(confirm_code=...) para autorizar."
        )
        title = "personal-mcp - Confirmar permiso (lote)"
    else:
        message = (
            f"Solicitud de permiso pendiente\n\n"
            f"Recurso: {resource}\n"
            f"Operacion: {operation}\n\n"
            f"Codigo de confirmacion: {code}\n\n"
            f"Usa este codigo en fs_approve(confirm_code=...) para autorizar."
        )
        title = "personal-mcp - Confirmar permiso"

    def _show() -> None:
        ctypes.windll.user32.MessageBoxW(
            0, message, title,
            MB_ICONINFORMATION | MB_TOPMOST,
        )

    threading.Thread(target=_show, daemon=True).start()


def _show_linux(resource: str, operation: str, code: str, batch: bool, files: List[str] | None = None) -> None:
    """Linux implementation using zenity, kdialog, notify-send, or file fallback."""
    if batch and files:
        if len(files) <= MAX_PREVIEW_FILES:
            file_list = "\n".join(f"  - {r}" for r in files)
        else:
            shown = files[:MAX_PREVIEW_FILES]
            remaining = len(files) - MAX_PREVIEW_FILES
            file_list = "\n".join(f"  - {r}" for r in shown)
            file_list += f"\n  ... y {remaining} archivo(s) más (lista completa: tool security_pending)"

        message = (
            f"Solicitud de permiso pendiente ({len(files)} archivos)\n\n"
            f"Operación: {operation}\n\n"
            f"Archivos:\n{file_list}\n\n"
            f"Código de confirmación: {code}\n\n"
            f"Este código autoriza exactamente los {len(files)} archivos de "
            f"la solicitud original (ver security_pending para la lista completa "
            f"si no se muestran todos arriba), nada más. "
            f"Úsalo en fs_approve(confirm_code=...) para autorizar."
        )
        title = "personal-mcp - Confirmar permiso (lote)"
    else:
        message = (
            f"Solicitud de permiso pendiente\n\n"
            f"Recurso: {resource}\n"
            f"Operación: {operation}\n\n"
            f"Código de confirmación: {code}\n\n"
            f"Usa este código en fs_approve(confirm_code=...) para autorizar."
        )
        title = "personal-mcp - Confirmar permiso"

    def _run_zenity() -> bool:
        try:
            subprocess.run(
                ["zenity", "--info", f"--title={title}", f"--text={message}", "--no-wrap"],
                check=True, timeout=5,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            return True
        except (FileNotFoundError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return False

    def _run_kdialog() -> bool:
        try:
            subprocess.run(
                ["kdialog", "--msgbox", message, title],
                check=True, timeout=5,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            return True
        except (FileNotFoundError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return False

    def _run_notify_send() -> bool:
        try:
            # notify-send doesn't block, but at least shows the code
            subprocess.run(
                ["notify-send", "-u", "critical", "-t", "30000", title, message],
                check=True, timeout=3,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            return True
        except (FileNotFoundError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return False

    def _write_fallback() -> None:
        """Last resort: write code to a temp file and log warning."""
        import tempfile
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", prefix="personal-mcp-confirm-", suffix=".txt",
                delete=False, encoding="utf-8"
            ) as f:
                f.write(f"{title}\n\n{message}\n")
                path = f.name
            # Also print to stderr so it shows in server logs
            print(f"[CONFIRMATION CODE] {code} — written to {path}", file=sys.stderr, flush=True)
        except Exception:
            print(f"[CONFIRMATION CODE] {code} — could not write fallback file", file=sys.stderr, flush=True)

    def _show() -> None:
        # Try GUI dialogs in order of preference
        if _run_zenity():
            return
        if _run_kdialog():
            return
        if _run_notify_send():
            # notify-send doesn't block, but at least user sees it
            return
        # No display or all dialogs failed — write to temp file
        _write_fallback()

    import subprocess
    threading.Thread(target=_show, daemon=True).start()


def _show_macos(resource: str, operation: str, code: str, batch: bool, files: List[str] | None = None) -> None:
    """macOS implementation using osascript."""
    if batch and files:
        if len(files) <= MAX_PREVIEW_FILES:
            file_list = "\n".join(f"  - {r}" for r in files)
        else:
            shown = files[:MAX_PREVIEW_FILES]
            remaining = len(files) - MAX_PREVIEW_FILES
            file_list = "\n".join(f"  - {r}" for r in shown)
            file_list += f"\n  ... y {remaining} archivo(s) más (lista completa: tool security_pending)"

        message = (
            f"Solicitud de permiso pendiente ({len(files)} archivos)\n\n"
            f"Operación: {operation}\n\n"
            f"Archivos:\n{file_list}\n\n"
            f"Código de confirmación: {code}\n\n"
            f"Este código autoriza exactamente los {len(files)} archivos de "
            f"la solicitud original (ver security_pending para la lista completa "
            f"si no se muestran todos arriba), nada más. "
            f"Úsalo en fs_approve(confirm_code=...) para autorizar."
        )
        title = "personal-mcp - Confirmar permiso (lote)"
    else:
        message = (
            f"Solicitud de permiso pendiente\n\n"
            f"Recurso: {resource}\n"
            f"Operación: {operation}\n\n"
            f"Código de confirmación: {code}\n\n"
            f"Usa este código en fs_approve(confirm_code=...) para autorizar."
        )
        title = "personal-mcp - Confirmar permiso"

    script = f'display dialog "{message}" with title "{title}" buttons {{"OK"}} default button "OK"'

    def _show() -> None:
        import subprocess
        try:
            subprocess.run(
                ["osascript", "-e", script],
                check=True, timeout=5,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except Exception:
            # Fallback to notify
            try:
                subprocess.run(
                    ["osascript", "-e", f'display notification "{message}" with title "{title}"'],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
            except Exception:
                pass

    threading.Thread(target=_show, daemon=True).start()


def show_confirmation_code(resource: str, operation: str, code: str) -> None:
    """Show confirmation code for a single resource."""
    if "PYTEST_CURRENT_TEST" in os.environ:
        return
    if sys.platform == "win32":
        _show_windows(resource, operation, code, batch=False)
    elif sys.platform == "darwin":
        _show_macos(resource, operation, code, batch=False)
    else:
        _show_linux(resource, operation, code, batch=False)


def show_confirmation_code_batch(resources: List[str], operation: str, code: str) -> None:
    """Show confirmation code for a batch of resources (fs_delete_batch)."""
    if "PYTEST_CURRENT_TEST" in os.environ:
        return
    if sys.platform == "win32":
        _show_windows("", operation, code, batch=True, files=resources)
    elif sys.platform == "darwin":
        _show_macos("", operation, code, batch=True, files=resources)
    else:
        _show_linux("", operation, code, batch=True, files=resources)