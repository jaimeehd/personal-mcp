"""Popup nativo de Windows para mostrar el codigo de confirmacion de un ticket.

Este es el UNICO canal donde el codigo de confirmacion es visible. Nunca se
devuelve en la respuesta de ningun tool MCP (fs_request_allow, security_pending,
etc.) - si en el futuro se te ocurre exponerlo ahi "para depurar", se reabre el
gap de auto-aprobacion que este modulo existe para cerrar.

Se ejecuta en un hilo separado (daemon) porque MessageBoxW bloquea hasta que
alguien lo cierra, y no queremos bloquear el event loop de asyncio del servidor
mientras el usuario no esta frente a la pantalla.
"""

import ctypes
import os
import threading

MB_ICONINFORMATION = 0x40
MB_TOPMOST = 0x00040000


def show_confirmation_code(resource: str, operation: str, code: str) -> None:
    if "PYTEST_CURRENT_TEST" in os.environ:
        return

    def _show() -> None:
        message = (
            f"Solicitud de permiso pendiente\n\n"
            f"Recurso: {resource}\n"
            f"Operacion: {operation}\n\n"
            f"Codigo de confirmacion: {code}\n\n"
            f"Usa este codigo en fs_approve(confirm_code=...) para autorizar."
        )
        ctypes.windll.user32.MessageBoxW(
            0, message, "personal-mcp - Confirmar permiso",
            MB_ICONINFORMATION | MB_TOPMOST,
        )

    threading.Thread(target=_show, daemon=True).start()