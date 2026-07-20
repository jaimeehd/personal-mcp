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
from typing import List

MB_ICONINFORMATION = 0x40
MB_TOPMOST = 0x00040000

# 2026-07-19: reintroducido junto con PermissionManager.request_batch() /
# fs_delete_batch. La version anterior de esta funcion listaba cada ruta
# individual - para un lote de 100 archivos eso producia un mensaje de
# MessageBoxW de ~13,000 caracteres que el usuario confirmo que no se podia
# leer (el codigo de confirmacion quedaba fuera de la pantalla visible). El
# preview acotado de abajo mantiene el tamano del mensaje independiente de N,
# a proposito, porque ahora request_batch() ya no limita cuantos archivos
# puede cubrir un solo ticket - si el preview tambien escalara con N, el
# problema original volveria en cuanto alguien borre un lote grande.
MAX_PREVIEW_FILES = 10


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


def show_confirmation_code_batch(resources: List[str], operation: str, code: str) -> None:
    """Same channel and same guarantees as show_confirmation_code, but for a
    request that covers several enumerated resources under one ticket (see
    PermissionManager.request_batch). No limit on len(resources) is enforced
    anywhere in that path by design - see the MAX_PREVIEW_FILES comment above
    for why the popup itself stays a fixed size regardless.
    """
    if "PYTEST_CURRENT_TEST" in os.environ:
        return

    def _show() -> None:
        if len(resources) <= MAX_PREVIEW_FILES:
            file_list = "\n".join(f"  - {r}" for r in resources)
        else:
            shown = resources[:MAX_PREVIEW_FILES]
            remaining = len(resources) - MAX_PREVIEW_FILES
            file_list = "\n".join(f"  - {r}" for r in shown)
            file_list += f"\n  ... y {remaining} archivo(s) mas (lista completa: tool security_pending)"

        message = (
            f"Solicitud de permiso pendiente ({len(resources)} archivos)\n\n"
            f"Operacion: {operation}\n\n"
            f"Archivos:\n{file_list}\n\n"
            f"Codigo de confirmacion: {code}\n\n"
            f"Este codigo autoriza exactamente los {len(resources)} archivos de "
            f"la solicitud original (ver security_pending para la lista completa "
            f"si no se muestran todos arriba), nada mas. "
            f"Usalo en fs_approve(confirm_code=...) para autorizar."
        )
        ctypes.windll.user32.MessageBoxW(
            0, message, "personal-mcp - Confirmar permiso (lote)",
            MB_ICONINFORMATION | MB_TOPMOST,
        )

    threading.Thread(target=_show, daemon=True).start()