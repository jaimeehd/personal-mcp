"""Confirmation code display — delegates to oslayer for cross-platform support.

This is the ONLY channel where the confirmation code is visible. Never return it
in any MCP tool response (fs_request_allow, security_pending, etc.) — doing so
would reopen the auto-approval gap this module exists to close.

Runs in a separate daemon thread because native dialogs block until dismissed,
and we don't want to block the server's asyncio event loop while waiting for
the user to be in front of their screen.
"""

from src.oslayer.confirm import show_confirmation_code, show_confirmation_code_batch

__all__ = ["show_confirmation_code", "show_confirmation_code_batch"]