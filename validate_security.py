import asyncio
import json
from pathlib import Path

from src.config import AppConfig
from src.server import create_app


async def run_tests():
    app = create_app()
    config = AppConfig.load()

    print("--- Starting Security Validation ---")

    # Helper to extract text from FastMCP result
    def get_text(result_obj):
        # result_obj is often a tuple (content_list, metadata)
        if isinstance(result_obj, tuple) and len(result_obj) > 0:
            content = result_obj[0]
        else:
            content = result_obj

        if isinstance(content, list) and len(content) > 0:
            # Content objects have a .text attribute
            return getattr(content[0], 'text', str(content[0]))
        return str(content)

    # Test 1: Path Hard-Lock via paths_deny (paths_allow puede cubrir todo el
    # disco — el boundary real es paths_deny: ~/.ssh/id_rsa está denegado por
    # defecto en cualquier instalación).
    print("\nTest 1: Path Hard-Lock (paths_deny)...")
    denied_probe = str(Path.home() / ".ssh" / "id_rsa")
    result_obj = await app.call_tool("fs_read", {"path": denied_probe})
    res1 = get_text(result_obj)
    print(f"Result: {res1[:120]}")
    if "Access denied" in res1:
        print("PASSED: Path hard-lock is working.")
    else:
        print("FAILED: Path hard-lock failed.")

    # Test 2: Read inside data_dir (auto-allowed, no ticket needed).
    print("\nTest 2: Read inside data_dir (no ticket expected)...")
    data_dir = Path(config.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    probe_read = data_dir / ".validate_security_read.txt"
    probe_read.write_text("read probe", encoding="utf-8")
    try:
        result_obj = await app.call_tool("fs_read", {"path": str(probe_read)})
        res2 = get_text(result_obj)
        print(f"Result: {res2[:120]}")
        if "Access denied" not in res2 and "permission_required" not in res2:
            print("PASSED: Read in data_dir succeeded without ticket.")
        else:
            print("FAILED: Read in data_dir was blocked.")
    finally:
        probe_read.unlink(missing_ok=True)

    # Test 3: Write inside paths_allow DOES require a ticket (HITL). The
    # confirm_code is only visible via the native popup — a script cannot
    # automate approval, so we only assert the ticket is issued.
    print("\nTest 3: Write inside paths_allow requires ticket (HITL)...")
    allow = config.security.paths_allow
    probe_dir = allow[0] if allow else config.data_dir
    write_target = str(Path(probe_dir) / ".validate_security_probe.txt")
    result_obj = await app.call_tool(
        "fs_write", {"path": write_target, "content": "probe"}
    )
    res3 = get_text(result_obj)
    print(f"Result: {res3[:300]}")
    try:
        data = json.loads(res3)
        if data.get("status") == "permission_required":
            print("PASSED: Write issued permission_required ticket.")
            print("  Aprobación NO automatizable: el confirm_code solo se muestra")
            print("  en el popup nativo (regla HITL). Repetir la llamada original")
            print("  tras aprobar manualmente con fs_approve.")
        else:
            print(f"FAILED: Unexpected payload: {data}")
    except json.JSONDecodeError:
        if "Written" in res3:
            print("WARNING: Write succeeded WITHOUT a ticket — revisar paths_allow/grant.")
        else:
            print(f"FAILED: Result was not a JSON payload: {res3[:200]}")

    # Test 4: Command Whitelist (Outside whitelist). En configs con paths_allow
    # amplio, `curl http://...` puede ser bloqueado por el escaneo de rutas
    # ("p:/" de http://) en vez del mensaje de whitelist — ambos son un bloqueo.
    print("\nTest 4: Command Whitelist (Outside whitelist)...")
    try:
        res4_obj = await app.call_tool("sh_exec", {"command": "curl http://example.com"})
        res4 = get_text(res4_obj)
        print(f"Result: {res4[:160]}")
        if (
            "is not in the allowed command whitelist" in res4
            or "Access denied" in res4
            or "is not in allowed directories" in res4
        ):
            print("PASSED: Command whitelist blocked unauthorized command.")
        else:
            print("FAILED: Command whitelist bypassed.")
    except Exception as e:
        print(f"PASSED: Command blocked by exception: {e}")

    # Test 5: Command Whitelist (Inside whitelist)
    print("\nTest 5: Command Whitelist (Inside whitelist)...")
    try:
        res5_obj = await app.call_tool("sh_exec", {"command": "echo security_validate"})
        res5 = get_text(res5_obj)
        print(f"Result: {res5[:120]}")
        if "Access denied" not in res5 and "is not in the allowed command whitelist" not in res5:
            print("PASSED: Whitelisted command executed.")
        else:
            print(f"FAILED: Whitelisted command blocked: {res5[:120]}")
    except Exception as e:
        print(f"FAILED: Whitelisted command failed with exception: {e}")

    # Cleanup probe file if it somehow got written (grant pre-existed).
    probe_path = Path(write_target)
    if probe_path.exists():
        probe_path.unlink(missing_ok=True)

    print("\n--- Validation Complete ---")

if __name__ == "__main__":
    asyncio.run(run_tests())