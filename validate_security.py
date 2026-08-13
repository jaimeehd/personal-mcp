import asyncio
import json
from pathlib import Path
from src.server import create_app

async def run_tests():
    app = create_app()
    
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

    # Test 1: Path Hard-Lock (Outside paths_allow)
    print("\nTest 1: Path Hard-Lock (Outside paths_allow)...")
    invalid_path = "C:\\Windows\\System32\\notepad.exe"
    result_obj = await app.call_tool("fs_read", {"path": invalid_path})
    res1 = get_text(result_obj)
    print(f"Result: {res1}")
    if "Access denied: Path not in allowed directories" in res1:
        print("PASSED: Path hard-lock is working.")
    else:
        print("FAILED: Path hard-lock failed.")

    # Test 2: HITL Approval (Inside paths_allow, no grant)
    print("\nTest 2: HITL Approval (Inside paths_allow, no grant)...")
    valid_path = str(Path("C:/Repos/.personal-mcp/AGENTS.md").resolve())
    result_obj = await app.call_tool("fs_read", {"path": valid_path})
    res2 = get_text(result_obj)
    print(f"Result: {res2}")
    try:
        data = json.loads(res2)
        if data.get("status") == "permission_required":
            print("PASSED: HITL permission request triggered.")
            ticket_id = data.get("ticket")
        else:
            print("FAILED: Did not receive permission_required JSON.")
            ticket_id = None
    except json.JSONDecodeError:
        print("FAILED: Result was not a JSON payload.")
        ticket_id = None

    # Test 3: Grant Success (Inside paths_allow, with grant)
    if ticket_id:
        print("\nTest 3: Grant Success (Inside paths_allow, with grant)...")
        await app.call_tool("fs_approve", {"ticket_id": ticket_id, "level": "single"})
        result_obj = await app.call_tool("fs_read", {"path": valid_path})
        res3 = get_text(result_obj)
        if "Access denied" not in res3 and "permission_required" not in res3:
            print("PASSED: Operation succeeded after approval.")
        else:
            print(f"FAILED: Operation still blocked: {res3}")
    else:
        print("\nTest 3: SKIPPED (Test 2 failed)")

    # Test 4: Command Whitelist (Outside whitelist)
    print("\nTest 4: Command Whitelist (Outside whitelist)...")
    try:
        res4_obj = await app.call_tool("sh_exec", {"command": "curl http://example.com"})
        res4 = get_text(res4_obj)
        print(f"Result: {res4}")
        if "is not in the allowed command whitelist" in res4:
            print("PASSED: Command whitelist blocked unauthorized command.")
        else:
            print("FAILED: Command whitelist bypassed.")
    except Exception as e:
        print(f"PASSED: Command blocked by exception: {e}")

    # Test 5: Command Whitelist (Inside whitelist)
    print("\nTest 5: Command Whitelist (Inside whitelist)...")
    try:
        res5_obj = await app.call_tool("sh_exec", {"command": "git status"})
        res5 = get_text(res5_obj)
        print(f"Result: {res5}")
        if "Access denied" not in res5 and "is not in the allowed command whitelist" not in res5:
            print("PASSED: Whitelisted command executed.")
        else:
            print(f"FAILED: Whitelisted command blocked: {res5}")
    except Exception as e:
        print(f"FAILED: Whitelisted command failed with exception: {e}")

    print("\n--- Validation Complete ---")

if __name__ == "__main__":
    asyncio.run(run_tests())
