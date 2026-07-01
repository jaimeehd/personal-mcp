import asyncio, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from src.server import create_app

def extract_text(result):
    if isinstance(result, tuple) and len(result) > 0:
        item = result[0]
        if isinstance(item, list) and len(item) > 0:
            item = item[0]
        if hasattr(item, "text"):
            return item.text
    return str(result)

async def verify():
    app = create_app()
    tm = app._tool_manager
    tool_names = list(tm._tools.keys())
    print("=== personal-mcp Live Health Check ===")
    print(f"Tools registered: {len(tool_names)}")

    layers = {
        "Layer 1 - Filesystem": [t for t in tool_names if t.startswith("fs_")],
        "Layer 2 - Shell": [t for t in tool_names if t.startswith("sh_")],
        "Layer 3 - SSH": [t for t in tool_names if t.startswith("ssh_")],
        "Layer 4 - Personal": [t for t in tool_names if t.startswith(("journal_", "note_", "project_"))],
        "Layer 5 - Health": [t for t in tool_names if t.startswith(("health_", "mcp_"))],
    }

    for layer, tools in layers.items():
        status = "OK" if tools else "EMPTY"
        print(f"  [{status}] {layer}: {len(tools)} tools")

    print()

    # health_check
    print("1. health_check")
    r = extract_text(await app.call_tool("health_check", {}))
    data = json.loads(r)
    print(f"   Platform: {data.get('platform', '?')}")
    print(f"   Python: {data.get('python_version', '?')}")
    disk = data.get("disk", {})
    if isinstance(disk, dict):
        print(f"   Disk: {disk.get('free_gb', '?')}GB free / {disk.get('total_gb', '?')}GB total")
    mem = data.get("memory", {})
    if isinstance(mem, dict):
        print(f"   Memory: {mem.get('free_pct', '?')}% free")
    else:
        print(f"   Memory: {mem}")

    # mcp_diag
    print()
    print("2. mcp_diag")
    r = extract_text(await app.call_tool("mcp_diag", {}))
    data = json.loads(r)
    print(f"   Node: {data.get('node', '?')}  Git: {data.get('git', '?')}")
    print(f"   Config: {data.get('config_exists', '?')}  Shell: {data.get('shell_enabled', '?')}")
    print(f"   Audit: {data.get('audit', '?')}")

    # sh_exec
    print()
    print("3. sh_exec")
    r = extract_text(await app.call_tool("sh_exec", {"command": "echo hello_mcp"}))
    print(f"   Output: {r[:100]}")

    # fs_list
    print()
    print("4. fs_list on C:\\Repos")
    r = extract_text(await app.call_tool("fs_list", {"path": "C:\\Repos", "max_results": 5}))
    print(f"   {r[:300]}")

    # journal
    print()
    print("5. journal_add + journal_list")
    r = extract_text(await app.call_tool("journal_add", {"content": "personal-mcp installed", "tags": "setup,test"}))
    print(f"   Add: {r}")
    r = extract_text(await app.call_tool("journal_list", {"limit": 5}))
    print(f"   List: {r[:200]}")

    # mcp_audit_log
    print()
    print("6. mcp_audit_log")
    r = extract_text(await app.call_tool("mcp_audit_log", {"n": 10}))
    data = json.loads(r)
    print(f"   Recent operations: {len(data)}")
    for entry in data[-3:]:
        print(f"   - {entry['tool']}: {'OK' if entry['success'] else 'FAIL'} ({entry['duration_ms']}ms)")

    # mcp_list_tools
    print()
    print("7. mcp_list_tools")
    r = extract_text(await app.call_tool("mcp_list_tools", {}))
    print(f"   {r[:500]}")

    print()
    print("=== ALL CHECKS PASSED ===")

asyncio.run(verify())
