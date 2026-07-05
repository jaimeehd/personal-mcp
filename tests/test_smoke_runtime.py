"""Smoke tests against a live personal-mcp MCP server over stdio JSON-RPC.

Spawns the server as a subprocess, drives it via MCP protocol,
and detects three known runtime bugs:

  Bug #1: mcp_diag / mcp_audit_log timeout (>4 min hang)
  Bug #2: health_processes PowerShell expression not evaluated
  Bug #3: sh_exec hangs/crashes the server

No tool source code is modified.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

REPO_ROOT = Path(__file__).parent.parent
DATA_DIR = Path.home() / ".personal-mcp" / "data"

# How long to wait for a line on stdout before declaring the server dead
_STARTUP_TIMEOUT = 15


# ===================================================================
# Synchronous MCP JSON-RPC client (stdio transport)
# ===================================================================

class MCPError(Exception):
    def __init__(self, code: int, message: str, data=None):
        self.code = code
        super().__init__(f"[{code}] {message}")


class MCPClient:
    """Sync MCP client speaking JSON-RPC 2.0 over stdio.

    Wraps a subprocess.Popen with stdin/stdout pipes.  Thread-safe for
    sequential use only (one request at a time).
    """

    def __init__(self, proc: subprocess.Popen,
                 server_info: dict, protocol_version: str):
        self._proc = proc
        self._id = 0
        self._lock = threading.Lock()
        self.server_info = server_info
        self.protocol_version = protocol_version

    # ------------------------------------------------------------------
    # Low-level I/O helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _recv_line(pipe, timeout: float) -> bytes:
        """Read one line from *pipe* with a timeout via daemon thread.

        Uses a thread because pipe reads on Windows block forever and cannot
        be interrupted by signals or async cancellation.
        """
        buf = []
        done = threading.Event()

        def reader():
            buf.append(pipe.readline())
            done.set()

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        if not done.wait(timeout=timeout):
            raise TimeoutError(f"timed out after {timeout}s")
        line = buf[0]
        if not line:
            raise ConnectionError("Server closed stdout")
        return line.rstrip(b"\r\n")

    @staticmethod
    def _send_line(pipe, data: bytes):
        pipe.write(data)
        pipe.flush()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def request(self, method: str, params: dict = None,
                timeout: float = 30) -> dict:
        with self._lock:
            self._id += 1
            msg = {"jsonrpc": "2.0", "id": self._id, "method": method}
            if params:
                msg["params"] = params
            line = json.dumps(msg, ensure_ascii=False) + "\n"
            self._send_line(self._proc.stdin, line.encode("utf-8"))
            raw = self._recv_line(self._proc.stdout, timeout=timeout)
            resp = json.loads(raw.decode("utf-8").strip())
            if "error" in resp:
                e = resp["error"]
                raise MCPError(e.get("code", -1), e.get("message", "unknown"),
                               e.get("data"))
            return resp.get("result", {})

    def call_tool(self, name: str, arguments: dict,
                  timeout: float = 30) -> dict:
        return self.request(
            "tools/call",
            {"name": name, "arguments": arguments},
            timeout=timeout,
        )


# ===================================================================
# Fixtures
# ===================================================================

def _start_server():
    """Start the server subprocess, handshake, return (MCPClient, Popen)."""
    env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    proc = subprocess.Popen(
        [sys.executable, "-m", "src.server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(REPO_ROOT),
        env=env,
    )
    try:
        # The server prints "personal-mcp starting (stdio mode)\n" first
        _ = MCPClient._recv_line(proc.stdout, timeout=_STARTUP_TIMEOUT)

        # Initialize handshake
        init_req = {
            "jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "smoke-test", "version": "1.0"},
            },
        }
        MCPClient._send_line(
            proc.stdin, (json.dumps(init_req) + "\n").encode("utf-8")
        )
        raw = MCPClient._recv_line(proc.stdout, timeout=_STARTUP_TIMEOUT)
        init_resp = json.loads(raw.decode("utf-8").strip())
        init_result = init_resp.get("result", {})

        # Send initialized notification
        notif = '{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
        MCPClient._send_line(proc.stdin, notif.encode("utf-8"))

        client = MCPClient(
            proc,
            server_info=init_result.get("serverInfo", {}),
            protocol_version=init_result.get("protocolVersion", "unknown"),
        )
        return client, proc
    except Exception:
        proc.kill()
        proc.wait()
        raise


@pytest.fixture(scope="function")
def mcp_server():
    """Spawn a fresh MCP server per test function.

    Function-scoped so a hanging tool (Bug #1 / Bug #3) only kills its own
    test and a fresh server starts for the next one.  ~2 s overhead per test.
    """
    client, proc = _start_server()
    try:
        yield client
    finally:
        if proc.returncode is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


@pytest.fixture(scope="function")
def smoke_dir():
    """Create a temporary directory under data_dir for read-only file tests.

    data_dir is auto-allowed by the server, so no permission grants needed.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(dir=str(DATA_DIR), prefix=".smoke_"))
    (tmp / "hello.txt").write_text("Hello, smoke test!")
    (tmp / "sub").mkdir()
    (tmp / "sub" / "nested.txt").write_text("nested content")
    yield tmp
    shutil.rmtree(tmp, ignore_errors=True)


# ===================================================================
# Helpers
# ===================================================================

def _extract_text(result: dict) -> str:
    blocks = result.get("content", [])
    texts = [b["text"] for b in blocks if b.get("type") == "text"]
    return "\n".join(texts)


def _ensure_tool_list(client: MCPClient):
    result = client.request("tools/list", timeout=10)
    tools = result.get("tools", [])
    names = [t["name"] for t in tools]
    assert "fs_read" in names, "tools/list did not return expected tools"
    return names


# ===================================================================
# 0 — Handshake and connectivity
# ===================================================================

class TestServerHandshake:

    def test_initialize_returns_server_info(self, mcp_server):
        assert mcp_server.server_info.get("name") == "personal-mcp"
        assert mcp_server.protocol_version is not None

    def test_list_tools_returns_all_tools(self, mcp_server):
        names = _ensure_tool_list(mcp_server)
        assert len(names) >= 40, f"Expected 40+, got {len(names)}"
        for required in ("fs_read", "sh_exec", "health_check",
                          "mcp_diag", "mcp_audit_log"):
            assert required in names, f"Missing tool: {required}"


# ===================================================================
# 1 — Bug #1: mcp_diag / mcp_audit_log timeout
# ===================================================================

class TestBug1Timeout:

    def test_mcp_diag_responds_within_timeout(self, mcp_server):
        """Bug #1 detection: mcp_diag should respond within 15s."""
        try:
            result = mcp_server.call_tool("mcp_diag", {}, timeout=15)
            text = _extract_text(result)
            data = json.loads(text)
            assert "python" in data
            assert "git" in data
        except TimeoutError:
            pytest.fail("Bug #1 DETECTED: mcp_diag timed out (>15s)")

    def test_mcp_audit_log_responds_within_timeout(self, mcp_server):
        """Bug #1 detection: mcp_audit_log should respond within 10s."""
        try:
            result = mcp_server.call_tool("mcp_audit_log",
                                           {"n": 5}, timeout=10)
            text = _extract_text(result)
            entries = json.loads(text)
            assert isinstance(entries, list)
        except TimeoutError:
            pytest.fail("Bug #1 DETECTED: mcp_audit_log timed out (>10s)")


# ===================================================================
# 2 — Bug #2: health_processes PowerShell expression
# ===================================================================

class TestBug2HealthProcesses:

    def test_health_processes_evaluates_expression(self, mcp_server):
        """Bug #2 detection: CPU expression should be evaluated, not literal."""
        try:
            result = mcp_server.call_tool("health_processes",
                                           {"top": 3}, timeout=10)
            text = _extract_text(result)
        except TimeoutError:
            pytest.fail("Bug #2 DETECTED: health_processes timed out (>10s)")

        # Bug #2: if the output contains literal "$_.CPU" or "ToString",
        # the PowerShell expression was NOT evaluated.
        if "$_.CPU" in text or "ToString" in text:
            pytest.fail(
                "Bug #2 DETECTED: health_processes shows literal "
                "PowerShell expression instead of evaluated values. "
                "Got:\n" + text[:500]
            )

        assert len(text) > 0, "health_processes returned empty output"
        has_process = any(
            line.strip() and not line.startswith("--")
            for line in text.splitlines()
        )
        assert has_process, (
            "health_processes: no process data in output.\n"
            f"Got:\n{text[:500]}"
        )


# ===================================================================
# 3 — Bug #3: sh_exec hang
# ===================================================================

class TestBug3ShellExec:

    def test_sh_exec_echo_responds(self, mcp_server):
        """Bug #3 detection: sh_exec with trivial command should respond."""
        try:
            result = mcp_server.call_tool(
                "sh_exec",
                {"command": "echo smoke-test-ok", "timeout": 10},
                timeout=15,
            )
            text = _extract_text(result)
            assert "smoke-test-ok" in text, (
                f"sh_exec echo did not return expected text. Got:\n{text[:300]}"
            )
        except TimeoutError:
            pytest.fail(
                "Bug #3 DETECTED: sh_exec timed out (>15s) "
                "on trivial 'echo' command"
            )


# ===================================================================
# 4 — General health smoke tests
# ===================================================================

class TestHealthSmoke:

    def test_health_check_returns_json(self, mcp_server):
        result = mcp_server.call_tool("health_check", {}, timeout=30)
        text = _extract_text(result)
        data = json.loads(text)
        assert "timestamp" in data
        assert "platform" in data
        assert "disk" in data
        assert "memory" in data
        assert "audit" in data

    def test_health_config_returns_json(self, mcp_server):
        result = mcp_server.call_tool("health_config", {}, timeout=10)
        text = _extract_text(result)
        data = json.loads(text)
        assert "security" in data
        assert "paths_allow" in data["security"]

    def test_health_disk_returns_usage(self, mcp_server):
        result = mcp_server.call_tool(
            "health_disk", {"paths": str(Path.home())}, timeout=10
        )
        text = _extract_text(result)
        data = json.loads(text)
        key = str(Path.home())
        assert key in data, f"Expected {key} in disk results"
        assert "total_gb" in data[key]

    def test_mcp_list_tools_returns_names(self, mcp_server):
        result = mcp_server.request("tools/list", timeout=10)
        tools = result.get("tools", [])
        names = [t["name"] for t in tools]
        assert len(names) >= 40
        assert "health_check" in names

    def test_mcp_log_returns_string(self, mcp_server):
        result = mcp_server.call_tool(
            "mcp_log", {"lines": 5, "level": "INFO"}, timeout=10
        )
        text = _extract_text(result)
        assert isinstance(text, str)


# ===================================================================
# 5 — Security / state smoke tests
# ===================================================================

class TestSecuritySmoke:

    def test_security_stats_returns_json(self, mcp_server):
        result = mcp_server.call_tool("security_stats", {}, timeout=10)
        text = _extract_text(result)
        data = json.loads(text)
        assert "total_tickets" in data
        assert "session_grants" in data

    def test_security_pending_returns_list(self, mcp_server):
        result = mcp_server.call_tool("security_pending", {},
                                       timeout=10)
        text = _extract_text(result)
        if text.startswith("["):
            data = json.loads(text)
            assert isinstance(data, list)

    def test_sh_history_returns_string(self, mcp_server):
        result = mcp_server.call_tool("sh_history", {}, timeout=10)
        text = _extract_text(result)
        assert isinstance(text, str)

    def test_sh_session_list_returns_string(self, mcp_server):
        result = mcp_server.call_tool("sh_session_list", {}, timeout=10)
        text = _extract_text(result)
        assert isinstance(text, str)


# ===================================================================
# 6 — Filesystem read-only smoke tests (via data_dir, auto-allowed)
# ===================================================================

class TestFilesystemReadSmoke:

    def test_fs_info_returns_metadata(self, mcp_server, smoke_dir):
        target = str(smoke_dir / "hello.txt")
        result = mcp_server.call_tool("fs_info", {"path": target},
                                       timeout=10)
        text = _extract_text(result)
        assert "size:" in text
        assert "sha256:" in text
        assert "hello.txt" in text

    def test_fs_read_returns_content(self, mcp_server, smoke_dir):
        target = str(smoke_dir / "hello.txt")
        result = mcp_server.call_tool("fs_read", {"path": target},
                                       timeout=10)
        text = _extract_text(result)
        assert "Hello, smoke test!" in text

    def test_fs_list_returns_entries(self, mcp_server, smoke_dir):
        result = mcp_server.call_tool("fs_list", {"path": str(smoke_dir)},
                                       timeout=10)
        text = _extract_text(result)
        assert "hello.txt" in text
        assert "sub" in text

    def test_fs_tree_returns_structure(self, mcp_server, smoke_dir):
        result = mcp_server.call_tool(
            "fs_tree", {"path": str(smoke_dir), "max_depth": 3}, timeout=10
        )
        text = _extract_text(result)
        assert "hello.txt" in text
        assert "nested.txt" in text

    def test_fs_diff_identical(self, mcp_server, smoke_dir):
        target = str(smoke_dir / "hello.txt")
        result = mcp_server.call_tool(
            "fs_diff", {"path_a": target, "path_b": target}, timeout=10
        )
        text = _extract_text(result)
        assert "(identical)" in text

    def test_fs_diff_different_files(self, mcp_server, smoke_dir):
        a = str(smoke_dir / "hello.txt")
        b = str(smoke_dir / "sub" / "nested.txt")
        result = mcp_server.call_tool(
            "fs_diff", {"path_a": a, "path_b": b}, timeout=10
        )
        text = _extract_text(result)
        assert len(text) > 0
        assert any(c in text for c in ("---", "+++", "@@", "Hello", "nested"))


# ===================================================================
# 7 — Permission required / denied path patterns (regression)
# ===================================================================

class TestPermissionRequired:

    def test_fs_read_outside_allowed_returns_error(self, mcp_server):
        result = mcp_server.call_tool(
            "fs_read", {"path": "C:\\Windows\\system.ini"}, timeout=10
        )
        text = _extract_text(result)
        assert "Access denied" in text

    def test_fs_read_inside_allowed_no_grant_succeeds(self, mcp_server):
        """Read inside paths_allow works without grant (Option C)."""
        target = str(Path.home() / "Repos" / ".smoke_no_access.txt")
        Path(target).parent.mkdir(parents=True, exist_ok=True)
        Path(target).write_text("no grant test")
        try:
            result = mcp_server.call_tool(
                "fs_read", {"path": target}, timeout=10
            )
            text = _extract_text(result)
            assert "no grant test" in text
        finally:
            Path(target).unlink(missing_ok=True)

    def test_health_processes_utf8_no_mojibake(self, mcp_server):
        """Regression: uptime/date strings should not have mojibake."""
        result = mcp_server.call_tool("health_processes",
                                       {"top": 5}, timeout=10)
        text = _extract_text(result)
        mojibake_signs = ["mi\u201a", "a.\xff", "\ufffd"]
        for sign in mojibake_signs:
            assert sign not in text, (
                f"Mojibake detected in health_processes output: {sign!r}"
            )


# ===================================================================
# 8 — Server cleanup integrity
# ===================================================================

class TestServerCleanup:

    def test_server_stderr_has_no_crashes(self, mcp_server):
        proc = mcp_server._proc
        stderr_text = ""
        if proc.stderr:
            buf = []
            done = threading.Event()

            def reader():
                buf.append(proc.stderr.read())
                done.set()

            t = threading.Thread(target=reader, daemon=True)
            t.start()
            if done.wait(timeout=2):
                data = buf[0]
                if data:
                    stderr_text = data.decode("utf-8", errors="replace")
        if stderr_text:
            traceback_indicators = ["Traceback", "Error:", "Exception:"]
            for indicator in traceback_indicators:
                if indicator in stderr_text:
                    pytest.fail(
                        f"Server stderr contains '{indicator}':\n"
                        f"{stderr_text[:1000]}"
                    )
