#!/usr/bin/env bash
# ============================================================
# personal-mcp Linux/macOS Installer
# ============================================================
# Installs personal-mcp MCP server for Claude Desktop.
# Supports: Ubuntu 22.04+, Fedora 38+, macOS 13+
# ============================================================

set -euo pipefail

# Colors
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Paths
MCP_DIR="$HOME/.personal-mcp"
CONFIG_PATH="$MCP_DIR/config.json"
CLAUDE_CONFIG_LINUX="$HOME/.config/Claude/claude_desktop_config.json"
CLAUDE_CONFIG_MACOS="$HOME/Library/Application Support/Claude/claude_desktop_config.json"
VENV_DIR="$(dirname "$(readlink -f "$0")")/.venv"
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"

echo -e "${CYAN}=== personal-mcp Installer (Linux/macOS) ===${NC}"
echo ""

# Step 1: Check Python
echo -e "${YELLOW}[1/6] Checking Python...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}  ERROR: python3 not found. Install Python 3.10+${NC}"
    exit 1
fi
PY_VERSION=$(python3 --version)
echo -e "${GREEN}  OK: $PY_VERSION${NC}"

# Check Python version >= 3.10
PY_MAJOR=$(python3 -c "import sys; print(sys.version_info.major)")
PY_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")
if [ "$PY_MAJOR" -lt 3 ] || [ "$PY_MAJOR" -eq 3 -a "$PY_MINOR" -lt 10 ]; then
    echo -e "${RED}  ERROR: Python 3.10+ required, found $PY_MAJOR.$PY_MINOR${NC}"
    exit 1
fi

# Step 2: Create venv
echo -e "${YELLOW}[2/6] Creating virtual environment...${NC}"
if [ ! -f "$VENV_DIR/bin/python" ]; then
    python3 -m venv "$VENV_DIR"
    echo -e "${GREEN}  OK: Created $VENV_DIR${NC}"
else
    echo -e "${GREEN}  OK: Using existing venv: $VENV_DIR${NC}"
fi
PYTHON="$VENV_DIR/bin/python"

# Step 3: Create directory structure
echo -e "${YELLOW}[3/6] Creating directory structure...${NC}"
mkdir -p "$MCP_DIR/data/journal"
mkdir -p "$MCP_DIR/src/layers"
echo -e "${GREEN}  OK: $MCP_DIR${NC}"

# Step 4: Install dependencies
echo -e "${YELLOW}[4/6] Installing Python dependencies...${NC}"
"$PYTHON" -m pip install -r "$SCRIPT_DIR/requirements.txt" --quiet 2>&1 || {
    echo -e "${YELLOW}  WARN: pip install had issues, continuing...${NC}"
}
echo -e "${GREEN}  OK: Dependencies installed${NC}"

# Step 5: Create default config
echo -e "${YELLOW}[5/6] Configuring...${NC}"
if [ ! -f "$CONFIG_PATH" ]; then
    # Auto-detect common workspace directories
    ALLOWED_PATHS=("$HOME" "$HOME/Repos" "$HOME/Projects" "$HOME/code" "$HOME/src")
    EXISTING_PATHS=()
    for p in "${ALLOWED_PATHS[@]}"; do
        if [ -d "$p" ]; then
            EXISTING_PATHS+=("$p")
        fi
    done
    # Always include ~/.personal-mcp
    EXISTING_PATHS+=("$MCP_DIR")

    # Build JSON config
    cat > "$CONFIG_PATH" <<EOF
{
  "security": {
    "paths_allow": $(printf '%s\n' "${EXISTING_PATHS[@]}" | jq -R . | jq -s .),
    "paths_deny": [
      "**/node_modules/**",
      "**/.git/**",
      "**/.ssh/**",
      "**/.aws/**",
      "**/.env*",
      "**/*.pem",
      "**/id_rsa*",
      "**/id_ed25519*"
    ],
    "commands": {
      "allow_prefix": [
        "git", "npm", "python3", "python", "ls", "pytest", "echo",
        "uv", "make", "docker", "cat", "dotnet", "node", "pnpm",
        "flutter", "cargo", "go", "pip", "pip3"
      ],
      "readonly_prefix": [
        "git status", "git log", "git diff", "git show", "git branch", "git remote -v",
        "ls", "cat", "echo", "docker ps", "docker images", "docker version",
        "npm list", "npm --version", "npm ls",
        "dotnet --version", "dotnet --info",
        "node --version", "pnpm --version", "pnpm list",
        "flutter --version", "flutter doctor",
        "python --version", "python3 --version",
        "cargo --version", "go version"
      ],
      "deny": [
        "shutdown", "reboot", "poweroff", "halt",
        "mkfs", "fdisk", "parted",
        "userdel", "groupdel", "passwd",
        "rm -rf", "rm -r -f",
        "shred", "wipefs"
      ],
      "require_flag_approval": ["-force", "-f", "/f", "/q", "-recurse -force"]
    },
    "rate_limit_commands_per_minute": 60,
    "rate_limit_files_per_operation": 100,
    "secret_scanning_enabled": true
  },
  "shell": {
    "enabled": true,
    "default_shell": "bash",
    "shell_map": {},
    "session_timeout_seconds": 600,
    "command_timeout_seconds": 120
  },
  "ssh": {
    "enabled": false
  },
  "journal": {
    "enabled": true,
    "path": "$MCP_DIR/data/journal"
  },
  "audit_max_entries": 10000,
  "data_dir": "$MCP_DIR/data"
}
EOF
    echo -e "${GREEN}  OK: Default config created at $CONFIG_PATH${NC}"
else
    echo -e "${GREEN}  OK: Config already exists at $CONFIG_PATH${NC}"
fi

# Step 6: Register with Claude Desktop
echo -e "${YELLOW}[6/6] Registering with Claude Desktop...${NC}"

# Determine Claude config path
if [[ "$OSTYPE" == "darwin"* ]]; then
    CLAUDE_CONFIG="$CLAUDE_CONFIG_MACOS"
else
    CLAUDE_CONFIG="$CLAUDE_CONFIG_LINUX"
fi

mkdir -p "$(dirname "$CLAUDE_CONFIG")"

# Read existing config or create new
if [ -f "$CLAUDE_CONFIG" ]; then
    # Use python to merge JSON (more reliable than jq)
    "$PYTHON" -c "
import json, os, sys
config_path = '$CLAUDE_CONFIG'
server_entry = {
    'command': '$PYTHON',
    'args': ['$SCRIPT_DIR/run_server.py']
}
try:
    with open(config_path, 'r') as f:
        config = json.load(f)
except:
    config = {}
if 'mcpServers' not in config:
    config['mcpServers'] = {}
config['mcpServers']['personal-mcp'] = server_entry
with open(config_path, 'w') as f:
    json.dump(config, f, indent=2)
print('OK: Updated', config_path)
"
else
    "$PYTHON" -c "
import json, os
config_path = '$CLAUDE_CONFIG'
server_entry = {
    'command': '$PYTHON',
    'args': ['$SCRIPT_DIR/run_server.py']
}
config = {'mcpServers': {'personal-mcp': server_entry}}
with open(config_path, 'w') as f:
    json.dump(config, f, indent=2)
print('OK: Created', config_path)
"
fi

echo -e "${GREEN}  OK: Claude Desktop configured${NC}"

# Summary
echo ""
echo -e "${CYAN}=== Installation Complete ===${NC}"
echo -e "Python:       $PYTHON"
echo -e "Config:       $CONFIG_PATH"
echo -e "Data:         $MCP_DIR/data"
echo -e "Claude Config: $CLAUDE_CONFIG"
echo ""
echo -e "${CYAN}Available tools:${NC}"
echo -e "  Layer 1 - Filesystem:  fs_read, fs_write, fs_edit, fs_delete, fs_list, fs_tree, fs_search, fs_find, fs_info, fs_diff, fs_batch, fs_snapshot"
echo -e "  Layer 2 - Shell:       sh_exec, sh_session_start, sh_session_list, sh_session_send, sh_session_read, sh_session_interrupt, sh_session_close, sh_script, sh_history"
echo -e "  Layer 3 - SSH:         ssh_list_hosts, ssh_connect, ssh_exec, ssh_disconnect (if enabled)"
echo -e "  Layer 4 - Personal:    journal_add, journal_list, journal_search, journal_stats, journal_export, note_quick, project_scan, project_find"
echo -e "  Layer 5 - Health:      health_check, health_disk, health_processes, health_config, mcp_diag, mcp_audit_log, mcp_list_tools, mcp_benchmark"
echo -e "  Layer 6 - Permissions: fs_approve, fs_deny, fs_request_allow, security_pending, security_revoke, security_stats"
echo ""
echo -e "${YELLOW}Restart Claude Desktop to activate personal-mcp.${NC}"