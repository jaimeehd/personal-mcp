<#
.SYNOPSIS
    Installs personal-mcp MCP server for Claude Desktop on this machine.
.DESCRIPTION
    Creates config, installs dependencies, and registers with Claude Desktop.
    Supports multiple Claude instances via -UserDataDirs parameter.
.PARAMETER UserDataDirs
    Extra Claude user-data-dir paths to install into (e.g. 
    "C:\Users\user\Claude-Cuenta2", "C:\Users\user\Claude-Cuenta3", "C:\Users\user\Claude-Cuenta4").
#>
param(
    [string[]]$UserDataDirs = @()
)

$ErrorActionPreference = "Stop"
$McpDir = "$env:USERPROFILE\.personal-mcp"
$ConfigPath = "$McpDir\config.json"
$ClaudeConfigPath = "$env:APPDATA\Claude\claude_desktop_config.json"
$VenvDir = "$PSScriptRoot\.venv"
if (Test-Path "$VenvDir\Scripts\python.exe") {
    $Python = "$VenvDir\Scripts\python.exe"
} else {
    $Python = "python"
}

Write-Host "=== personal-mcp Installer ===" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check Python and create venv
Write-Host "[1/6] Checking Python..." -ForegroundColor Yellow
try {
    $pyVersion = & $Python --version
    Write-Host "  OK: $pyVersion" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: Python not found. Please install Python 3.10+" -ForegroundColor Red
    exit 1
}

# Create venv if missing
if (-not (Test-Path "$VenvDir\Scripts\python.exe")) {
    Write-Host "  Creating virtual environment..." -ForegroundColor Yellow
    & $Python -m venv "$VenvDir"
    $Python = "$VenvDir\Scripts\python.exe"
    Write-Host "  OK: Created $VenvDir" -ForegroundColor Green
} else {
    Write-Host "  OK: Using venv: $VenvDir" -ForegroundColor Green
}

# Step 2: Create directory structure
Write-Host "[2/6] Creating directory structure..." -ForegroundColor Yellow
$null = New-Item -ItemType Directory -Path "$McpDir\data\journal" -Force
$null = New-Item -ItemType Directory -Path "$McpDir\src\layers" -Force
Write-Host "  OK: $McpDir" -ForegroundColor Green

# Step 3: Install Python dependencies (in venv)
Write-Host "[3/6] Installing Python dependencies..." -ForegroundColor Yellow
try {
    & $Python -m pip install -r "$PSScriptRoot\requirements.txt" --quiet 2>&1 | Out-Null
    Write-Host "  OK: Dependencies installed" -ForegroundColor Green
} catch {
    Write-Host "  WARN: pip install had issues, continuing..." -ForegroundColor Yellow
}

# Step 4: Create default config if not exists
Write-Host "[4/6] Configuring..." -ForegroundColor Yellow
if (-not (Test-Path $ConfigPath)) {
    # Auto-detect common workspace directories (VS, GitHub Desktop defaults)
    $defaultPaths = @(
        "$env:USERPROFILE\source\repos",
        "$env:USERPROFILE\Documents\GitHub",
        "$env:USERPROFILE\repos"
    )
    $allowedPaths = @()
    foreach ($p in $defaultPaths) {
        if (Test-Path $p) {
            $allowedPaths += $p
        }
    }
    # Fallback: create the first one if none exist
    if ($allowedPaths.Count -eq 0) {
        $first = $defaultPaths[0]
        $null = New-Item -ItemType Directory -Force -Path $first
        $allowedPaths += $first
        Write-Host "  Created default workspace: $first" -ForegroundColor Cyan
    }
    # Also add Desktop and personal-mcp for convenience
    $allowedPaths += "$env:USERPROFILE\Desktop"
    $allowedPaths += "$McpDir"
    if (Test-Path "$env:USERPROFILE\OneDrive") {
        $allowedPaths += "$env:USERPROFILE\OneDrive"
    }

    $config = @{
        security = @{
            paths_allow = $allowedPaths
            paths_deny = @(
                "**\node_modules\**",
                "**\.git\**",
                "**\bin\**",
                "**\obj\**",
                "**\AppData\**",
                "**\.ssh\**",
                "**\.aws\**",
                "**\.azure\**",
                "**\.kube\**",
                "**\.gnupg\**",
                "**\.env*",
                "**\*.pem",
                "**\id_rsa*",
                "**\id_ed25519*",
                "**\.git-credentials",
                "**\.npmrc",
                "**\.pypirc",
                "**\.docker\config.json"
            )
            commands = @{
                allow_prefix = @(
                    "git", "npm", "python", "ls", "pytest", "echo", "uv",
                    "make", "docker", "cat", "type", "dotnet", "node",
                    "pnpm", "flutter", "gh"
                )
                deny = @(
                    "shutdown", "reboot", "restart-computer", "stop-computer",
                    "format", "format-volume", "reg delete", "net user",
                    "net localgroup administrators", "clear-eventlog",
                    "remove-item -recurse -force", "rm -rf"
                )
                require_flag_approval = @("-force", "-f", "/f", "/q", "-recurse -force")
            }
            rate_limit_commands_per_minute = 60
            rate_limit_files_per_operation = 100
        }
        shell = @{
            enabled = $true
            default_shell = "powershell"
            session_timeout_seconds = 600
            command_timeout_seconds = 120
        }
        ssh = @{
            enabled = $false
        }
        journal = @{
            enabled = $true
            path = "$McpDir\data\journal"
        }
        audit_max_entries = 10000
        data_dir = "$McpDir\data"
    }

    $config | ConvertTo-Json -Depth 10 | Set-Content -Path $ConfigPath -Encoding UTF8
    Write-Host "  OK: Default config created at $ConfigPath" -ForegroundColor Green
} else {
    Write-Host "  OK: Config already exists at $ConfigPath" -ForegroundColor Green
}

# Step 5: Register with Claude Desktop
function Register-ClaudeInstance {
    param([string]$ConfigPath)
    Write-Host "  Registering in: $ConfigPath" -ForegroundColor Yellow
    $serverEntry = @{
        command = "$Python"
        args = @("$PSScriptRoot\run_server.py")
    }
    if (Test-Path $ConfigPath) {
        try {
            $claudeConfig = Get-Content $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
        } catch {
            Write-Host "    WARN: Could not parse, creating new one..." -ForegroundColor Yellow
            $claudeConfig = [PSCustomObject]@{}
        }
    } else {
        $claudeConfig = [PSCustomObject]@{}
    }
    # Ensure mcpServers exists at top level (new Claude Desktop format)
    if (-not $claudeConfig.mcpServers) {
        $claudeConfig | Add-Member -NotePropertyName "mcpServers" -NotePropertyValue ([PSCustomObject]@{}) -Force
    }
    $claudeConfig.mcpServers | Add-Member -NotePropertyName "personal-mcp" -NotePropertyValue $serverEntry -Force
    [System.IO.File]::WriteAllText($ConfigPath, ($claudeConfig | ConvertTo-Json -Depth 10), [System.Text.UTF8Encoding]::new($false))
}

Write-Host "[5/6] Registering with Claude Desktop..." -ForegroundColor Yellow
Register-ClaudeInstance -ConfigPath $ClaudeConfigPath
foreach ($dir in $UserDataDirs) {
    $extraPath = "$dir\claude_desktop_config.json"
    if (Test-Path $dir) {
        Register-ClaudeInstance -ConfigPath $extraPath
    } else {
        Write-Host "  SKIP: Directory not found: $dir" -ForegroundColor Yellow
    }
}
Write-Host "  OK: Claude Desktop configured" -ForegroundColor Green

# Step 6: Summary
Write-Host ""
Write-Host "[6/6] Verifying installation..." -ForegroundColor Yellow
try {
    & $Python -c "import src.server; print('  OK: Server module loads successfully')" -ForegroundColor Green
} catch {
    Write-Host "  WARN: Server import failed: $_" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Installation Complete ===" -ForegroundColor Cyan
Write-Host "Python:       $Python"
Write-Host "Config:       $ConfigPath"
Write-Host "Data:         $McpDir\data"
Write-Host "Claude Config: $ClaudeConfigPath"
Write-Host ""
Write-Host "Available tools:" -ForegroundColor White
Write-Host "  Layer 1 - Filesystem:  fs_read, fs_write, fs_edit, fs_edit_advanced, fs_delete, fs_delete_batch, fs_list, fs_list_with_sizes, fs_list_allowed, fs_tree, fs_search, fs_find, fs_find_duplicates, fs_info, fs_diff, fs_batch, fs_snapshot, fs_create_directory, fs_move, fs_read_multi, fs_read_media"
Write-Host "  Layer 2 - Shell:       sh_exec, sh_session_start, sh_session_list, sh_session_send, sh_session_read, sh_session_interrupt, sh_session_close, sh_script, sh_history"
Write-Host "  Layer 3 - SSH:         ssh_list_hosts, ssh_connect, ssh_exec, ssh_disconnect (if enabled)"
Write-Host "  Layer 4 - Personal:    journal_add, journal_list, journal_search, journal_stats, journal_export, note_quick, project_scan, project_find"
Write-Host "  Layer 5 - Health:      health_check, health_disk, health_processes, health_config, mcp_diag, mcp_audit_log, mcp_list_tools, mcp_benchmark, mcp_log"
Write-Host "  Layer 6 - Permissions: fs_approve, fs_deny, fs_request_allow, security_pending, security_revoke, security_stats"
Write-Host ""
Write-Host "Restart Claude Desktop to activate personal-mcp." -ForegroundColor Yellow
