<#
.SYNOPSIS
    Sincroniza (unidireccional) el config.json oficial hacia la copia-espejo dentro del repo.

.DESCRIPTION
    La configuracion real que carga el servidor vive en ~/.personal-mcp/config.json
    (ver AppConfig.default_path() en src/config.py). Esa es la UNICA fuente de verdad.

    La copia dentro de este repo (config.json, junto a este script) es solo un ESPEJO
    de solo lectura, pensado para poder verla junto al codigo versionado sin tener que
    navegar a la carpeta de usuario. Editar la copia del repo NO tiene ningun efecto
    sobre el servidor en ejecucion.

    Este script siempre copia oficial -> repo. Nunca al reves. Si el config oficial
    tiene JSON invalido, el script se detiene sin tocar el espejo, para no propagar
    un archivo roto.

.EXAMPLE
    .\sync-config.ps1
#>

$ErrorActionPreference = "Stop"
$OfficialConfig = "$env:USERPROFILE\.personal-mcp\config.json"
$RepoConfigMirror = "$PSScriptRoot\config.json"

Write-Host "=== Sincronizando config.json (oficial -> espejo del repo) ===" -ForegroundColor Cyan

if (-not (Test-Path $OfficialConfig)) {
    Write-Host "ERROR: no se encontro el config oficial en $OfficialConfig" -ForegroundColor Red
    Write-Host "Nada que sincronizar. Verifica que personal-mcp este instalado (install.ps1)." -ForegroundColor Red
    exit 1
}

try {
    $null = Get-Content $OfficialConfig -Raw -Encoding UTF8 | ConvertFrom-Json
} catch {
    Write-Host "ERROR: el config oficial tiene JSON invalido. No se toca el espejo." -ForegroundColor Red
    Write-Host "Detalle: $_" -ForegroundColor Red
    exit 1
}

Copy-Item -Path $OfficialConfig -Destination $RepoConfigMirror -Force

Write-Host "OK: espejo actualizado en $RepoConfigMirror" -ForegroundColor Green
Write-Host ""
Write-Host "Recordatorio importante:" -ForegroundColor Yellow
Write-Host "  Este archivo (config.json en el repo) es SOLO de lectura/consulta." -ForegroundColor Yellow
Write-Host "  El unico archivo que el servidor realmente usa es:" -ForegroundColor Yellow
Write-Host "  $OfficialConfig" -ForegroundColor Yellow
Write-Host ""
Write-Host "Para entender que significa cada campo, ver CONFIG-GUIA.md en esta misma carpeta." -ForegroundColor Cyan
