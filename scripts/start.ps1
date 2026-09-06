<#
.SYNOPSIS
    Validates the environment, then builds and starts the full stack.

.DESCRIPTION
    Checks that .env exists AND that every required value is present and
    non-blank before invoking docker compose. Merely checking that the file
    exists is not enough: a half-written .env produces a blank
    POSTGRES_PASSWORD and an opaque PostgreSQL initdb failure.

.EXAMPLE
    .\scripts\start.ps1
    .\scripts\start.ps1 -Detached
#>
[CmdletBinding()]
param([switch]$Detached, [switch]$NoBuild)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $envPath = Join-Path $root '.env'

    if (-not (Test-Path $envPath)) {
        Write-Host "No .env found." -ForegroundColor Red
        Write-Host "Run: .\scripts\init-env.ps1" -ForegroundColor Yellow
        exit 1
    }

    # ---- validate the contents, not just the file's existence -------------
    $required = @('POSTGRES_USER', 'POSTGRES_PASSWORD', 'POSTGRES_DB',
                  'SECRET_KEY', 'INGEST_API_KEY', 'CORS_ORIGINS')
    $parsed = @{}
    foreach ($line in (Get-Content $envPath)) {
        if ($line -match '^\s*([A-Z0-9_]+)\s*=\s*(.*)$') { $parsed[$Matches[1]] = $Matches[2].Trim() }
    }

    $problems = @()
    foreach ($key in $required) {
        if (-not $parsed.ContainsKey($key))              { $problems += "$key is missing from .env" }
        elseif ([string]::IsNullOrWhiteSpace($parsed[$key])) { $problems += "$key is empty" }
        elseif ($parsed[$key] -like 'CHANGE_ME*')        { $problems += "$key is still a placeholder" }
        elseif ($parsed[$key] -like 'change_me*')        { $problems += "$key is still a placeholder" }
    }

    if ($problems.Count -gt 0) {
        Write-Host ".env is present but incomplete:" -ForegroundColor Red
        $problems | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
        Write-Host ""
        Write-Host "Regenerate it with: .\scripts\init-env.ps1 -Force" -ForegroundColor Yellow
        exit 1
    }
    Write-Host ".env validated - all required values present." -ForegroundColor Green

    # ---- Docker must actually be running ----------------------------------
    docker info *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Docker is not responding. Start Docker Desktop and try again." -ForegroundColor Red
        exit 1
    }

    # Not named $args: that is an automatic variable in PowerShell.
    $composeArgs = @('compose', 'up')
    if (-not $NoBuild) { $composeArgs += '--build' }
    if ($Detached)     { $composeArgs += '-d' }

    docker @composeArgs

    if ($Detached) {
        Write-Host ""
        Write-Host "Frontend : http://localhost:54173" -ForegroundColor Green
        Write-Host "API docs : http://localhost:58000/docs" -ForegroundColor Green
        Write-Host ""
        Write-Host "Follow logs with: docker compose logs -f"
    }
}
finally { Pop-Location }
