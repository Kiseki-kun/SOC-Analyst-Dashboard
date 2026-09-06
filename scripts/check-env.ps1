<#
.SYNOPSIS
    Diagnoses environment problems without starting anything.

.DESCRIPTION
    Read-only. Reports PowerShell edition, Docker availability, whether .env
    exists and is complete, and whether the database volume already holds an
    initialised PostgreSQL cluster (which matters when changing
    POSTGRES_PASSWORD, since that is only applied on first initialisation).

.EXAMPLE
    .\scripts\check-env.ps1
#>
[CmdletBinding()]
param()

$root = Split-Path -Parent $PSScriptRoot
$envPath = Join-Path $root '.env'

Write-Host ""
Write-Host "=== PowerShell ===" -ForegroundColor Cyan
Write-Host "  Version : $($PSVersionTable.PSVersion)"
Write-Host "  Edition : $($PSVersionTable.PSEdition)"
if ($PSVersionTable.PSVersion.Major -lt 6) {
    Write-Host "  Note    : Windows PowerShell 5.1 runs on .NET Framework." -ForegroundColor DarkGray
    Write-Host "            The scripts here handle that; some .NET Core APIs are unavailable." -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "=== Docker ===" -ForegroundColor Cyan
docker version --format '  Client  : {{.Client.Version}}' 2>$null
docker info --format '  Server  : {{.ServerVersion}} ({{.OperatingSystem}})' 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Docker is not responding - start Docker Desktop." -ForegroundColor Red
}

Write-Host ""
Write-Host "=== .env ===" -ForegroundColor Cyan
if (-not (Test-Path $envPath)) {
    Write-Host "  MISSING - run .\scripts\init-env.ps1" -ForegroundColor Red
} else {
    $parsed = @{}
    foreach ($line in (Get-Content $envPath)) {
        if ($line -match '^\s*([A-Z0-9_]+)\s*=\s*(.*)$') { $parsed[$Matches[1]] = $Matches[2].Trim() }
    }
    $ok = $true
    foreach ($key in @('POSTGRES_USER','POSTGRES_PASSWORD','POSTGRES_DB','SECRET_KEY','INGEST_API_KEY','CORS_ORIGINS')) {
        $value = $parsed[$key]
        if ([string]::IsNullOrWhiteSpace($value)) {
            Write-Host ("  {0,-20} EMPTY" -f $key) -ForegroundColor Red; $ok = $false
        } elseif ($value -like 'CHANGE_ME*' -or $value -like 'change_me*') {
            Write-Host ("  {0,-20} PLACEHOLDER" -f $key) -ForegroundColor Red; $ok = $false
        } elseif ($key -like '*PASSWORD*' -or $key -like '*KEY*') {
            Write-Host ("  {0,-20} set ({1} chars)" -f $key, $value.Length) -ForegroundColor Green
        } else {
            Write-Host ("  {0,-20} {1}" -f $key, $value) -ForegroundColor Green
        }
    }
    if ($ok) { Write-Host "  .env looks complete." -ForegroundColor Green }
}

Write-Host ""
Write-Host "=== Database volume ===" -ForegroundColor Cyan
$volume = docker volume ls --filter name=soc_postgres_data --format '{{.Name}}' 2>$null
if (-not $volume) {
    Write-Host "  Not created yet - PostgreSQL will initialise on first start." -ForegroundColor Green
} else {
    # PG_VERSION exists only after initdb has completed successfully.
    $initialised = docker run --rm -v soc_postgres_data:/d alpine:3 sh -c 'test -f /d/PG_VERSION && echo yes || echo no' 2>$null
    if ($initialised -match 'yes') {
        Write-Host "  soc_postgres_data EXISTS and is INITIALISED." -ForegroundColor Yellow
        Write-Host "  POSTGRES_PASSWORD is only applied at first initialisation." -ForegroundColor Yellow
        Write-Host "  If you have since changed it, remove the volume:" -ForegroundColor Yellow
        Write-Host "    docker compose down -v" -ForegroundColor Yellow
    } else {
        Write-Host "  soc_postgres_data exists but is NOT initialised (empty or partial)." -ForegroundColor Yellow
        Write-Host "  Safe to remove: docker compose down -v" -ForegroundColor Yellow
    }
}
Write-Host ""
