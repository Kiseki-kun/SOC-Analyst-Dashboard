<#
.SYNOPSIS
    DESTRUCTIVE. Deletes the database volume and all stored data.

.DESCRIPTION
    Removes the named Docker volume holding PostgreSQL's data directory. Every
    event, alert, incident, note, response action, audit record and user
    account is destroyed. Migrations and demo seeding re-run on next start.

    Requires typing the confirmation phrase. A reset that could be triggered by
    a stray arrow-key in shell history is a reset that will eventually happen
    by accident.

.EXAMPLE
    .\scripts\reset-database.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    Write-Host ""
    Write-Host "  THIS WILL PERMANENTLY DELETE ALL DATA" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Destroyed: every event, alert, incident, investigation note," -ForegroundColor Yellow
    Write-Host "             simulated response action, audit record and user." -ForegroundColor Yellow
    Write-Host "  Kept:      your .env file and all source code." -ForegroundColor Yellow
    Write-Host ""

    $confirmation = Read-Host "Type exactly 'DELETE ALL DATA' to proceed"
    if ($confirmation -cne 'DELETE ALL DATA') {
        Write-Host "Cancelled. Nothing was changed." -ForegroundColor Green
        exit 0
    }

    docker compose down -v
    Write-Host ""
    Write-Host "Database volume removed." -ForegroundColor Green
    Write-Host "Run .\scripts\start.ps1 to rebuild from a clean state."
}
finally { Pop-Location }
