<#
.SYNOPSIS
    Runs the backend test suite inside the backend container.

.DESCRIPTION
    Tests run against SQLite, so they need no database container and leave the
    development data untouched.

.EXAMPLE
    .\scripts\run-tests.ps1
    .\scripts\run-tests.ps1 -Coverage
#>
[CmdletBinding()]
param([switch]$Coverage)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    if ($Coverage) {
        docker compose exec backend python -m pytest tests --cov=app --cov-report=term-missing
    } else {
        docker compose exec backend python -m pytest tests -v
    }
}
finally { Pop-Location }
