<#
.SYNOPSIS
    Fires one attack scenario on demand, for demonstrations.

.DESCRIPTION
    Runs the generator's trigger command inside the running generator
    container. All activity is synthetic.

.EXAMPLE
    .\scripts\trigger-scenario.ps1 -List
    .\scripts\trigger-scenario.ps1 brute_force
    .\scripts\trigger-scenario.ps1 port_scan -Repeat 2
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Scenario,
    [int]$Repeat = 1,
    [switch]$List
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    if ($List -or -not $Scenario) {
        docker compose exec generator python -m generator.trigger list
        exit 0
    }
    docker compose exec generator python -m generator.trigger $Scenario $Repeat
}
finally { Pop-Location }
