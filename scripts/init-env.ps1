<#
.SYNOPSIS
    Creates .env from .env.example with strong, randomly generated secrets.

.DESCRIPTION
    Generates SECRET_KEY, INGEST_API_KEY and POSTGRES_PASSWORD using the
    platform cryptographic RNG, then verifies the written file before exiting.

    Works on BOTH Windows PowerShell 5.1 (.NET Framework) and PowerShell 7+
    (.NET 5+). These have different cryptography APIs:
      - PowerShell 7+ : RandomNumberGenerator::Fill (static, .NET Core 2.0+)
      - PowerShell 5.1: RNGCryptoServiceProvider::GetBytes (instance)
    Calling Fill() on 5.1 fails with "does not contain a method named 'Fill'",
    which previously left no .env at all — and a blank POSTGRES_PASSWORD makes
    the postgres container refuse to initialise with a confusing error.

.EXAMPLE
    .\scripts\init-env.ps1
    .\scripts\init-env.ps1 -Force
#>
[CmdletBinding()]
param([switch]$Force)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$envPath = Join-Path $root '.env'
$examplePath = Join-Path $root '.env.example'

Write-Host "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))" -ForegroundColor DarkGray

if (-not (Test-Path $examplePath)) {
    Write-Host "Cannot find .env.example at $examplePath" -ForegroundColor Red
    exit 1
}

if ((Test-Path $envPath) -and -not $Force) {
    Write-Host ".env already exists. Re-run with -Force to regenerate it." -ForegroundColor Yellow
    Write-Host "Warning: regenerating SECRET_KEY signs out every active session," -ForegroundColor Yellow
    Write-Host "and changing POSTGRES_PASSWORD after the database is initialised" -ForegroundColor Yellow
    Write-Host "requires removing the volume (.\scripts\reset-database.ps1)." -ForegroundColor Yellow
    exit 1
}

function New-Secret {
    <#
        Cryptographically secure random bytes, rendered URL-safe base64.
        Two code paths because the two PowerShell editions expose different
        APIs; both are the platform CSPRNG, not System.Random.
    #>
    param([int]$Bytes = 48)

    $buffer = New-Object byte[] $Bytes

    if ($PSVersionTable.PSVersion.Major -ge 6) {
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($buffer)
    }
    else {
        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        try   { $rng.GetBytes($buffer) }
        finally { $rng.Dispose() }
    }

    [Convert]::ToBase64String($buffer).Replace('+', '-').Replace('/', '_').TrimEnd('=')
}

# Fail before writing anything if the RNG is not usable on this host.
try {
    $probe = New-Secret 16
    if ([string]::IsNullOrWhiteSpace($probe)) { throw 'empty result' }
}
catch {
    Write-Host "Could not generate secure random values on this PowerShell edition." -ForegroundColor Red
    Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Generate them manually and paste into .env:" -ForegroundColor Yellow
    Write-Host '  python -c "import secrets; print(secrets.token_urlsafe(64))"' -ForegroundColor Yellow
    exit 1
}

$content = Get-Content $examplePath -Raw
$content = $content -replace 'SECRET_KEY=CHANGE_ME[^\r\n]*',      "SECRET_KEY=$(New-Secret 64)"
$content = $content -replace 'INGEST_API_KEY=CHANGE_ME[^\r\n]*',  "INGEST_API_KEY=$(New-Secret 48)"
$content = $content -replace 'POSTGRES_PASSWORD=change_me[^\r\n]*', "POSTGRES_PASSWORD=$(New-Secret 24)"

# No BOM. docker compose does not strip one, and a BOM turns the first variable
# name into a byte-prefixed string that silently never matches.
[System.IO.File]::WriteAllText($envPath, $content, (New-Object System.Text.UTF8Encoding($false)))

# ---------------------------------------------------------------- verification
# Read the file back and prove every required value is present and non-blank.
# Reporting success without checking is how the previous version of this script
# appeared to work while leaving the stack unable to start.
$required = @('POSTGRES_USER', 'POSTGRES_PASSWORD', 'POSTGRES_DB', 'SECRET_KEY', 'INGEST_API_KEY', 'CORS_ORIGINS')
$parsed = @{}
foreach ($line in (Get-Content $envPath)) {
    if ($line -match '^\s*([A-Z0-9_]+)\s*=\s*(.*)$') { $parsed[$Matches[1]] = $Matches[2].Trim() }
}

$problems = @()
foreach ($key in $required) {
    if (-not $parsed.ContainsKey($key))              { $problems += "$key is missing";      continue }
    if ([string]::IsNullOrWhiteSpace($parsed[$key])) { $problems += "$key is empty";        continue }
    if ($parsed[$key] -like 'CHANGE_ME*')            { $problems += "$key is a placeholder" }
    if ($parsed[$key] -like 'change_me*')            { $problems += "$key is a placeholder" }
}
foreach ($key in @('SECRET_KEY', 'INGEST_API_KEY')) {
    if ($parsed.ContainsKey($key) -and $parsed[$key].Length -lt 32) {
        $problems += "$key is shorter than the 32 characters the backend requires"
    }
}

if ($problems.Count -gt 0) {
    Write-Host ""
    Write-Host ".env was written but failed verification:" -ForegroundColor Red
    $problems | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    Write-Host "Do not run docker compose until this is resolved." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Created .env and verified it." -ForegroundColor Green
Write-Host ("  SECRET_KEY        {0} chars" -f $parsed['SECRET_KEY'].Length)
Write-Host ("  INGEST_API_KEY    {0} chars" -f $parsed['INGEST_API_KEY'].Length)
Write-Host ("  POSTGRES_PASSWORD {0} chars" -f $parsed['POSTGRES_PASSWORD'].Length)
Write-Host ("  POSTGRES_USER     {0}" -f $parsed['POSTGRES_USER'])
Write-Host ("  POSTGRES_DB       {0}" -f $parsed['POSTGRES_DB'])
Write-Host ""
Write-Host "Demo account passwords are still the documented defaults." -ForegroundColor Yellow
Write-Host "Change them in .env before showing this to anyone." -ForegroundColor Yellow
Write-Host ""
Write-Host "Next: docker compose up --build"
