# scripts/

PowerShell helpers for Windows. Every one of them is a thin wrapper around a
`docker compose` command — nothing here is required, and the equivalent raw
command is shown in `docs/development.md` if you would rather type it.

| Script | Purpose |
|--------|---------|
| `init-env.ps1` | Create `.env` with cryptographically generated secrets, then verify it. Run this first. |
| `check-env.ps1` | Read-only diagnosis: PowerShell edition, Docker, `.env` completeness, database volume state. |
| `start.ps1` | Validate `.env`, then build and start the stack. |
| `trigger-scenario.ps1` | Fire one attack scenario on demand, for a demo. |
| `run-tests.ps1` | Run the backend test suite inside the container. |
| `reset-database.ps1` | **Destructive.** Delete the database volume. Requires typing a confirmation phrase. |

If PowerShell refuses to run a script, it is the execution policy, not the
script. Either run it for one session:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start.ps1
```

or allow local scripts for your user once:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```


## PowerShell compatibility

These scripts run on **both** Windows PowerShell 5.1 and PowerShell 7+. That is
not automatic: 5.1 runs on .NET Framework 4.8 and does not have `??`, `?.`,
ternary `? :`, `ForEach-Object -Parallel`, `$PSStyle`, or
`RandomNumberGenerator::Fill`. Some of those are parse errors rather than
runtime errors, so a script using them fails before executing anything —
which is how an earlier version of `init-env.ps1` silently produced no `.env`
and left PostgreSQL unable to initialise.

`check-env.ps1` prints your edition if you need to confirm which you are on.
