# Development

## Prerequisites

Docker Desktop with the WSL2 backend, and Git. Nothing else — Python and Node
run inside containers, so their versions on your host do not matter.

## First run

```powershell
git clone <your-repo-url>
cd SOC-Analyst-Dashboard
.\scripts\init-env.ps1          # generates .env with real secrets
docker compose up --build
```

First build takes several minutes. When it settles:

| Service | URL |
|---------|-----|
| Frontend | http://localhost:54173 |
| API docs | http://localhost:58000/docs |
| Database | localhost:55432 |

## Why those ports

Not 3000/5173/8000/5432. During environment setup on the development machine,
outbound connections were observed holding local ports in the 1025–8100 range,
which means Windows was allocating dynamic ports from a low range rather than
the usual 49152–65535. A service bound to 8000 can then intermittently fail to
start because a browser tab grabbed that port a second earlier — a bug that
looks random and unreproducible.

Everything is above 49152. Check your own range with:

```powershell
netsh int ipv4 show dynamicport tcp
```

All three ports are overridable in `.env`.

## Windows and Docker: the four things that bite

These are designed around, not discovered later.

**Line endings.** `.gitattributes` forces LF on shell scripts. A script checked
out with CRLF fails inside a Linux container with a spectacularly unhelpful
`exec /app/entrypoint.sh: no such file or directory` — the file exists, its
interpreter line just ends in `\r`.

**The execute bit.** `./backend` is bind-mounted over `/app` at runtime,
replacing the image's copy of `entrypoint.sh` with the host's — and Windows
filesystems do not carry the Unix execute bit. The entrypoint is therefore
invoked as `bash /app/entrypoint.sh`, which does not need it.

**`node_modules` shadowing.** The frontend service bind-mounts your folder into
`/app`. Without an anonymous volume over `/app/node_modules`, your empty
(git-ignored) host directory shadows the one built into the image and the
container starts with no dependencies. The volume ordering in
`docker-compose.yml` is load-bearing.

**Hot reload.** Two separate problems. Filesystem events do not reliably cross
the WSL2 bind mount, so Vite polls (`CHOKIDAR_USEPOLLING`). And the browser
reaches Vite on host port 54173 while the server binds 5173 inside the
container, so `VITE_HMR_CLIENT_PORT` tells the HMR websocket where to connect.
Without it, hot reload silently stops working with no error anywhere.

## Everyday commands

```powershell
docker compose logs -f backend        # follow one service
docker compose logs -f generator      # watch telemetry being sent
docker compose restart backend
docker compose ps                     # health status
docker compose down                   # stop, keep data
.\scripts\reset-database.ps1          # destroy all data (asks for confirmation)
```

## Running tests

```powershell
.\scripts\run-tests.ps1
.\scripts\run-tests.ps1 -Coverage
```

Backend tests run against SQLite, so they need no database container and leave
development data untouched. That portability is why the models use SQLAlchemy
type variants — `JSONB` degrades to `JSON`, native `UUID` to `CHAR(32)`.

Frontend tests:

```powershell
docker compose exec frontend npm run test
docker compose exec frontend npm run typecheck
```

## Making changes

**Backend.** Edit and save; uvicorn reloads. Adding a model means a migration:

```powershell
docker compose exec backend alembic revision --autogenerate -m "describe it"
docker compose exec backend alembic upgrade head
```

Read the generated migration before committing. Autogenerate is a good first
draft and an unreliable final one — it renders `JSONB` variants correctly but
has, in this project, emitted a bare `Text()` without importing it.

**Adding a detection rule.** Three steps: a module in
`backend/app/detection/rules/`, an import in that package's `__init__.py`, and
tests. The rule is picked up automatically at the next start, and
`seed_detections` creates its database row. Give it a positive test, a negative
test and a threshold test — a rule with only a positive test is a rule that
might fire on everything.

**Frontend.** Edit and save; Vite hot-reloads. New API surface goes in
`src/types/api.ts` first, then a hook in `src/hooks/queries.ts`.

## Troubleshooting

**Backend container restarts in a loop.** Check `docker compose logs backend`.
Usually `.env` is missing or still holds a `CHANGE_ME` placeholder — the config
validator refuses to start on one, deliberately.

**`address already in use`.** Something holds the port. Change it in `.env`;
that is why the ports are configurable.

**Frontend loads but every request fails.** Check `VITE_API_BASE_URL` matches
your `BACKEND_PORT`, and that `CORS_ORIGINS` includes your frontend origin. Both
are set from `.env`, so a port changed in one place and not the other is the
usual cause.

**Hot reload stopped working.** Confirm `CHOKIDAR_USEPOLLING=true` and
`VITE_HMR_CLIENT_PORT` reached the container: `docker compose exec frontend env
| findstr VITE`.

**No events appearing.** `docker compose logs generator`. If it reports
`ingest.rejected_credentials`, `INGEST_API_KEY` differs between the two
services — both read it from the same `.env`, so this usually means a stale
container. `docker compose up -d --force-recreate generator`.

**Logs show `detection.rule_not_implemented`.** This was a real defect, fixed:
the rule modules were never imported by the API process, so the registry was
empty and no event was ever evaluated. If it recurs, check the startup line:

```powershell
docker compose logs backend | Select-String "detection_rules_active"
```

It should report `count=8`. `count=0`, or an
`application.enabled_rules_without_implementation` line, means a rule module
failed to import — read the traceback above it.

**Disk filling up.** Docker Desktop's WSL2 disk grows and does not shrink on its
own. `docker system prune -a --volumes` reclaims it, but note that `--volumes`
destroys the database.

**PowerShell refuses to run a script.** Execution policy, not the script:
`powershell -ExecutionPolicy Bypass -File .\scripts\start.ps1`.

**`Database is uninitialized and superuser password is not specified`.** Postgres
is fine; `.env` is missing or has an empty `POSTGRES_PASSWORD`. Compose now
refuses to start in that state with a clear message, but if you see the raw
PostgreSQL error, run `.\scripts\check-env.ps1` — it reports exactly which
values are missing.

The original cause of this on Windows PowerShell 5.1 was `init-env.ps1` calling
`RandomNumberGenerator::Fill`, a .NET Core-only API. The script died, no `.env`
was written, and every Compose variable interpolated to an empty string. It now
detects the PowerShell edition and uses `RNGCryptoServiceProvider` on 5.1, and
verifies the file it wrote before reporting success.

If you write scripts for this project, remember that Windows PowerShell 5.1 runs
on .NET Framework 4.8 and does not support `??`, `?.`, ternary `? :`,
`ForEach-Object -Parallel`, `$PSStyle`, or `$PSVersionTable.Platform`. Several of
those are parse errors, so the script fails before its first line executes.

**Changing `POSTGRES_PASSWORD` after the first start has no effect.** PostgreSQL
applies it only when it initialises the data directory. Change it and the
backend can no longer authenticate. Either revert the value, or destroy the
volume with `.\scripts\reset-database.ps1`.
