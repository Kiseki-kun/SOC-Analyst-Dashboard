# docker/

Shared Docker assets that do not belong to a single build context.

Each service keeps its own `Dockerfile` next to its source (`backend/`,
`frontend/`, `generator/`). That is deliberate: a Dockerfile can only `COPY`
from within its build context, so placing them here would force the build
context to be the repository root and ship every service's source into every
image.

Files that must live inside a service's context — `backend/entrypoint.sh` is the
main one — are stored there for the same reason.

| Path | Purpose |
|------|---------|
| `../database/init/` | SQL executed once on first database creation |
| `../backend/entrypoint.sh` | Waits for Postgres, migrates, seeds, then execs uvicorn |
| `../docker-compose.yml` | The development stack |
