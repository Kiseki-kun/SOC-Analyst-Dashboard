#!/usr/bin/env bash
# Backend container entrypoint.
#
# NOTE: this file must keep LF line endings. .gitattributes enforces that.
# A CRLF copy fails inside the container with the misleading error
# "exec /app/entrypoint.sh: no such file or directory".
set -euo pipefail

# Where the database actually is depends on how this deployment is configured.
# With DATABASE_URL_OVERRIDE set (a managed instance such as Neon) the Compose
# service name `postgres` does not resolve at all, so probing it would burn the
# whole retry budget and abort a container that could have started.
#
# Only the hostname is echoed. The override carries the username, the password
# and the connection parameters, and none of those belong in a startup log.
if [ -n "${DATABASE_URL_OVERRIDE:-}" ]; then
    DB_TARGET="$(python -c "
import os
from urllib.parse import urlsplit
print(urlsplit(os.environ.get('DATABASE_URL_OVERRIDE', '')).hostname or 'external host')
" 2>/dev/null || echo 'external host')"
    echo "[entrypoint] waiting for external database at ${DB_TARGET} (DATABASE_URL_OVERRIDE) ..."
else
    echo "[entrypoint] waiting for database at ${POSTGRES_HOST:-postgres}:5432 ..."
fi

# Compose's service_healthy condition already gates startup, but a container
# restart can outrun the health check. This is a cheap, explicit guard.
ATTEMPTS=0
MAX_ATTEMPTS=60
until python -c "
import os, sys
from urllib.parse import urlsplit, urlunsplit

import psycopg

override = os.environ.get('DATABASE_URL_OVERRIDE', '').strip()
try:
    if override:
        # DATABASE_URL_OVERRIDE is a SQLAlchemy URL. Its dialect suffix
        # ('postgresql+psycopg://') is not valid libpq conninfo, so strip it.
        # Everything else is passed through untouched, which is what preserves
        # sslmode=require and any other parameter a managed provider needs.
        parts = urlsplit(override)
        conninfo = urlunsplit((
            parts.scheme.split('+', 1)[0],
            parts.netloc,
            parts.path,
            parts.query,
            parts.fragment,
        ))
        # Longer than the local timeout: a managed instance may be resuming
        # from idle, and TLS plus a wider network path is simply slower.
        psycopg.connect(conninfo, connect_timeout=10).close()
    else:
        psycopg.connect(
            host=os.environ.get('POSTGRES_HOST', 'postgres'),
            port=5432,
            user=os.environ['POSTGRES_USER'],
            password=os.environ['POSTGRES_PASSWORD'],
            dbname=os.environ['POSTGRES_DB'],
            connect_timeout=3,
        ).close()
except Exception as exc:
    print(exc, file=sys.stderr)
    sys.exit(1)
" 2>/dev/null; do
    ATTEMPTS=$((ATTEMPTS + 1))
    if [ "$ATTEMPTS" -ge "$MAX_ATTEMPTS" ]; then
        echo "[entrypoint] database unreachable after ${MAX_ATTEMPTS} attempts; aborting." >&2
        exit 1
    fi
    sleep 2
done
echo "[entrypoint] database is reachable."

echo "[entrypoint] applying database migrations ..."
alembic upgrade head

# Detection rules and the synthetic IOC watchlist are always synchronised:
# they are application definitions, not demo data, and the engine cannot run
# without them. Tuned thresholds are preserved.
echo "[entrypoint] synchronising detection rules and IOC watchlist ..."
python -m app.cli.seed_detections

if [ "${SEED_DEMO_USERS:-false}" = "true" ]; then
    echo "[entrypoint] seeding demo users (no-op if users already exist) ..."
    python -m app.cli.seed
fi

echo "[entrypoint] starting: $*"
exec "$@"
