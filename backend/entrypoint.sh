#!/usr/bin/env bash
# Backend container entrypoint.
#
# NOTE: this file must keep LF line endings. .gitattributes enforces that.
# A CRLF copy fails inside the container with the misleading error
# "exec /app/entrypoint.sh: no such file or directory".
set -euo pipefail

echo "[entrypoint] waiting for database at ${POSTGRES_HOST:-postgres}:5432 ..."

# Compose's service_healthy condition already gates startup, but a container
# restart can outrun the health check. This is a cheap, explicit guard.
ATTEMPTS=0
MAX_ATTEMPTS=60
until python -c "
import os, sys
import psycopg
try:
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
