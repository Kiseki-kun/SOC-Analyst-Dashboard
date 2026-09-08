# syntax=docker/dockerfile:1

# Two stages, and the order matters. `docker build` with no --target builds the
# LAST stage, and docker-compose.yml sets neither a target nor a command - so
# `development` is deliberately last and Compose keeps behaving exactly as
# before, hot reload and `docker compose exec backend pytest` included.
#
# Koyeb (or any other production build) must select the production stage:
#     docker build --target production -t soc-backend .
FROM python:3.13-slim AS base

# - PYTHONDONTWRITEBYTECODE: no .pyc litter in the bind-mounted source tree.
# - PYTHONUNBUFFERED: logs reach `docker compose logs` immediately.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# curl is required by the Compose healthcheck.
RUN apt-get update \
    && apt-get install --no-install-recommends -y curl \
    && rm -rf /var/lib/apt/lists/*

# Dependencies are copied and installed before the source so that editing a
# Python file does not invalidate the (slow) pip layer.
COPY requirements.txt requirements-dev.txt ./
# Runtime dependencies only. The test and lint tooling is added in the
# development stage, so it never reaches a published image.
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

# Run as an unprivileged user. Container processes must not be root: a container
# escape or an RCE in the app then lands on a user with no package-manager or
# filesystem-write rights outside /app.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Entrypoint waits for the database, applies migrations, then seeds demo users.
ENTRYPOINT ["bash", "/app/entrypoint.sh"]


# --------------------------------------------------------------------------
# Production image. Built explicitly with --target production.
# --------------------------------------------------------------------------
FROM base AS production

# `sh -c` rather than the exec form because ${PORT} has to be expanded at
# container start: Koyeb assigns the port at runtime, and the exec form would
# pass the literal string "${PORT:-8000}" to uvicorn.
#
# --proxy-headers with --forwarded-allow-ips: the platform terminates TLS and
# proxies the request, so without these every audit entry records the proxy's
# address instead of the client's. The wildcard is appropriate only because
# nothing but the platform's own proxy can reach this container.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*'"]


# --------------------------------------------------------------------------
# Development image. LAST, so it is what `docker compose build` produces.
# --------------------------------------------------------------------------
FROM base AS development

# pytest and ruff live only here. Root is needed to install, then dropped again.
USER root
RUN pip install --no-cache-dir -r requirements-dev.txt
USER appuser

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
