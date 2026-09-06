# syntax=docker/dockerfile:1

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
RUN pip install --no-cache-dir -r requirements-dev.txt

COPY . /app

# Run as an unprivileged user. Container processes must not be root: a container
# escape or an RCE in the app then lands on a user with no package-manager or
# filesystem-write rights outside /app.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Entrypoint waits for Postgres, applies migrations, then seeds demo users.
ENTRYPOINT ["bash", "/app/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
