"""Liveness and readiness."""

from __future__ import annotations

from fastapi import APIRouter, status
from sqlalchemy import text

from app.api.deps import DbDep
from app.core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(tags=["health"])


@router.get("/health")
def health(db: DbDep) -> dict[str, str]:
    """Used by the Compose healthcheck, so it must stay cheap and unauthenticated.

    It reports only liveness and database reachability — never version numbers,
    hostnames or configuration, which would be free reconnaissance.
    """
    try:
        db.execute(text("SELECT 1"))
        database = "ok"
    except Exception:
        logger.exception("health.database_unreachable")
        database = "unavailable"

    return {"status": "ok" if database == "ok" else "degraded", "database": database}


@router.get("/health/ready", status_code=status.HTTP_200_OK)
def readiness(db: DbDep) -> dict[str, bool]:
    db.execute(text("SELECT 1"))
    return {"ready": True}
