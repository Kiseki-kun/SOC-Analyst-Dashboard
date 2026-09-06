"""v1 router assembly.

Routers are registered here rather than in main.py so the application factory
stays small and the whole API surface is readable in one place.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.routers import (
    alerts,
    analytics,
    audit,
    auth,
    detections,
    events,
    health,
    incidents,
    ingest,
    investigations,
    users,
)

api_router = APIRouter()

api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(ingest.router)
api_router.include_router(events.router)
api_router.include_router(alerts.router)
api_router.include_router(incidents.router)
api_router.include_router(investigations.router)
api_router.include_router(analytics.router)
api_router.include_router(detections.router)
api_router.include_router(audit.router)
