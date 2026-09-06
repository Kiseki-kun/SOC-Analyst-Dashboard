"""Telemetry ingestion.

Authenticated with a shared service key rather than a user session — the
generator is a machine, not a person, and should not hold a user account.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, status

from app.api.deps import DbDep, require_ingest_key
from app.schemas.event import EventBatchIn, IngestResult
from app.services.ingest import ingest_events

router = APIRouter(prefix="/ingest", tags=["ingest"])


@router.post(
    "/events",
    response_model=IngestResult,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_ingest_key)],
)
def ingest_batch(batch: EventBatchIn, db: DbDep) -> IngestResult:
    """Accept a batch of raw events.

    Batch size is capped by the schema (500). Returning per-category counts
    rather than a bare 202 lets the generator notice that its events are being
    rejected instead of silently filling the void.
    """
    outcome = ingest_events(db, batch.events)
    return IngestResult(
        received=outcome.received,
        stored=outcome.stored,
        duplicates=outcome.duplicates,
        rejected=outcome.rejected,
        alerts_created=outcome.alerts_created,
        alerts_updated=outcome.alerts_updated,
    )
