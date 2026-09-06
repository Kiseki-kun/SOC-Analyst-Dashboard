"""Incident helpers: reference allocation and timeline construction."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.incident import Incident, IncidentTimelineEntry


def allocate_incident_uid(db: Session) -> str:
    """Human-quotable reference of the form INC-2026-0042.

    Sequential within the year because analysts read these aloud and paste them
    into tickets. The database's unique constraint is the real guard: on the
    rare collision between two concurrent creations, the caller retries.
    """
    year = datetime.now(timezone.utc).year
    prefix = f"INC-{year}-"
    highest = db.execute(
        select(func.max(Incident.incident_uid)).where(Incident.incident_uid.like(f"{prefix}%"))
    ).scalar_one_or_none()
    next_number = 1
    if highest:
        try:
            next_number = int(highest.rsplit("-", 1)[1]) + 1
        except (IndexError, ValueError):
            next_number = 1
    return f"{prefix}{next_number:04d}"


def add_timeline_entry(
    db: Session,
    incident: Incident,
    *,
    entry_type: str,
    summary: str,
    actor_email: str | None = None,
    details: dict | None = None,
    occurred_at: datetime | None = None,
) -> IncidentTimelineEntry:
    """Append to the incident narrative.

    Distinct from the audit log: this is the story an analyst writes up, in the
    order things happened, and it is meant to be read by a person.
    """
    entry = IncidentTimelineEntry(
        incident_id=incident.id,
        occurred_at=occurred_at or utcnow(),
        entry_type=entry_type,
        summary=summary[:500],
        actor_email=actor_email,
        details=details or {},
    )
    db.add(entry)
    return entry


# Status changes that stamp a lifecycle timestamp, so mean-time-to-X is
# computed from recorded fact rather than inferred later.
STATUS_TIMESTAMPS = {
    "investigating": "acknowledged_at",
    "contained": "contained_at",
    "resolved": "resolved_at",
    "closed": "closed_at",
}


def apply_status_timestamps(incident: Incident, new_status: str) -> None:
    field = STATUS_TIMESTAMPS.get(new_status)
    if field and getattr(incident, field) is None:
        setattr(incident, field, utcnow())
