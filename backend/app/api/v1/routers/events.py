"""Event explorer: search, filter, sort, paginate."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, or_, select

from app.api.deps import DbDep, PaginationDep, require
from app.api.v1.sorting import column_ordering, severity_ordering
from app.core.enums import EventOutcome, EventType, Severity
from app.core.permissions import Permission
from app.models.event import SecurityEvent
from app.models.user import User
from app.schemas.common import Page
from app.schemas.event import EventDetail, EventRead

router = APIRouter(prefix="/events", tags=["events"])

# Only columns that are indexed or cheap to sort are offered. Accepting an
# arbitrary column name from the query string would be both a performance trap
# and a small injection surface.
SORTABLE = {
    "timestamp": SecurityEvent.timestamp,
    "severity": SecurityEvent.severity,
    "event_type": SecurityEvent.event_type,
    "outcome": SecurityEvent.outcome,
    "src_ip": SecurityEvent.src_ip,
    "username": SecurityEvent.username,
}


def _apply_filters(stmt, *, start, end, severity, event_type, outcome, source,
                   src_ip, dst_ip, username, hostname, search):
    if start is not None:
        stmt = stmt.where(SecurityEvent.timestamp >= start)
    if end is not None:
        stmt = stmt.where(SecurityEvent.timestamp <= end)
    if severity:
        stmt = stmt.where(SecurityEvent.severity.in_([s.value for s in severity]))
    if event_type:
        stmt = stmt.where(SecurityEvent.event_type.in_([t.value for t in event_type]))
    if outcome:
        stmt = stmt.where(SecurityEvent.outcome.in_([o.value for o in outcome]))
    if source:
        stmt = stmt.where(SecurityEvent.source == source)
    if src_ip:
        stmt = stmt.where(SecurityEvent.src_ip == src_ip)
    if dst_ip:
        stmt = stmt.where(SecurityEvent.dst_ip == dst_ip)
    if username:
        stmt = stmt.where(SecurityEvent.username == username)
    if hostname:
        stmt = stmt.where(SecurityEvent.hostname == hostname)
    if search:
        # Parameterised LIKE via SQLAlchemy - the term is bound, never
        # interpolated. `%` and `_` are escaped so a user searching for "50%"
        # does not accidentally issue a wildcard query.
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        term = f"%{escaped}%"
        stmt = stmt.where(
            or_(
                SecurityEvent.message.ilike(term, escape="\\"),
                SecurityEvent.username.ilike(term, escape="\\"),
                SecurityEvent.hostname.ilike(term, escape="\\"),
                SecurityEvent.url_path.ilike(term, escape="\\"),
                SecurityEvent.dns_query.ilike(term, escape="\\"),
                SecurityEvent.process_name.ilike(term, escape="\\"),
                SecurityEvent.command_line.ilike(term, escape="\\"),
            )
        )
    return stmt


@router.get("", response_model=Page[EventRead])
def list_events(
    db: DbDep,
    pagination: PaginationDep,
    _: User = require(Permission.EVENT_READ),
    start: datetime | None = None,
    end: datetime | None = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    event_type: Annotated[list[EventType] | None, Query()] = None,
    outcome: Annotated[list[EventOutcome] | None, Query()] = None,
    source: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    username: str | None = None,
    hostname: str | None = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
    sort_by: Literal[
        "timestamp", "severity", "event_type", "outcome", "src_ip", "username"
    ] = "timestamp",
    sort_dir: Literal["asc", "desc"] = "desc",
) -> Page[EventRead]:
    filters = {
        "start": start, "end": end, "severity": severity, "event_type": event_type,
        "outcome": outcome, "source": source, "src_ip": src_ip, "dst_ip": dst_ip,
        "username": username, "hostname": hostname, "search": search,
    }

    total = db.execute(
        _apply_filters(select(func.count()).select_from(SecurityEvent), **filters)
    ).scalar_one()

    # Severity is text in the database, so a plain ORDER BY would sort it
    # alphabetically (critical < high < info < low < medium) - the opposite of
    # useful. Every table that exposes severity sorting uses the same helper.
    order = (
        severity_ordering(SecurityEvent.severity, sort_dir)
        if sort_by == "severity"
        else column_ordering(SORTABLE[sort_by], sort_dir)
    )
    rows = (
        db.execute(
            _apply_filters(select(SecurityEvent), **filters)
            # Secondary sort on the primary key keeps pagination stable when
            # many rows share a timestamp; without it, page 2 can repeat rows
            # from page 1.
            .order_by(order, SecurityEvent.id)
            .offset(pagination.offset)
            .limit(pagination.page_size)
        )
        .scalars()
        .all()
    )
    return Page.build(
        [EventRead.model_validate(r) for r in rows], total, pagination.page, pagination.page_size
    )


@router.get("/{event_id}", response_model=EventDetail)
def get_event(
    event_id: uuid.UUID,
    db: DbDep,
    _: User = require(Permission.EVENT_READ),
) -> EventDetail:
    event = db.get(SecurityEvent, event_id)
    if event is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Event not found.")
    return EventDetail.model_validate(event)
