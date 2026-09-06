"""Alert triage and investigation."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, Request, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import selectinload

from app.api.deps import DbDep, PaginationDep, require
from app.api.v1.sorting import column_ordering, severity_ordering
from app.core.enums import ALERT_TERMINAL_STATUSES, AlertStatus, AuditAction, Severity
from app.core.permissions import Permission
from app.db.base import utcnow
from app.models.alert import Alert, AlertNote
from app.models.incident import Incident
from app.models.user import User
from app.schemas.alert import (
    AlertAssign,
    AlertDetail,
    AlertLinkIncident,
    AlertNoteCreate,
    AlertNoteRead,
    AlertRead,
    AlertStatusUpdate,
)
from app.schemas.common import Page
from app.services import audit

router = APIRouter(prefix="/alerts", tags=["alerts"])

SORTABLE = {
    "created_at": Alert.created_at,
    "last_seen": Alert.last_seen,
    "severity": Alert.severity,
    "confidence": Alert.confidence,
    "status": Alert.status,
    "rule_key": Alert.rule_key,
    "src_ip": Alert.src_ip,
}

def _load_alert(db, alert_id: uuid.UUID) -> Alert:
    alert = db.execute(
        select(Alert)
        .options(
            selectinload(Alert.notes),
            selectinload(Alert.events),
            selectinload(Alert.assigned_to),
        )
        .where(Alert.id == alert_id)
    ).scalar_one_or_none()
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found.")
    return alert


@router.get("", response_model=Page[AlertRead])
def list_alerts(
    db: DbDep,
    pagination: PaginationDep,
    _: User = require(Permission.ALERT_READ),
    alert_status: Annotated[list[AlertStatus] | None, Query(alias="status")] = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    rule_key: str | None = None,
    src_ip: str | None = None,
    username: str | None = None,
    assigned_to_id: uuid.UUID | None = None,
    unassigned: bool | None = None,
    incident_id: uuid.UUID | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
    sort_by: Literal[
        "created_at", "last_seen", "severity", "confidence", "status",
        "rule_key", "src_ip",
    ] = "created_at",
    sort_dir: Literal["asc", "desc"] = "desc",
) -> Page[AlertRead]:
    def apply(stmt):
        if alert_status:
            stmt = stmt.where(Alert.status.in_([s.value for s in alert_status]))
        if severity:
            stmt = stmt.where(Alert.severity.in_([s.value for s in severity]))
        if rule_key:
            stmt = stmt.where(Alert.rule_key == rule_key)
        if src_ip:
            stmt = stmt.where(Alert.src_ip == src_ip)
        if username:
            stmt = stmt.where(Alert.username == username)
        if assigned_to_id:
            stmt = stmt.where(Alert.assigned_to_id == assigned_to_id)
        if unassigned:
            stmt = stmt.where(Alert.assigned_to_id.is_(None))
        if incident_id:
            stmt = stmt.where(Alert.incident_id == incident_id)
        if start is not None:
            stmt = stmt.where(Alert.created_at >= start)
        if end is not None:
            stmt = stmt.where(Alert.created_at <= end)
        if search:
            escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            term = f"%{escaped}%"
            stmt = stmt.where(
                or_(
                    Alert.title.ilike(term, escape="\\"),
                    Alert.description.ilike(term, escape="\\"),
                    Alert.alert_uid.ilike(term, escape="\\"),
                    Alert.src_ip.ilike(term, escape="\\"),
                    Alert.username.ilike(term, escape="\\"),
                )
            )
        return stmt

    total = db.execute(apply(select(func.count()).select_from(Alert))).scalar_one()

    order = (
        severity_ordering(Alert.severity, sort_dir)
        if sort_by == "severity"
        else column_ordering(SORTABLE[sort_by], sort_dir)
    )

    rows = (
        db.execute(
            apply(select(Alert).options(selectinload(Alert.assigned_to)))
            .order_by(order, Alert.id)
            .offset(pagination.offset)
            .limit(pagination.page_size)
        )
        .scalars()
        .all()
    )
    return Page.build(
        [AlertRead.model_validate(r) for r in rows], total, pagination.page, pagination.page_size
    )


@router.get("/{alert_id}", response_model=AlertDetail)
def get_alert(
    alert_id: uuid.UUID,
    db: DbDep,
    _: User = require(Permission.ALERT_READ),
) -> AlertDetail:
    return AlertDetail.model_validate(_load_alert(db, alert_id))


@router.patch("/{alert_id}/status", response_model=AlertDetail)
def update_alert_status(
    alert_id: uuid.UUID,
    payload: AlertStatusUpdate,
    request: Request,
    db: DbDep,
    actor: User = require(Permission.ALERT_TRIAGE),
) -> AlertDetail:
    alert = _load_alert(db, alert_id)
    previous = alert.status

    if previous == payload.status.value:
        return AlertDetail.model_validate(alert)

    closing = payload.status.value in ALERT_TERMINAL_STATUSES
    if closing and not (payload.resolution_note or "").strip():
        # Closing an alert is a judgement call. Requiring the reasoning is what
        # separates a triage queue from a "mark all read" button.
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "A resolution note is required when resolving or dismissing an alert.",
        )

    alert.status = payload.status.value
    if closing:
        alert.resolved_at = utcnow()
        alert.resolution_note = payload.resolution_note
    else:
        alert.resolved_at = None

    audit.record(
        db,
        action=AuditAction.ALERT_STATUS_CHANGED,
        actor=actor,
        resource_type="alert",
        resource_id=alert.id,
        request=request,
        details={"from_status": previous, "to_status": alert.status, "alert_uid": alert.alert_uid},
    )
    db.commit()
    return AlertDetail.model_validate(_load_alert(db, alert_id))


@router.patch("/{alert_id}/assign", response_model=AlertDetail)
def assign_alert(
    alert_id: uuid.UUID,
    payload: AlertAssign,
    request: Request,
    db: DbDep,
    actor: User = require(Permission.ALERT_TRIAGE),
) -> AlertDetail:
    alert = _load_alert(db, alert_id)

    if payload.assignee_id is not None:
        assignee = db.get(User, payload.assignee_id)
        if assignee is None or not assignee.is_active:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Assignee not found or inactive.")
        if not assignee.has_permission(Permission.ALERT_TRIAGE):
            # Assigning work to someone who cannot act on it produces a queue
            # that silently never moves.
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "That user does not have permission to triage alerts.",
            )
        # Assign the relationship, not just the FK: the alert object is
        # already loaded with `assigned_to` populated, and setting the column
        # alone leaves that stale, so the response would report the alert as
        # still unassigned.
        alert.assigned_to = assignee
        assigned_label = assignee.email
    else:
        alert.assigned_to = None
        assigned_label = "unassigned"

    audit.record(
        db,
        action=AuditAction.ALERT_ASSIGNED,
        actor=actor,
        resource_type="alert",
        resource_id=alert.id,
        request=request,
        details={"assigned_to": assigned_label, "alert_uid": alert.alert_uid},
    )
    db.commit()
    return AlertDetail.model_validate(_load_alert(db, alert_id))


@router.post("/{alert_id}/notes", response_model=AlertNoteRead, status_code=status.HTTP_201_CREATED)
def add_alert_note(
    alert_id: uuid.UUID,
    payload: AlertNoteCreate,
    request: Request,
    db: DbDep,
    actor: User = require(Permission.ALERT_NOTE_CREATE),
) -> AlertNoteRead:
    alert = _load_alert(db, alert_id)
    note = AlertNote(
        alert_id=alert.id,
        author_id=actor.id,
        author_email=actor.email,
        body=payload.body,
    )
    db.add(note)
    audit.record(
        db,
        action=AuditAction.ALERT_NOTE_ADDED,
        actor=actor,
        resource_type="alert",
        resource_id=alert.id,
        request=request,
        # The note body is not audited: it is investigation content, already
        # stored and attributed, and copying it here would duplicate
        # potentially sensitive text into a second table.
        details={"alert_uid": alert.alert_uid, "note_length": len(payload.body)},
    )
    db.commit()
    db.refresh(note)
    return AlertNoteRead.model_validate(note)


@router.patch("/{alert_id}/incident", response_model=AlertDetail)
def link_alert_to_incident(
    alert_id: uuid.UUID,
    payload: AlertLinkIncident,
    request: Request,
    db: DbDep,
    actor: User = require(Permission.INCIDENT_UPDATE),
) -> AlertDetail:
    alert = _load_alert(db, alert_id)

    if payload.incident_id is not None:
        incident = db.get(Incident, payload.incident_id)
        if incident is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found.")
        alert.incident_id = incident.id
        label = incident.incident_uid
    else:
        alert.incident_id = None
        label = "unlinked"

    audit.record(
        db,
        action=AuditAction.ALERT_LINKED_TO_INCIDENT,
        actor=actor,
        resource_type="alert",
        resource_id=alert.id,
        request=request,
        details={"alert_uid": alert.alert_uid, "incident_uid": label},
    )
    db.commit()
    return AlertDetail.model_validate(_load_alert(db, alert_id))
