"""Incident management and simulated response."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, Request, status
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload

from app.api.deps import DbDep, PaginationDep, require
from app.api.v1.sorting import column_ordering, severity_ordering
from app.core.enums import (
    INCIDENT_TERMINAL_STATUSES,
    AuditAction,
    IncidentStatus,
    ResponseActionType,
    Severity,
)
from app.core.permissions import Permission
from app.models.alert import Alert
from app.models.incident import Incident, IncidentNote, ResponseAction
from app.models.user import User
from app.schemas.common import Page
from app.schemas.incident import (
    IncidentAssign,
    IncidentCreate,
    IncidentDetail,
    IncidentNoteCreate,
    IncidentNoteRead,
    IncidentRead,
    IncidentUpdate,
    ResponseActionCreate,
    ResponseActionRead,
)
from app.services import audit
from app.services.incidents import (
    add_timeline_entry,
    allocate_incident_uid,
    apply_status_timestamps,
)

router = APIRouter(prefix="/incidents", tags=["incidents"])

SORTABLE = {
    "created_at": Incident.created_at,
    "updated_at": Incident.updated_at,
    "status": Incident.status,
}

# Human-readable descriptions of what each simulated action would do in a real
# platform. Shown in the UI so the simulation is explicit at the point of use.
SIMULATED_ACTION_DESCRIPTIONS: dict[str, str] = {
    ResponseActionType.SIMULATED_IP_BLOCK.value:
        "would push a deny rule for this address to the perimeter firewall",
    ResponseActionType.SIMULATED_ACCOUNT_DISABLE.value:
        "would disable this account in the directory",
    ResponseActionType.SIMULATED_HOST_ISOLATION.value:
        "would place this host in network quarantine via the endpoint agent",
    ResponseActionType.SIMULATED_CREDENTIAL_RESET.value:
        "would force a credential reset and revoke active sessions",
    ResponseActionType.ADD_IOC_TO_WATCHLIST.value:
        "adds this indicator to the local watchlist (this one does take effect, "
        "inside this application only)",
}


def _load(db, incident_id: uuid.UUID) -> Incident:
    incident = db.execute(
        select(Incident)
        .options(
            selectinload(Incident.alerts).selectinload(Alert.assigned_to),
            selectinload(Incident.notes),
            selectinload(Incident.response_actions),
            selectinload(Incident.timeline_entries),
            selectinload(Incident.assigned_to),
            selectinload(Incident.created_by),
        )
        .where(Incident.id == incident_id)
    ).scalar_one_or_none()
    if incident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found.")
    return incident


@router.get("", response_model=Page[IncidentRead])
def list_incidents(
    db: DbDep,
    pagination: PaginationDep,
    _: User = require(Permission.INCIDENT_READ),
    incident_status: Annotated[list[IncidentStatus] | None, Query(alias="status")] = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    assigned_to_id: uuid.UUID | None = None,
    unassigned: bool | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
    sort_by: Literal["created_at", "updated_at", "severity", "status"] = "created_at",
    sort_dir: Literal["asc", "desc"] = "desc",
) -> Page[IncidentRead]:
    def apply(stmt):
        if incident_status:
            stmt = stmt.where(Incident.status.in_([s.value for s in incident_status]))
        if severity:
            stmt = stmt.where(Incident.severity.in_([s.value for s in severity]))
        if assigned_to_id:
            stmt = stmt.where(Incident.assigned_to_id == assigned_to_id)
        if unassigned:
            stmt = stmt.where(Incident.assigned_to_id.is_(None))
        if start is not None:
            stmt = stmt.where(Incident.created_at >= start)
        if end is not None:
            stmt = stmt.where(Incident.created_at <= end)
        if search:
            escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            term = f"%{escaped}%"
            stmt = stmt.where(
                or_(
                    Incident.title.ilike(term, escape="\\"),
                    Incident.description.ilike(term, escape="\\"),
                    Incident.incident_uid.ilike(term, escape="\\"),
                )
            )
        return stmt

    total = db.execute(apply(select(func.count()).select_from(Incident))).scalar_one()
    order = (
        severity_ordering(Incident.severity, sort_dir)
        if sort_by == "severity"
        else column_ordering(SORTABLE[sort_by], sort_dir)
    )
    rows = (
        db.execute(
            apply(
                select(Incident).options(
                    selectinload(Incident.assigned_to), selectinload(Incident.created_by)
                )
            )
            .order_by(order, Incident.id)
            .offset(pagination.offset)
            .limit(pagination.page_size)
        )
        .scalars()
        .all()
    )
    return Page.build(
        [IncidentRead.model_validate(r) for r in rows], total, pagination.page, pagination.page_size
    )


@router.post("", response_model=IncidentDetail, status_code=status.HTTP_201_CREATED)
def create_incident(
    payload: IncidentCreate,
    request: Request,
    db: DbDep,
    actor: User = require(Permission.INCIDENT_CREATE),
) -> IncidentDetail:
    if payload.assigned_to_id is not None:
        assignee = db.get(User, payload.assigned_to_id)
        if assignee is None or not assignee.is_active:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Assignee not found or inactive.")

    alerts: list[Alert] = []
    if payload.alert_ids:
        alerts = list(
            db.execute(select(Alert).where(Alert.id.in_(payload.alert_ids))).scalars().all()
        )
        missing = set(payload.alert_ids) - {a.id for a in alerts}
        if missing:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"{len(missing)} of the supplied alert identifiers do not exist.",
            )

    # Retry once on a UID collision: two analysts escalating simultaneously is
    # a real scenario, and the unique constraint is what actually arbitrates.
    for attempt in range(2):
        incident = Incident(
            incident_uid=allocate_incident_uid(db),
            title=payload.title,
            description=payload.description,
            severity=payload.severity.value,
            status=IncidentStatus.OPEN.value,
            created_by_id=actor.id,
            assigned_to_id=payload.assigned_to_id,
        )
        db.add(incident)
        try:
            db.flush()
            break
        except IntegrityError:
            db.rollback()
            if attempt == 1:
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    "Could not allocate an incident reference. Please retry.",
                ) from None

    add_timeline_entry(
        db, incident, entry_type="created",
        summary=f"Incident opened by {actor.email}", actor_email=actor.email,
        details={"severity": incident.severity},
    )

    for alert in alerts:
        alert.incident_id = incident.id
        add_timeline_entry(
            db, incident, entry_type="alert_linked",
            summary=f"Alert {alert.alert_uid} attached ({alert.rule_key})",
            actor_email=actor.email,
            details={"alert_uid": alert.alert_uid, "rule_key": alert.rule_key},
            # Ordered by when the alert actually fired, so the timeline reads
            # chronologically rather than by attachment order.
            occurred_at=alert.first_seen,
        )

    audit.record(
        db, action=AuditAction.INCIDENT_CREATED, actor=actor,
        resource_type="incident", resource_id=incident.id, request=request,
        details={"incident_uid": incident.incident_uid, "severity": incident.severity,
                 "count": len(alerts)},
    )
    db.commit()
    return IncidentDetail.model_validate(_load(db, incident.id))


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(
    incident_id: uuid.UUID,
    db: DbDep,
    _: User = require(Permission.INCIDENT_READ),
) -> IncidentDetail:
    return IncidentDetail.model_validate(_load(db, incident_id))


@router.patch("/{incident_id}", response_model=IncidentDetail)
def update_incident(
    incident_id: uuid.UUID,
    payload: IncidentUpdate,
    request: Request,
    db: DbDep,
    actor: User = require(Permission.INCIDENT_UPDATE),
) -> IncidentDetail:
    incident = _load(db, incident_id)

    if payload.title is not None:
        incident.title = payload.title
    if payload.description is not None:
        incident.description = payload.description
    if payload.severity is not None and payload.severity.value != incident.severity:
        previous = incident.severity
        incident.severity = payload.severity.value
        add_timeline_entry(
            db, incident, entry_type="severity_changed",
            summary=f"Severity changed from {previous} to {incident.severity}",
            actor_email=actor.email, details={"severity": incident.severity},
        )

    if payload.status is not None and payload.status.value != incident.status:
        new_status = payload.status.value
        closing = new_status in INCIDENT_TERMINAL_STATUSES
        if closing and not (payload.resolution_summary or incident.resolution_summary or "").strip():
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "A resolution summary is required before resolving or closing an incident.",
            )
        if closing and not actor.has_permission(Permission.INCIDENT_CLOSE):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "You do not have permission to resolve or close incidents.",
            )
        previous = incident.status
        incident.status = new_status
        apply_status_timestamps(incident, new_status)
        add_timeline_entry(
            db, incident, entry_type="status_changed",
            summary=f"Status changed from {previous} to {new_status}",
            actor_email=actor.email,
            details={"from_status": previous, "to_status": new_status},
        )
        audit.record(
            db, action=AuditAction.INCIDENT_STATUS_CHANGED, actor=actor,
            resource_type="incident", resource_id=incident.id, request=request,
            details={"from_status": previous, "to_status": new_status,
                     "incident_uid": incident.incident_uid},
        )

    if payload.resolution_summary is not None:
        incident.resolution_summary = payload.resolution_summary

    audit.record(
        db, action=AuditAction.INCIDENT_UPDATED, actor=actor,
        resource_type="incident", resource_id=incident.id, request=request,
        details={"incident_uid": incident.incident_uid},
    )
    db.commit()
    return IncidentDetail.model_validate(_load(db, incident_id))


@router.patch("/{incident_id}/assign", response_model=IncidentDetail)
def assign_incident(
    incident_id: uuid.UUID,
    payload: IncidentAssign,
    request: Request,
    db: DbDep,
    actor: User = require(Permission.INCIDENT_ASSIGN),
) -> IncidentDetail:
    incident = _load(db, incident_id)

    if payload.assignee_id is not None:
        assignee = db.get(User, payload.assignee_id)
        if assignee is None or not assignee.is_active:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Assignee not found or inactive.")
        if not assignee.has_permission(Permission.INCIDENT_UPDATE):
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "That user does not have permission to work incidents.",
            )
        # See the note in alerts.py: assign the relationship so the loaded
        # object and the response stay consistent.
        incident.assigned_to = assignee
        label = assignee.email
    else:
        incident.assigned_to = None
        label = "unassigned"

    add_timeline_entry(
        db, incident, entry_type="assigned",
        summary=f"Assigned to {label}", actor_email=actor.email,
        details={"assigned_to": label},
    )
    audit.record(
        db, action=AuditAction.INCIDENT_ASSIGNED, actor=actor,
        resource_type="incident", resource_id=incident.id, request=request,
        details={"assigned_to": label, "incident_uid": incident.incident_uid},
    )
    db.commit()
    return IncidentDetail.model_validate(_load(db, incident_id))


@router.post("/{incident_id}/notes", response_model=IncidentNoteRead,
             status_code=status.HTTP_201_CREATED)
def add_incident_note(
    incident_id: uuid.UUID,
    payload: IncidentNoteCreate,
    request: Request,
    db: DbDep,
    actor: User = require(Permission.INCIDENT_NOTE_CREATE),
) -> IncidentNoteRead:
    incident = _load(db, incident_id)
    note = IncidentNote(
        incident_id=incident.id, author_id=actor.id,
        author_email=actor.email, body=payload.body,
    )
    db.add(note)
    add_timeline_entry(
        db, incident, entry_type="note_added",
        summary=f"Investigation note added by {actor.email}", actor_email=actor.email,
        details={"note_length": len(payload.body)},
    )
    audit.record(
        db, action=AuditAction.INCIDENT_NOTE_ADDED, actor=actor,
        resource_type="incident", resource_id=incident.id, request=request,
        details={"incident_uid": incident.incident_uid, "note_length": len(payload.body)},
    )
    db.commit()
    db.refresh(note)
    return IncidentNoteRead.model_validate(note)


@router.post("/{incident_id}/response-actions", response_model=ResponseActionRead,
             status_code=status.HTTP_201_CREATED)
def simulate_response_action(
    incident_id: uuid.UUID,
    payload: ResponseActionCreate,
    request: Request,
    db: DbDep,
    actor: User = require(Permission.RESPONSE_ACTION_EXECUTE),
) -> ResponseActionRead:
    """Record a SIMULATED containment action.

    This endpoint writes a row and nothing else. It does not contact a
    firewall, a directory service, an endpoint agent, or any other system —
    none of which this application has a client for. The only action with a
    real effect is adding an indicator to the local watchlist, which affects
    future detections inside this application.
    """
    incident = _load(db, incident_id)

    action = ResponseAction(
        incident_id=incident.id,
        action_type=payload.action_type.value,
        target=payload.target,
        parameters=payload.parameters,
        note=payload.note,
        performed_by_id=actor.id,
        performed_by_email=actor.email,
        simulated=True,
    )
    db.add(action)

    description = SIMULATED_ACTION_DESCRIPTIONS.get(payload.action_type.value, "")
    add_timeline_entry(
        db, incident, entry_type="response_action",
        summary=(
            f"SIMULATED {payload.action_type.value.replace('_', ' ')} "
            f"against {payload.target}"
        ),
        actor_email=actor.email,
        details={"action_type": payload.action_type.value, "target": payload.target,
                 "reason": description},
    )
    audit.record(
        db, action=AuditAction.RESPONSE_ACTION_SIMULATED, actor=actor,
        resource_type="incident", resource_id=incident.id, request=request,
        details={"action_type": payload.action_type.value, "target": payload.target,
                 "incident_uid": incident.incident_uid},
    )
    db.commit()
    db.refresh(action)
    return ResponseActionRead.model_validate(action)
