"""Alert schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.core.enums import AlertStatus, Severity
from app.schemas.common import ORMModel
from app.schemas.event import EventRead


def _reject_blank(value: str) -> str:
    """Reject whitespace-only text.

    `min_length` counts characters, so "   " satisfies it. An investigation
    note that contains nothing is worse than absent: it looks like someone
    recorded a finding.
    """
    stripped = value.strip()
    if not stripped:
        raise ValueError("must not be empty or only whitespace")
    return stripped


class AlertUserRef(ORMModel):
    id: uuid.UUID
    email: str
    full_name: str


class AlertRead(ORMModel):
    id: uuid.UUID
    alert_uid: str
    rule_key: str
    title: str
    description: str
    severity: Severity
    confidence: int
    status: AlertStatus
    first_seen: datetime
    last_seen: datetime
    event_count: int
    src_ip: str | None
    dst_ip: str | None
    username: str | None
    hostname: str | None
    mitre_technique_id: str | None
    mitre_technique_name: str | None
    mitre_tactic: str | None
    assigned_to: AlertUserRef | None
    incident_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None


class AlertNoteRead(ORMModel):
    id: uuid.UUID
    author_email: str
    body: str
    created_at: datetime


class AlertDetail(AlertRead):
    evidence: dict[str, Any]
    resolution_note: str | None
    notes: list[AlertNoteRead]
    events: list[EventRead]


class AlertStatusUpdate(BaseModel):
    status: AlertStatus
    # Required when closing an alert: a resolution with no reasoning is not an
    # investigation, and the next analyst to see this IP needs the context.
    resolution_note: str | None = Field(default=None, max_length=4000)


class AlertAssign(BaseModel):
    # None unassigns.
    assignee_id: uuid.UUID | None = None


class AlertNoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=8000)

    _strip = field_validator("body")(_reject_blank)


class AlertLinkIncident(BaseModel):
    incident_id: uuid.UUID | None = None
