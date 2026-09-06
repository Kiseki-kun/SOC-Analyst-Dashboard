"""Incident schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.core.enums import IncidentStatus, ResponseActionType, Severity
from app.schemas.alert import AlertRead, AlertUserRef
from app.schemas.common import ORMModel


class IncidentNoteRead(ORMModel):
    id: uuid.UUID
    author_email: str
    body: str
    created_at: datetime


class TimelineEntryRead(ORMModel):
    id: uuid.UUID
    occurred_at: datetime
    entry_type: str
    summary: str
    actor_email: str | None
    details: dict[str, Any]


class ResponseActionRead(ORMModel):
    id: uuid.UUID
    action_type: ResponseActionType
    target: str
    parameters: dict[str, Any]
    note: str | None
    performed_by_email: str
    # Always true. Present in every response so a consumer cannot mistake a
    # recorded intent for a real containment action.
    simulated: bool
    created_at: datetime


class IncidentRead(ORMModel):
    id: uuid.UUID
    incident_uid: str
    title: str
    description: str
    severity: Severity
    status: IncidentStatus
    assigned_to: AlertUserRef | None
    created_by: AlertUserRef | None
    created_at: datetime
    updated_at: datetime
    acknowledged_at: datetime | None
    contained_at: datetime | None
    resolved_at: datetime | None
    closed_at: datetime | None
    resolution_summary: str | None


class IncidentDetail(IncidentRead):
    alerts: list[AlertRead]
    notes: list[IncidentNoteRead]
    response_actions: list[ResponseActionRead]
    timeline_entries: list[TimelineEntryRead]


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=300)
    description: str = Field(default="", max_length=8000)
    severity: Severity = Severity.MEDIUM
    # Alerts to attach on creation - the usual path is "escalate this alert".
    alert_ids: list[uuid.UUID] = Field(default_factory=list, max_length=200)
    assigned_to_id: uuid.UUID | None = None


class IncidentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=300)
    description: str | None = Field(default=None, max_length=8000)
    severity: Severity | None = None
    status: IncidentStatus | None = None
    resolution_summary: str | None = Field(default=None, max_length=8000)


class IncidentAssign(BaseModel):
    assignee_id: uuid.UUID | None = None


class IncidentNoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=8000)

    @field_validator("body")
    @classmethod
    def _reject_blank(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("must not be empty or only whitespace")
        return stripped


class ResponseActionCreate(BaseModel):
    action_type: ResponseActionType
    target: str = Field(min_length=1, max_length=255)
    note: str | None = Field(default=None, max_length=4000)
    parameters: dict[str, Any] = Field(default_factory=dict)
