"""Incidents, their notes, and simulated response actions."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    ForeignKey,
    Index,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import IncidentStatus, Severity
from app.db.base import Base, JSONVariant, TimestampMixin, UTCDateTime


class Incident(Base, TimestampMixin):
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Human-quotable reference, e.g. INC-2026-0042.
    incident_uid: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)

    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default=Severity.MEDIUM.value
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=IncidentStatus.OPEN.value
    )

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Timestamps that make mean-time-to-* metrics computable rather than guessed.
    acknowledged_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime, nullable=True
    )
    contained_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime, nullable=True
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime, nullable=True
    )
    closed_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime, nullable=True
    )
    resolution_summary: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Two separate FKs to users, so each relationship must name its own.
    assigned_to: Mapped[User | None] = relationship(  # noqa: F821
        back_populates="assigned_incidents",
        foreign_keys=[assigned_to_id],
    )
    created_by: Mapped[User | None] = relationship(  # noqa: F821
        foreign_keys=[created_by_id],
    )

    alerts: Mapped[list[Alert]] = relationship(  # noqa: F821
        back_populates="incident",
        foreign_keys="Alert.incident_id",
    )
    notes: Mapped[list[IncidentNote]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentNote.created_at",
    )
    response_actions: Mapped[list[ResponseAction]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="ResponseAction.created_at",
    )
    timeline_entries: Mapped[list[IncidentTimelineEntry]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentTimelineEntry.occurred_at",
    )

    __table_args__ = (
        Index("ix_incidents_status_created", "status", "created_at"),
        Index("ix_incidents_severity_created", "severity", "created_at"),
        Index("ix_incidents_assigned_status", "assigned_to_id", "status"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Incident {self.incident_uid} {self.severity} {self.status}>"


class IncidentNote(Base, TimestampMixin):
    __tablename__ = "incident_notes"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    author_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    author_email: Mapped[str] = mapped_column(String(320), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)

    incident: Mapped[Incident] = relationship(back_populates="notes")

    __table_args__ = (
        Index("ix_incident_notes_incident_created", "incident_id", "created_at"),
    )


class IncidentTimelineEntry(Base, TimestampMixin):
    """Ordered narrative of what happened to an incident.

    Separate from the audit log on purpose: the audit log answers "who did what
    to this system" for compliance, this answers "what happened during this
    investigation" for the analyst writing it up.
    """

    __tablename__ = "incident_timeline_entries"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    entry_type: Mapped[str] = mapped_column(String(48), nullable=False)
    summary: Mapped[str] = mapped_column(String(500), nullable=False)
    actor_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONVariant, nullable=False, default=dict
    )

    incident: Mapped[Incident] = relationship(back_populates="timeline_entries")

    __table_args__ = (
        Index("ix_timeline_incident_occurred", "incident_id", "occurred_at"),
    )


class ResponseAction(Base, TimestampMixin):
    """A simulated containment action.

    Nothing in this table causes any effect outside this database. There is no
    code path from a row here to a firewall, a directory service, an endpoint
    agent, or any external system — by design, and verified by the absence of
    any such client in the dependency list.
    """

    __tablename__ = "response_actions"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True
    )
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True
    )
    action_type: Mapped[str] = mapped_column(String(48), nullable=False)
    # What the action nominally targets: an IP, an account, a hostname.
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    parameters: Mapped[dict[str, Any]] = mapped_column(
        JSONVariant, nullable=False, default=dict
    )
    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    performed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    performed_by_email: Mapped[str] = mapped_column(String(320), nullable=False)

    # Always True. Stored explicitly so the column shows up in every API
    # response and every export, making the simulation impossible to overlook.
    simulated: Mapped[bool] = mapped_column(nullable=False, default=True)

    incident: Mapped[Incident | None] = relationship(back_populates="response_actions")

    __table_args__ = (
        Index("ix_response_actions_incident", "incident_id", "created_at"),
        Index("ix_response_actions_type", "action_type"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<ResponseAction {self.action_type} target={self.target} simulated=True>"
