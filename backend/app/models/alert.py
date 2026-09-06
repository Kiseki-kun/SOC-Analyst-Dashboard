"""Alerts and their link to the events that produced them."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Column,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import AlertStatus, Severity
from app.db.base import Base, JSONVariant, TimestampMixin, UTCDateTime

# Association table. An alert is evidence-backed: it points at the exact events
# that triggered it, which is what makes an investigation reproducible.
alert_events = Table(
    "alert_events",
    Base.metadata,
    Column(
        "alert_id",
        Uuid(as_uuid=True),
        ForeignKey("alerts.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "event_id",
        Uuid(as_uuid=True),
        ForeignKey("security_events.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Index("ix_alert_events_event_id", "event_id"),
)


class Alert(Base, TimestampMixin):
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    alert_uid: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)

    rule_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("detection_rules.id", ondelete="RESTRICT"),
        nullable=False,
    )
    # Snapshot of the rule identity at firing time. Rules can be renamed or
    # disabled; an alert must still describe what it meant when it fired.
    rule_key: Mapped[str] = mapped_column(String(64), nullable=False)

    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default=Severity.MEDIUM.value
    )
    # 0-100. How strongly the rule believes this is real, distinct from how bad
    # it would be if it were. Analysts triage on both.
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=AlertStatus.NEW.value
    )

    # Deduplication key: rule + entity + time bucket. A brute-force burst should
    # raise one alert that accumulates evidence, not one alert per failed login.
    dedup_key: Mapped[str] = mapped_column(String(255), nullable=False)

    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Denormalized pivot fields, copied so the alert list can be filtered and
    # sorted without joining through the association table.
    src_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(128), nullable=True)

    mitre_technique_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    mitre_technique_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    mitre_tactic: Mapped[str | None] = mapped_column(String(64), nullable=True)

    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True
    )

    resolved_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime, nullable=True
    )
    resolution_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Rule-supplied supporting data: the ports scanned, the accounts targeted,
    # the indicators matched. Stored so triage does not require re-running the
    # detection or reading every linked event.
    evidence: Mapped[dict] = mapped_column(JSONVariant, nullable=False, default=dict)

    rule: Mapped[DetectionRule] = relationship(back_populates="alerts")  # noqa: F821
    assigned_to: Mapped[User | None] = relationship(  # noqa: F821
        back_populates="assigned_alerts", foreign_keys=[assigned_to_id]
    )
    incident: Mapped[Incident | None] = relationship(  # noqa: F821
        back_populates="alerts", foreign_keys=[incident_id]
    )
    events: Mapped[list[SecurityEvent]] = relationship(  # noqa: F821
        secondary=alert_events, lazy="selectin"
    )
    notes: Mapped[list[AlertNote]] = relationship(
        back_populates="alert", cascade="all, delete-orphan", order_by="AlertNote.created_at"
    )

    __table_args__ = (
        # One open alert per rule+entity+bucket. Enforced by the database, not
        # by application logic, so a concurrent ingest batch cannot race past it.
        UniqueConstraint("dedup_key", name="uq_alerts_dedup_key"),
        Index("ix_alerts_status_created", "status", "created_at"),
        Index("ix_alerts_severity_created", "severity", "created_at"),
        Index("ix_alerts_rule_created", "rule_key", "created_at"),
        Index("ix_alerts_assigned_status", "assigned_to_id", "status"),
        Index("ix_alerts_src_ip", "src_ip"),
        Index("ix_alerts_incident", "incident_id"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Alert {self.alert_uid} {self.rule_key} {self.severity} {self.status}>"


class AlertNote(Base, TimestampMixin):
    __tablename__ = "alert_notes"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    alert_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False
    )
    author_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    # Author identity is snapshotted: deleting a user must not erase the
    # authorship of an investigation note.
    author_email: Mapped[str] = mapped_column(String(320), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)

    alert: Mapped[Alert] = relationship(back_populates="notes")

    __table_args__ = (Index("ix_alert_notes_alert_created", "alert_id", "created_at"),)
