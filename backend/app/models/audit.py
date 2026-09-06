"""Audit log and the IOC watchlist."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, JSONVariant, TimestampMixin, UTCDateTime, utcnow


class AuditLog(Base):
    """Append-only record of security-relevant actions.

    There is no update or delete path to this table anywhere in the API: the
    service layer exposes only `record()`, and the audit router is read-only and
    admin-gated. That is the enforcement — a comment claiming immutability while
    a PATCH endpoint exists would be worthless.
    """

    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    timestamp: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, default=utcnow, index=True
    )

    # Nullable: a failed login has no authenticated actor. The attempted
    # identifier is still captured in actor_email, which is what makes
    # credential-stuffing visible in the audit view.
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    actor_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    actor_role: Mapped[str | None] = mapped_column(String(20), nullable=True)

    action: Mapped[str] = mapped_column(String(48), nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(48), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Never contains credentials or tokens: the audit service allow-lists which
    # keys may be recorded.
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONVariant, nullable=False, default=dict
    )

    __table_args__ = (
        Index("ix_audit_action_timestamp", "action", "timestamp"),
        Index("ix_audit_actor_timestamp", "actor_id", "timestamp"),
        Index("ix_audit_resource", "resource_type", "resource_id"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AuditLog {self.action} actor={self.actor_email} ok={self.success}>"


class IOCWatchlistEntry(Base, TimestampMixin):
    """Indicators of compromise, all synthetic.

    Doubles as detection input: the malicious-hash rule matches events against
    the active entries here, so adding an IOC during an investigation
    immediately affects future detections.
    """

    __tablename__ = "ioc_watchlist"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    ioc_type: Mapped[str] = mapped_column(String(24), nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    added_by_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    added_by_email: Mapped[str | None] = mapped_column(String(320), nullable=True)

    __table_args__ = (
        UniqueConstraint("ioc_type", "value", name="uq_ioc_type_value"),
        Index("ix_ioc_active_type", "active", "ioc_type"),
    )
