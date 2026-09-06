"""User accounts."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, Index, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.permissions import Permission, Role, permissions_for
from app.db.base import Base, TimestampMixin, UTCDateTime


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Stored lower-cased (enforced in the service layer) so the unique index
    # actually prevents "Alice@x" and "alice@x" both registering.
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True)
    full_name: Mapped[str] = mapped_column(String(200), nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default=Role.VIEWER.value)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_login_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime, nullable=True
    )
    # Incremented on password change / forced logout. A future revocation check
    # can compare this against a claim to invalidate outstanding tokens.
    token_version: Mapped[int] = mapped_column(nullable=False, default=0)

    assigned_alerts: Mapped[list[Alert]] = relationship(  # noqa: F821
        back_populates="assigned_to",
        foreign_keys="Alert.assigned_to_id",
    )
    assigned_incidents: Mapped[list[Incident]] = relationship(  # noqa: F821
        back_populates="assigned_to",
        foreign_keys="Incident.assigned_to_id",
    )

    __table_args__ = (
        Index("ix_users_role_active", "role", "is_active"),
    )

    @property
    def permissions(self) -> frozenset[Permission]:
        return permissions_for(self.role)

    def has_permission(self, permission: Permission) -> bool:
        return permission in self.permissions

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<User {self.email} role={self.role} active={self.is_active}>"
