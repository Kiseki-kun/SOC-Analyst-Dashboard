"""Detection rules and their MITRE ATT&CK mapping.

Rule *logic* lives in code (`app/detection/rules/`); this table holds the
tunable parameters and the enable switch. That split is deliberate: thresholds
are operational settings an admin changes during a noisy afternoon, while the
matching logic is versioned, reviewed and tested like any other code.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import Boolean, Index, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import Severity
from app.db.base import Base, JSONVariant, TimestampMixin


class DetectionRule(Base, TimestampMixin):
    __tablename__ = "detection_rules"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Stable identifier that code references, e.g. "brute_force_authentication".
    # Never renamed: alerts keep a copy for historical reporting.
    rule_key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default=Severity.MEDIUM.value
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Rule-specific thresholds, validated by each rule's own config schema.
    config: Mapped[dict[str, Any]] = mapped_column(
        JSONVariant, nullable=False, default=dict
    )

    # --- MITRE ATT&CK -------------------------------------------------------
    # Real technique IDs only. An invented ID is worse than none: it looks
    # authoritative and cannot be cross-referenced.
    mitre_tactic: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mitre_technique_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    mitre_technique_name: Mapped[str | None] = mapped_column(String(128), nullable=True)

    alerts: Mapped[list[Alert]] = relationship(back_populates="rule")  # noqa: F821

    __table_args__ = (
        Index("ix_detection_rules_enabled", "enabled"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<DetectionRule {self.rule_key} enabled={self.enabled}>"
