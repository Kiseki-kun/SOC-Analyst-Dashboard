"""Security events.

This is the normalized schema every raw source is transformed into. Detection
rules read these columns and never the original payload, which is what lets a
new log source be supported by writing a parser rather than touching detections.

The original document is preserved verbatim in `raw` so an analyst can always
see what actually arrived.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    Float,
    Index,
    Integer,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import EventOutcome, Severity
from app.db.base import Base, JSONVariant, UTCDateTime, utcnow


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Identifier supplied by the source. Unique so a retried ingest batch cannot
    # duplicate events and inflate a brute-force count into a false positive.
    event_uid: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    # When the activity happened, per the source.
    timestamp: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, index=True
    )
    # When this system received it. The gap between the two is itself a signal.
    ingested_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, default=utcnow
    )

    source: Mapped[str] = mapped_column(String(32), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(
        String(16), nullable=False, default=EventOutcome.UNKNOWN.value
    )
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default=Severity.INFO.value
    )

    # --- network -----------------------------------------------------------
    # String(45) rather than INET: 45 chars holds any IPv6 form, and keeping the
    # column portable is what lets the detection tests run without PostgreSQL.
    src_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    bytes_sent: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    bytes_received: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    # --- identity ----------------------------------------------------------
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # --- geo (synthetic; drives the impossible-travel detection) ------------
    country_code: Mapped[str | None] = mapped_column(String(2), nullable=True)
    city: Mapped[str | None] = mapped_column(String(64), nullable=True)
    latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    longitude: Mapped[float | None] = mapped_column(Float, nullable=True)

    # --- endpoint / process -------------------------------------------------
    process_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    command_line: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # --- web ----------------------------------------------------------------
    http_method: Mapped[str | None] = mapped_column(String(10), nullable=True)
    url_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    dns_query: Mapped[str | None] = mapped_column(String(255), nullable=True)

    message: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # Verbatim source document.
    raw: Mapped[dict[str, Any]] = mapped_column(JSONVariant, nullable=False, default=dict)

    # Set once the detection engine has evaluated this event, so a restart does
    # not re-run rules over history and duplicate alerts.
    analyzed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    __table_args__ = (
        # Every index below backs a query the application actually issues.
        # The detection engine's windowed lookups are the hot path: each rule
        # asks "events for this <key> in the last N minutes", so a composite
        # (key, timestamp) index serves both the filter and the range scan.
        Index("ix_events_src_ip_timestamp", "src_ip", "timestamp"),
        Index("ix_events_username_timestamp", "username", "timestamp"),
        Index("ix_events_type_timestamp", "event_type", "timestamp"),
        # Event explorer default view: newest first, filtered by severity.
        Index("ix_events_severity_timestamp", "severity", "timestamp"),
        # Detection sweep: pending events, oldest first.
        Index("ix_events_analyzed_timestamp", "analyzed", "timestamp"),
        # IP investigation pivots on destination too.
        Index("ix_events_dst_ip_timestamp", "dst_ip", "timestamp"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<SecurityEvent {self.event_uid} {self.event_type}"
            f" {self.outcome} src={self.src_ip}>"
        )
