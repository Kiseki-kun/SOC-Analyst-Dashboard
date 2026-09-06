"""Event ingestion and read schemas.

`RawEventIn` is the wire contract between the generator and the ingest API. It
is deliberately loose about `payload` — that is the whole point of having a
normalization layer: sources disagree about field names, and the backend is
responsible for reconciling them rather than dictating one shape upstream.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.core.enums import EventOutcome, EventSource, EventType, Severity
from app.schemas.common import ORMModel

# A payload larger than this is refused. Without a bound, one request could
# carry an arbitrarily large JSON document straight into the database.
MAX_PAYLOAD_KEYS = 64
MAX_STRING_FIELD = 4096


class RawEventIn(BaseModel):
    """One event as submitted by a collector."""

    event_uid: str = Field(min_length=1, max_length=64)
    source: EventSource
    timestamp: datetime
    payload: dict[str, Any]

    @field_validator("payload")
    @classmethod
    def _bounded_payload(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(value) > MAX_PAYLOAD_KEYS:
            raise ValueError(f"payload may contain at most {MAX_PAYLOAD_KEYS} keys")
        for key, item in value.items():
            if isinstance(item, str) and len(item) > MAX_STRING_FIELD:
                raise ValueError(f"payload field '{key}' exceeds {MAX_STRING_FIELD} characters")
        return value


class EventBatchIn(BaseModel):
    events: list[RawEventIn] = Field(min_length=1, max_length=500)


class IngestResult(BaseModel):
    received: int
    stored: int
    duplicates: int
    rejected: int
    alerts_created: int
    alerts_updated: int


class EventRead(ORMModel):
    id: uuid.UUID
    event_uid: str
    timestamp: datetime
    ingested_at: datetime
    source: str
    event_type: str
    action: str
    outcome: str
    severity: str
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: str | None
    username: str | None
    hostname: str | None
    country_code: str | None
    city: str | None
    process_name: str | None
    file_hash: str | None
    http_method: str | None
    url_path: str | None
    http_status: int | None
    dns_query: str | None
    message: str


class EventDetail(EventRead):
    """Adds the fields only needed on the detail page."""

    command_line: str | None
    file_path: str | None
    user_agent: str | None
    bytes_sent: int | None
    bytes_received: int | None
    latitude: float | None
    longitude: float | None
    raw: dict[str, Any]
    analyzed: bool


class NormalizedEvent(BaseModel):
    """The common schema every source is mapped into.

    This is the contract detection rules are written against. Adding a log
    source means writing a normalizer; it must never mean editing a rule.
    """

    event_uid: str
    timestamp: datetime
    source: str
    event_type: EventType
    action: str
    outcome: EventOutcome = EventOutcome.UNKNOWN
    severity: Severity = Severity.INFO
    message: str = ""

    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    bytes_sent: int | None = None
    bytes_received: int | None = None

    username: str | None = None
    hostname: str | None = None

    country_code: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None

    process_name: str | None = None
    command_line: str | None = None
    file_path: str | None = None
    file_hash: str | None = None

    http_method: str | None = None
    url_path: str | None = None
    http_status: int | None = None
    user_agent: str | None = None
    dns_query: str | None = None

    raw: dict[str, Any] = Field(default_factory=dict)
