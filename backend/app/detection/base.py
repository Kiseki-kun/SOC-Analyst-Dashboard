"""Detection rule framework.

A rule is a class with declared metadata, a validated config schema, and one
`evaluate` method. That structure exists so the engine can do the repetitive
work — loading config, deduplicating, building alerts, mapping MITRE — leaving
each rule to express only its detection logic.

The alternative, one growing `if/elif` over event types, is what this design is
specifically avoiding: it makes rules untestable in isolation, impossible to
enable or tune individually, and guarantees a merge conflict every time two
people add a detection.
"""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, ClassVar

from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.enums import Severity
from app.db.base import as_utc
from app.models.event import SecurityEvent


@dataclass(slots=True)
class AlertCandidate:
    """What a rule returns when it believes something happened.

    A candidate is not yet an alert: the engine deduplicates it against
    existing open alerts before deciding whether to create or extend one.
    """

    dedup_key: str
    title: str
    description: str
    severity: Severity
    confidence: int
    event_ids: list[Any]
    first_seen: datetime
    last_seen: datetime
    src_ip: str | None = None
    dst_ip: str | None = None
    username: str | None = None
    hostname: str | None = None
    # Rule-specific evidence surfaced to the analyst, e.g. the ports scanned.
    evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.confidence = max(0, min(100, int(self.confidence)))


@dataclass(slots=True)
class DetectionContext:
    """Everything a rule is allowed to see.

    Rules receive a database session because most detections are inherently
    stateful — "five failures in five minutes" cannot be answered from a single
    event. They are expected to query narrowly, using the composite
    (entity, timestamp) indexes on security_events.
    """

    db: Session
    events: list[SecurityEvent]
    config: dict[str, Any]
    now: datetime

    def window_start(self, minutes: int) -> datetime:
        return self.now - timedelta(minutes=minutes)


class RuleConfig(BaseModel):
    """Base for per-rule configuration schemas."""

    model_config = {"extra": "forbid"}


class DetectionRule(ABC):
    """Base class for all detection rules."""

    key: ClassVar[str]
    name: ClassVar[str]
    description: ClassVar[str]
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    default_confidence: ClassVar[int] = 60

    # MITRE ATT&CK. These are real published identifiers; see
    # docs/detection-rules.md for the mapping table and links.
    mitre_tactic: ClassVar[str | None] = None
    mitre_technique_id: ClassVar[str | None] = None
    mitre_technique_name: ClassVar[str | None] = None

    config_model: ClassVar[type[RuleConfig]]

    @classmethod
    def default_config(cls) -> dict[str, Any]:
        return cls.config_model().model_dump()

    @classmethod
    def parse_config(cls, raw: dict[str, Any] | None) -> RuleConfig:
        """Validate stored config, falling back to defaults if it is invalid.

        An administrator can edit thresholds through the API. A bad value must
        degrade to the default rather than crash the ingest pipeline — a
        detection engine that stops on malformed config is a denial-of-service
        against the whole platform.
        """
        try:
            return cls.config_model(**(raw or {}))
        except Exception:
            return cls.config_model()

    @abstractmethod
    def evaluate(self, ctx: DetectionContext) -> list[AlertCandidate]:
        """Inspect the batch and return any alert candidates."""
        raise NotImplementedError


# ----------------------------------------------------------------- utilities
def time_bucket(moment: datetime, minutes: int) -> int:
    """Floor a timestamp to a bucket index.

    Used in dedup keys so a sustained attack collapses into one alert per
    window instead of one per evaluation pass.

    The timestamp is coerced to timezone.utc first: `datetime.timestamp()` on a naive
    value interprets it in the local timezone, which would silently shift every
    bucket boundary if the container ran outside timezone.utc.
    """
    return int(as_utc(moment).timestamp() // (minutes * 60))


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometres."""
    radius = 6371.0
    d_lat = math.radians(lat2 - lat1)
    d_lon = math.radians(lon2 - lon1)
    a = (
        math.sin(d_lat / 2) ** 2
        + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(d_lon / 2) ** 2
    )
    return 2 * radius * math.asin(math.sqrt(a))
