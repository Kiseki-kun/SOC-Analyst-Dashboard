"""IP investigation schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

from app.schemas.alert import AlertRead
from app.schemas.event import EventRead


class IPActivitySummary(BaseModel):
    total_events: int
    connection_count: int
    authentication_attempts: int
    failed_authentications: int
    successful_authentications: int
    distinct_destination_ports: int
    distinct_destination_hosts: int
    first_seen: datetime | None
    last_seen: datetime | None


class IPReputation(BaseModel):
    """Reputation derived ONLY from this project's own synthetic data.

    No external threat-intelligence service is queried, and none of these
    scores mean anything outside this application. The `basis` field spells
    out exactly which local observations produced the verdict.
    """

    verdict: str            # benign | suspicious | malicious
    score: int              # 0-100, higher is worse
    basis: list[str]
    on_watchlist: bool
    source: str = "local_synthetic_data_only"


class IPInvestigation(BaseModel):
    ip_address: str
    summary: IPActivitySummary
    reputation: IPReputation
    associated_usernames: list[str]
    associated_hostnames: list[str]
    top_destination_ports: list[int]
    related_alerts: list[AlertRead]
    related_incident_uids: list[str]
    recent_events: list[EventRead]
