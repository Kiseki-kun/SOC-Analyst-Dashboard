"""Analytics response schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class DashboardSummary(BaseModel):
    generated_at: datetime
    total_events: int
    events_last_hour: int
    events_last_24h: int
    open_alerts: int
    critical_high_open_alerts: int
    unassigned_open_alerts: int
    open_incidents: int
    auth_failures_last_24h: int
    alerts_by_severity: dict[str, int]
    alerts_by_status: dict[str, int]
    incidents_by_severity: dict[str, int]
    incidents_by_status: dict[str, int]


class TimeSeriesPoint(BaseModel):
    bucket: datetime
    count: int


class AuthTrendPoint(BaseModel):
    bucket: datetime
    success: int
    failure: int


class TopIP(BaseModel):
    ip: str
    event_count: int
    failure_count: int | None = None


class TopRule(BaseModel):
    rule_key: str
    alert_count: int


class MitreEntry(BaseModel):
    technique_id: str
    technique_name: str | None
    tactic: str | None
    alert_count: int


class TacticEntry(BaseModel):
    tactic: str
    alert_count: int


class EventTypeEntry(BaseModel):
    event_type: str
    count: int


class ResponseMetrics(BaseModel):
    window_days: int
    # Null when no incident has reached that stage yet. Reporting 0 would be a
    # fabricated statistic.
    mean_time_to_acknowledge_minutes: float | None
    mean_time_to_contain_minutes: float | None
    mean_time_to_resolve_minutes: float | None
    incidents_acknowledged: int
    incidents_resolved: int


class AnalyticsOverview(BaseModel):
    summary: DashboardSummary
    events_over_time: list[TimeSeriesPoint]
    alerts_over_time: list[TimeSeriesPoint]
    authentication_trend: list[AuthTrendPoint]
    top_source_ips: list[TopIP]
    top_destination_ips: list[TopIP]
    top_detection_rules: list[TopRule]
    mitre_distribution: list[MitreEntry]
    attack_categories: list[TacticEntry]
    event_type_distribution: list[EventTypeEntry]
    response_metrics: ResponseMetrics
