"""Analytics.

Every figure returned here is computed from rows in this database. Nothing is
invented, estimated or hard-coded: a dashboard that shows plausible-looking
numbers unconnected to the data is worse than an empty one, because it cannot
be caught being wrong.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import Float, case, cast, func, select
from sqlalchemy.orm import Session

from app.core.enums import (
    ALERT_TERMINAL_STATUSES,
    INCIDENT_TERMINAL_STATUSES,
    EventOutcome,
    EventType,
)
from app.db.base import utcnow
from app.models.alert import Alert
from app.models.event import SecurityEvent
from app.models.incident import Incident


def _epoch_bucket(db: Session, column, seconds: int):
    """Truncate a timestamp column to a bucket, on either supported dialect.

    PostgreSQL and SQLite have no common date-truncation function, so the
    expression is chosen per dialect. Doing this in SQL rather than pulling
    every row into Python is what keeps the dashboard responsive once the
    event table is large.
    """
    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        epoch = func.extract("epoch", column)
    else:
        epoch = cast(func.strftime("%s", column), Float)
    return cast(func.floor(epoch / seconds) * seconds, Float)


@dataclass(slots=True)
class TimePoint:
    bucket: datetime
    count: int


def _series(db: Session, model, timestamp_column, *, since: datetime,
            bucket_seconds: int, extra_filters=()) -> list[TimePoint]:
    bucket = _epoch_bucket(db, timestamp_column, bucket_seconds)
    stmt = (
        select(bucket.label("bucket"), func.count().label("count"))
        .where(timestamp_column >= since)
        .group_by("bucket")
        .order_by("bucket")
    )
    for condition in extra_filters:
        stmt = stmt.where(condition)


    return [
        TimePoint(
            bucket=datetime.fromtimestamp(float(row.bucket), tz=timezone.utc),
            count=row.count,
        )
        for row in db.execute(stmt).all()
        if row.bucket is not None
    ]


def dashboard_summary(db: Session) -> dict:
    now = utcnow()
    hour_ago = now - timedelta(hours=1)
    day_ago = now - timedelta(days=1)

    total_events = db.execute(select(func.count()).select_from(SecurityEvent)).scalar_one()
    events_last_hour = db.execute(
        select(func.count()).select_from(SecurityEvent).where(SecurityEvent.timestamp >= hour_ago)
    ).scalar_one()
    events_last_day = db.execute(
        select(func.count()).select_from(SecurityEvent).where(SecurityEvent.timestamp >= day_ago)
    ).scalar_one()

    open_alert_filter = Alert.status.notin_(tuple(ALERT_TERMINAL_STATUSES))
    open_alerts = db.execute(
        select(func.count()).select_from(Alert).where(open_alert_filter)
    ).scalar_one()
    critical_high_open = db.execute(
        select(func.count()).select_from(Alert).where(
            open_alert_filter, Alert.severity.in_(("critical", "high"))
        )
    ).scalar_one()
    unassigned_open = db.execute(
        select(func.count()).select_from(Alert).where(
            open_alert_filter, Alert.assigned_to_id.is_(None)
        )
    ).scalar_one()

    open_incident_filter = Incident.status.notin_(tuple(INCIDENT_TERMINAL_STATUSES))
    open_incidents = db.execute(
        select(func.count()).select_from(Incident).where(open_incident_filter)
    ).scalar_one()

    auth_failures_day = db.execute(
        select(func.count()).select_from(SecurityEvent).where(
            SecurityEvent.timestamp >= day_ago,
            SecurityEvent.event_type == EventType.AUTHENTICATION.value,
            SecurityEvent.outcome == EventOutcome.FAILURE.value,
        )
    ).scalar_one()

    return {
        "generated_at": now,
        "total_events": total_events,
        "events_last_hour": events_last_hour,
        "events_last_24h": events_last_day,
        "open_alerts": open_alerts,
        "critical_high_open_alerts": critical_high_open,
        "unassigned_open_alerts": unassigned_open,
        "open_incidents": open_incidents,
        "auth_failures_last_24h": auth_failures_day,
        "alerts_by_severity": _count_by(db, Alert.severity, open_alert_filter),
        "alerts_by_status": _count_by(db, Alert.status),
        "incidents_by_severity": _count_by(db, Incident.severity, open_incident_filter),
        "incidents_by_status": _count_by(db, Incident.status),
    }


def _count_by(db: Session, column, *filters) -> dict[str, int]:
    stmt = select(column, func.count()).group_by(column)
    for condition in filters:
        stmt = stmt.where(condition)
    return {row[0]: row[1] for row in db.execute(stmt).all() if row[0] is not None}


def events_over_time(db: Session, *, hours: int = 24, buckets: int = 48) -> list[dict]:
    since = utcnow() - timedelta(hours=hours)
    seconds = max(60, (hours * 3600) // max(1, buckets))
    return [
        {"bucket": p.bucket, "count": p.count}
        for p in _series(db, SecurityEvent, SecurityEvent.timestamp,
                         since=since, bucket_seconds=seconds)
    ]


def alerts_over_time(db: Session, *, hours: int = 24, buckets: int = 48) -> list[dict]:
    since = utcnow() - timedelta(hours=hours)
    seconds = max(60, (hours * 3600) // max(1, buckets))
    return [
        {"bucket": p.bucket, "count": p.count}
        for p in _series(db, Alert, Alert.created_at, since=since, bucket_seconds=seconds)
    ]


def authentication_trend(db: Session, *, hours: int = 24, buckets: int = 24) -> list[dict]:
    """Success vs failure over time - the shape that reveals credential attacks."""
    since = utcnow() - timedelta(hours=hours)
    seconds = max(60, (hours * 3600) // max(1, buckets))
    bucket = _epoch_bucket(db, SecurityEvent.timestamp, seconds)

    rows = db.execute(
        select(
            bucket.label("bucket"),
            func.sum(case((SecurityEvent.outcome == EventOutcome.SUCCESS.value, 1), else_=0)).label("success"),
            func.sum(case((SecurityEvent.outcome == EventOutcome.FAILURE.value, 1), else_=0)).label("failure"),
        )
        .where(
            SecurityEvent.timestamp >= since,
            SecurityEvent.event_type == EventType.AUTHENTICATION.value,
        )
        .group_by("bucket")
        .order_by("bucket")
    ).all()


    return [
        {
            "bucket": datetime.fromtimestamp(float(r.bucket), tz=timezone.utc),
            "success": int(r.success or 0),
            "failure": int(r.failure or 0),
        }
        for r in rows
        if r.bucket is not None
    ]


def top_source_ips(db: Session, *, hours: int = 24, limit: int = 10) -> list[dict]:
    since = utcnow() - timedelta(hours=hours)
    rows = db.execute(
        select(
            SecurityEvent.src_ip,
            func.count().label("event_count"),
            func.sum(
                case((SecurityEvent.outcome == EventOutcome.FAILURE.value, 1), else_=0)
            ).label("failures"),
        )
        .where(SecurityEvent.timestamp >= since, SecurityEvent.src_ip.is_not(None))
        .group_by(SecurityEvent.src_ip)
        .order_by(func.count().desc())
        .limit(limit)
    ).all()
    return [
        {"ip": r.src_ip, "event_count": r.event_count, "failure_count": int(r.failures or 0)}
        for r in rows
    ]


def top_destination_ips(db: Session, *, hours: int = 24, limit: int = 10) -> list[dict]:
    since = utcnow() - timedelta(hours=hours)
    rows = db.execute(
        select(SecurityEvent.dst_ip, func.count().label("event_count"))
        .where(SecurityEvent.timestamp >= since, SecurityEvent.dst_ip.is_not(None))
        .group_by(SecurityEvent.dst_ip)
        .order_by(func.count().desc())
        .limit(limit)
    ).all()
    return [{"ip": r.dst_ip, "event_count": r.event_count} for r in rows]


def top_detection_rules(db: Session, *, days: int = 7, limit: int = 10) -> list[dict]:
    since = utcnow() - timedelta(days=days)
    rows = db.execute(
        select(Alert.rule_key, func.count().label("alert_count"))
        .where(Alert.created_at >= since)
        .group_by(Alert.rule_key)
        .order_by(func.count().desc())
        .limit(limit)
    ).all()
    return [{"rule_key": r.rule_key, "alert_count": r.alert_count} for r in rows]


def mitre_distribution(db: Session, *, days: int = 7) -> list[dict]:
    since = utcnow() - timedelta(days=days)
    rows = db.execute(
        select(
            Alert.mitre_technique_id,
            Alert.mitre_technique_name,
            Alert.mitre_tactic,
            func.count().label("alert_count"),
        )
        .where(Alert.created_at >= since, Alert.mitre_technique_id.is_not(None))
        .group_by(Alert.mitre_technique_id, Alert.mitre_technique_name, Alert.mitre_tactic)
        .order_by(func.count().desc())
    ).all()
    return [
        {
            "technique_id": r.mitre_technique_id,
            "technique_name": r.mitre_technique_name,
            "tactic": r.mitre_tactic,
            "alert_count": r.alert_count,
        }
        for r in rows
    ]


def attack_categories(db: Session, *, days: int = 7) -> list[dict]:
    """Alert volume grouped by ATT&CK tactic - the 'what stage' view."""
    since = utcnow() - timedelta(days=days)
    rows = db.execute(
        select(Alert.mitre_tactic, func.count().label("alert_count"))
        .where(Alert.created_at >= since)
        .group_by(Alert.mitre_tactic)
        .order_by(func.count().desc())
    ).all()
    return [
        {"tactic": r.mitre_tactic or "Uncategorised", "alert_count": r.alert_count}
        for r in rows
    ]


def response_metrics(db: Session, *, days: int = 30) -> dict:
    """Mean time to acknowledge and to resolve, computed from real timestamps.

    Returns None for a metric with no qualifying incidents rather than 0 — an
    average of nothing is not zero, and showing "0 minutes MTTR" on an empty
    system is exactly the kind of fake statistic to avoid.
    """
    since = utcnow() - timedelta(days=days)

    acknowledged = db.execute(
        select(Incident.created_at, Incident.acknowledged_at).where(
            Incident.created_at >= since, Incident.acknowledged_at.is_not(None)
        )
    ).all()
    resolved = db.execute(
        select(Incident.created_at, Incident.resolved_at).where(
            Incident.created_at >= since, Incident.resolved_at.is_not(None)
        )
    ).all()
    contained = db.execute(
        select(Incident.created_at, Incident.contained_at).where(
            Incident.created_at >= since, Incident.contained_at.is_not(None)
        )
    ).all()

    def mean_minutes(pairs) -> float | None:
        deltas = [
            (later - earlier).total_seconds() / 60.0
            for earlier, later in pairs
            if earlier and later and later >= earlier
        ]
        return round(sum(deltas) / len(deltas), 1) if deltas else None

    return {
        "window_days": days,
        "mean_time_to_acknowledge_minutes": mean_minutes(acknowledged),
        "mean_time_to_contain_minutes": mean_minutes(contained),
        "mean_time_to_resolve_minutes": mean_minutes(resolved),
        "incidents_acknowledged": len(acknowledged),
        "incidents_resolved": len(resolved),
    }


def event_type_distribution(db: Session, *, hours: int = 24) -> list[dict]:
    since = utcnow() - timedelta(hours=hours)
    rows = db.execute(
        select(SecurityEvent.event_type, func.count().label("count"))
        .where(SecurityEvent.timestamp >= since)
        .group_by(SecurityEvent.event_type)
        .order_by(func.count().desc())
    ).all()
    return [{"event_type": r.event_type, "count": r.count} for r in rows]
