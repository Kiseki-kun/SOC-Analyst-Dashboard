"""IP investigation: pivot on an address across events, alerts and incidents."""

from __future__ import annotations

import ipaddress

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.core.enums import EventOutcome, EventType, IOCType
from app.models.alert import Alert
from app.models.audit import IOCWatchlistEntry
from app.models.event import SecurityEvent
from app.models.incident import Incident


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def investigate_ip(db: Session, ip_address: str, *, event_limit: int = 50) -> dict:
    involving_ip = or_(SecurityEvent.src_ip == ip_address, SecurityEvent.dst_ip == ip_address)

    totals = db.execute(
        select(
            func.count().label("total"),
            func.min(SecurityEvent.timestamp).label("first_seen"),
            func.max(SecurityEvent.timestamp).label("last_seen"),
        ).where(involving_ip)
    ).one()

    auth_counts = db.execute(
        select(SecurityEvent.outcome, func.count())
        .where(involving_ip, SecurityEvent.event_type == EventType.AUTHENTICATION.value)
        .group_by(SecurityEvent.outcome)
    ).all()
    auth_map = {row[0]: row[1] for row in auth_counts}

    connections = db.execute(
        select(func.count())
        .select_from(SecurityEvent)
        .where(involving_ip, SecurityEvent.event_type == EventType.NETWORK_CONNECTION.value)
    ).scalar_one()

    distinct_ports = db.execute(
        select(func.count(func.distinct(SecurityEvent.dst_port)))
        .where(SecurityEvent.src_ip == ip_address, SecurityEvent.dst_port.is_not(None))
    ).scalar_one()
    distinct_hosts = db.execute(
        select(func.count(func.distinct(SecurityEvent.dst_ip)))
        .where(SecurityEvent.src_ip == ip_address, SecurityEvent.dst_ip.is_not(None))
    ).scalar_one()

    usernames = [
        row[0]
        for row in db.execute(
            select(SecurityEvent.username)
            .where(involving_ip, SecurityEvent.username.is_not(None))
            .group_by(SecurityEvent.username)
            .order_by(func.count().desc())
            .limit(25)
        ).all()
    ]
    hostnames = [
        row[0]
        for row in db.execute(
            select(SecurityEvent.hostname)
            .where(involving_ip, SecurityEvent.hostname.is_not(None))
            .group_by(SecurityEvent.hostname)
            .order_by(func.count().desc())
            .limit(25)
        ).all()
    ]
    top_ports = [
        row[0]
        for row in db.execute(
            select(SecurityEvent.dst_port)
            .where(SecurityEvent.src_ip == ip_address, SecurityEvent.dst_port.is_not(None))
            .group_by(SecurityEvent.dst_port)
            .order_by(func.count().desc())
            .limit(15)
        ).all()
    ]

    related_alerts = list(
        db.execute(
            select(Alert)
            .options(selectinload(Alert.assigned_to))
            .where(or_(Alert.src_ip == ip_address, Alert.dst_ip == ip_address))
            .order_by(Alert.created_at.desc())
            .limit(50)
        )
        .scalars()
        .all()
    )

    incident_uids = [
        row[0]
        for row in db.execute(
            select(Incident.incident_uid)
            .join(Alert, Alert.incident_id == Incident.id)
            .where(or_(Alert.src_ip == ip_address, Alert.dst_ip == ip_address))
            .group_by(Incident.incident_uid)
        ).all()
    ]

    recent_events = list(
        db.execute(
            select(SecurityEvent)
            .where(involving_ip)
            .order_by(SecurityEvent.timestamp.desc())
            .limit(event_limit)
        )
        .scalars()
        .all()
    )

    on_watchlist = (
        db.execute(
            select(IOCWatchlistEntry.id).where(
                IOCWatchlistEntry.ioc_type == IOCType.IP_ADDRESS.value,
                IOCWatchlistEntry.value == ip_address,
                IOCWatchlistEntry.active.is_(True),
            )
        ).scalar_one_or_none()
        is not None
    )

    failed = auth_map.get(EventOutcome.FAILURE.value, 0)
    succeeded = auth_map.get(EventOutcome.SUCCESS.value, 0)

    reputation = _score_reputation(
        on_watchlist=on_watchlist,
        alerts=related_alerts,
        failed_authentications=failed,
        distinct_ports=distinct_ports,
        distinct_hosts=distinct_hosts,
    )

    return {
        "ip_address": ip_address,
        "summary": {
            "total_events": totals.total,
            "connection_count": connections,
            "authentication_attempts": sum(auth_map.values()),
            "failed_authentications": failed,
            "successful_authentications": succeeded,
            "distinct_destination_ports": distinct_ports,
            "distinct_destination_hosts": distinct_hosts,
            "first_seen": totals.first_seen,
            "last_seen": totals.last_seen,
        },
        "reputation": reputation,
        "associated_usernames": usernames,
        "associated_hostnames": hostnames,
        "top_destination_ports": top_ports,
        "related_alerts": related_alerts,
        "related_incident_uids": incident_uids,
        "recent_events": recent_events,
    }


def _score_reputation(
    *, on_watchlist: bool, alerts: list[Alert], failed_authentications: int,
    distinct_ports: int, distinct_hosts: int,
) -> dict:
    """Score an address from local observations only.

    Every contribution is recorded in `basis` so an analyst can see precisely
    why a verdict was reached and disagree with it. An opaque score would be
    worse than none: it cannot be argued with or corrected.
    """
    score = 0
    basis: list[str] = []

    if on_watchlist:
        score += 60
        basis.append("Address is on the local IOC watchlist")

    critical = sum(1 for a in alerts if a.severity == "critical")
    high = sum(1 for a in alerts if a.severity == "high")
    if critical:
        score += min(40, critical * 20)
        basis.append(f"{critical} critical alert(s) reference this address")
    if high:
        score += min(25, high * 10)
        basis.append(f"{high} high-severity alert(s) reference this address")
    other = len(alerts) - critical - high
    if other:
        score += min(10, other * 2)
        basis.append(f"{other} lower-severity alert(s) reference this address")

    if failed_authentications >= 20:
        score += 15
        basis.append(f"{failed_authentications} failed authentication attempts observed")
    elif failed_authentications >= 5:
        score += 8
        basis.append(f"{failed_authentications} failed authentication attempts observed")

    if distinct_ports >= 15:
        score += 15
        basis.append(f"Contacted {distinct_ports} distinct destination ports")
    if distinct_hosts >= 10:
        score += 10
        basis.append(f"Contacted {distinct_hosts} distinct destination hosts")

    score = min(100, score)
    if score >= 60:
        verdict = "malicious"
    elif score >= 25:
        verdict = "suspicious"
    else:
        verdict = "benign"

    if not basis:
        basis.append("No alerts, scanning behaviour or watchlist entries observed locally")

    return {
        "verdict": verdict,
        "score": score,
        "basis": basis,
        "on_watchlist": on_watchlist,
        "source": "local_synthetic_data_only",
    }
