"""Port scanning detection.

MITRE ATT&CK: T1046 (Network Service Discovery), tactic Discovery.
"""

from __future__ import annotations

from collections import defaultdict

from pydantic import Field
from sqlalchemy import select

from app.core.enums import EventType, Severity
from app.detection.base import (
    AlertCandidate,
    DetectionContext,
    DetectionRule,
    RuleConfig,
    time_bucket,
)
from app.detection.registry import register
from app.models.event import SecurityEvent


class PortScanConfig(RuleConfig):
    # Distinct destination ports touched by one source.
    distinct_port_threshold: int = Field(default=15, ge=3, le=1000)
    # Distinct destination hosts, which catches a horizontal sweep of one port.
    distinct_host_threshold: int = Field(default=10, ge=2, le=1000)
    window_minutes: int = Field(default=5, ge=1, le=1440)


@register
class PortScanRule(DetectionRule):
    key = "port_scan"
    name = "Port Scan / Network Service Discovery"
    description = (
        "One source contacts an unusual number of distinct destination ports "
        "or hosts in a short window, consistent with network reconnaissance."
    )
    default_severity = Severity.MEDIUM
    default_confidence = 75
    mitre_tactic = "Discovery"
    mitre_technique_id = "T1046"
    mitre_technique_name = "Network Service Discovery"
    config_model = PortScanConfig

    def evaluate(self, ctx: DetectionContext) -> list[AlertCandidate]:
        cfg = PortScanConfig(**ctx.config)

        candidate_ips = {
            e.src_ip
            for e in ctx.events
            if e.src_ip and e.event_type == EventType.NETWORK_CONNECTION.value
        }
        if not candidate_ips:
            return []

        rows = (
            ctx.db.execute(
                select(
                    SecurityEvent.src_ip,
                    SecurityEvent.dst_ip,
                    SecurityEvent.dst_port,
                    SecurityEvent.id,
                    SecurityEvent.timestamp,
                )
                .where(
                    SecurityEvent.src_ip.in_(candidate_ips),
                    SecurityEvent.event_type == EventType.NETWORK_CONNECTION.value,
                    SecurityEvent.timestamp >= ctx.window_start(cfg.window_minutes),
                )
                .order_by(SecurityEvent.timestamp)
            )
            .all()
        )

        grouped: dict[str, list] = defaultdict(list)
        for row in rows:
            grouped[row.src_ip].append(row)

        candidates: list[AlertCandidate] = []
        for src_ip, entries in grouped.items():
            ports = {e.dst_port for e in entries if e.dst_port is not None}
            hosts = {e.dst_ip for e in entries if e.dst_ip}

            vertical = len(ports) >= cfg.distinct_port_threshold
            horizontal = len(hosts) >= cfg.distinct_host_threshold
            if not (vertical or horizontal):
                continue

            if vertical and horizontal:
                shape = "a broad sweep across both hosts and ports"
                severity, confidence = Severity.HIGH, 85
            elif vertical:
                shape = f"a vertical scan of {len(ports)} ports"
                severity, confidence = Severity.MEDIUM, 75
            else:
                shape = f"a horizontal scan across {len(hosts)} hosts"
                severity, confidence = Severity.MEDIUM, 75

            candidates.append(
                AlertCandidate(
                    dedup_key=(
                        f"{self.key}|{src_ip}|"
                        f"{time_bucket(entries[-1].timestamp, cfg.window_minutes)}"
                    ),
                    title=f"Port scan from {src_ip}",
                    description=(
                        f"{src_ip} contacted {len(ports)} distinct ports across "
                        f"{len(hosts)} hosts in {cfg.window_minutes} minutes — "
                        f"{shape}."
                    ),
                    severity=severity,
                    confidence=confidence,
                    event_ids=[e.id for e in entries],
                    first_seen=entries[0].timestamp,
                    last_seen=entries[-1].timestamp,
                    src_ip=src_ip,
                    dst_ip=next(iter(hosts)) if len(hosts) == 1 else None,
                    evidence={
                        "distinct_ports": len(ports),
                        "distinct_hosts": len(hosts),
                        "connection_count": len(entries),
                        "ports_sample": sorted(p for p in ports)[:40],
                        "window_minutes": cfg.window_minutes,
                    },
                )
            )
        return candidates
