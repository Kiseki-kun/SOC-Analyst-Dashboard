"""Brute-force authentication detection.

MITRE ATT&CK: T1110 (Brute Force), tactic Credential Access.
"""

from __future__ import annotations

from collections import defaultdict

from pydantic import Field
from sqlalchemy import select

from app.core.enums import EventOutcome, EventType, Severity
from app.detection.base import (
    AlertCandidate,
    DetectionContext,
    DetectionRule,
    RuleConfig,
    time_bucket,
)
from app.detection.registry import register
from app.models.event import SecurityEvent


class BruteForceConfig(RuleConfig):
    threshold: int = Field(default=8, ge=2, le=1000)
    window_minutes: int = Field(default=5, ge=1, le=1440)
    # Distinct usernames tried from one source. A single source failing against
    # many accounts is password spraying, which is worth flagging harder.
    spray_account_threshold: int = Field(default=5, ge=2, le=100)


@register
class BruteForceRule(DetectionRule):
    key = "brute_force_authentication"
    name = "Brute Force Authentication"
    description = (
        "A single source address accumulates an unusual number of failed "
        "authentication attempts inside a short window."
    )
    default_severity = Severity.HIGH
    default_confidence = 80
    mitre_tactic = "Credential Access"
    mitre_technique_id = "T1110"
    mitre_technique_name = "Brute Force"
    config_model = BruteForceConfig

    def evaluate(self, ctx: DetectionContext) -> list[AlertCandidate]:
        cfg = BruteForceConfig(**ctx.config)

        # Only source addresses that appear in this batch are worth examining;
        # re-scanning every historical IP on every batch would not scale.
        candidate_ips = {
            e.src_ip
            for e in ctx.events
            if e.src_ip
            and e.event_type == EventType.AUTHENTICATION.value
            and e.outcome == EventOutcome.FAILURE.value
        }
        if not candidate_ips:
            return []

        window_start = ctx.window_start(cfg.window_minutes)
        rows = (
            ctx.db.execute(
                select(
                    SecurityEvent.src_ip,
                    SecurityEvent.id,
                    SecurityEvent.username,
                    SecurityEvent.hostname,
                    SecurityEvent.timestamp,
                )
                .where(
                    SecurityEvent.src_ip.in_(candidate_ips),
                    SecurityEvent.event_type == EventType.AUTHENTICATION.value,
                    SecurityEvent.outcome == EventOutcome.FAILURE.value,
                    SecurityEvent.timestamp >= window_start,
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
            if len(entries) < cfg.threshold:
                continue

            usernames = sorted({e.username for e in entries if e.username})
            hostnames = sorted({e.hostname for e in entries if e.hostname})
            spraying = len(usernames) >= cfg.spray_account_threshold

            severity = Severity.CRITICAL if spraying else Severity.HIGH
            confidence = 90 if spraying else 80

            if spraying:
                title = f"Password spraying from {src_ip} against {len(usernames)} accounts"
                description = (
                    f"{len(entries)} failed authentication attempts from {src_ip} "
                    f"in {cfg.window_minutes} minutes, spread across {len(usernames)} "
                    f"distinct accounts. Breadth across accounts rather than depth "
                    f"against one is characteristic of password spraying."
                )
            else:
                title = f"Brute force authentication from {src_ip}"
                description = (
                    f"{len(entries)} failed authentication attempts from {src_ip} "
                    f"in {cfg.window_minutes} minutes, exceeding the threshold of "
                    f"{cfg.threshold}. Targeted accounts: {', '.join(usernames[:5]) or 'unknown'}."
                )

            candidates.append(
                AlertCandidate(
                    dedup_key=(
                        f"{self.key}|{src_ip}|"
                        f"{time_bucket(entries[-1].timestamp, cfg.window_minutes)}"
                    ),
                    title=title,
                    description=description,
                    severity=severity,
                    confidence=confidence,
                    event_ids=[e.id for e in entries],
                    first_seen=entries[0].timestamp,
                    last_seen=entries[-1].timestamp,
                    src_ip=src_ip,
                    username=usernames[0] if len(usernames) == 1 else None,
                    hostname=hostnames[0] if len(hostnames) == 1 else None,
                    evidence={
                        "failure_count": len(entries),
                        "distinct_accounts": len(usernames),
                        "accounts": usernames[:20],
                        "window_minutes": cfg.window_minutes,
                        "threshold": cfg.threshold,
                        "password_spray": spraying,
                    },
                )
            )
        return candidates
