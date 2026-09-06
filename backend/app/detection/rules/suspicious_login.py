"""Successful authentication immediately following repeated failures.

MITRE ATT&CK: T1078 (Valid Accounts), tactic Initial Access.

This is the detection that matters most after a brute-force alert: the failures
are noise until one of them succeeds.
"""

from __future__ import annotations

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


class SuspiciousLoginConfig(RuleConfig):
    preceding_failure_threshold: int = Field(default=5, ge=1, le=1000)
    window_minutes: int = Field(default=15, ge=1, le=1440)


@register
class SuspiciousLoginRule(DetectionRule):
    key = "suspicious_login_after_failures"
    name = "Successful Login After Repeated Failures"
    description = (
        "An account authenticates successfully shortly after a burst of failed "
        "attempts against it, suggesting the credential guessing worked."
    )
    default_severity = Severity.CRITICAL
    default_confidence = 85
    mitre_tactic = "Initial Access"
    mitre_technique_id = "T1078"
    mitre_technique_name = "Valid Accounts"
    config_model = SuspiciousLoginConfig

    def evaluate(self, ctx: DetectionContext) -> list[AlertCandidate]:
        cfg = SuspiciousLoginConfig(**ctx.config)

        successes = [
            e
            for e in ctx.events
            if e.event_type == EventType.AUTHENTICATION.value
            and e.outcome == EventOutcome.SUCCESS.value
            and e.username
        ]
        if not successes:
            return []

        window_start = ctx.window_start(cfg.window_minutes)
        candidates: list[AlertCandidate] = []

        for success in successes:
            failures = (
                ctx.db.execute(
                    select(SecurityEvent)
                    .where(
                        SecurityEvent.username == success.username,
                        SecurityEvent.event_type == EventType.AUTHENTICATION.value,
                        SecurityEvent.outcome == EventOutcome.FAILURE.value,
                        SecurityEvent.timestamp >= window_start,
                        SecurityEvent.timestamp <= success.timestamp,
                    )
                    .order_by(SecurityEvent.timestamp)
                )
                .scalars()
                .all()
            )
            if len(failures) < cfg.preceding_failure_threshold:
                continue

            failure_ips = sorted({f.src_ip for f in failures if f.src_ip})
            # A success from one of the same addresses that was failing is a
            # far stronger signal than a success from somewhere else.
            same_source = success.src_ip in failure_ips
            confidence = 90 if same_source else 70

            candidates.append(
                AlertCandidate(
                    dedup_key=(
                        f"{self.key}|{success.username}|"
                        f"{time_bucket(success.timestamp, cfg.window_minutes)}"
                    ),
                    title=f"Successful login for '{success.username}' after {len(failures)} failures",
                    description=(
                        f"Account '{success.username}' authenticated successfully from "
                        f"{success.src_ip or 'an unknown address'} after {len(failures)} "
                        f"failed attempts in the preceding {cfg.window_minutes} minutes"
                        + (
                            ". The successful login came from an address that was also "
                            "generating failures, which is consistent with a guessed "
                            "credential rather than a user mistyping their password."
                            if same_source
                            else ". The successful login came from a different address "
                            "than the failures, which weakens but does not eliminate the "
                            "hypothesis."
                        )
                    ),
                    severity=Severity.CRITICAL if same_source else Severity.HIGH,
                    confidence=confidence,
                    event_ids=[f.id for f in failures] + [success.id],
                    first_seen=failures[0].timestamp,
                    last_seen=success.timestamp,
                    src_ip=success.src_ip,
                    username=success.username,
                    hostname=success.hostname,
                    evidence={
                        "failure_count": len(failures),
                        "source_addresses": failure_ips[:20],
                        "success_from_failing_source": same_source,
                        "window_minutes": cfg.window_minutes,
                    },
                )
            )
        return candidates
