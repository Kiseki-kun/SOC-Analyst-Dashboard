"""Suspicious privilege changes.

MITRE ATT&CK: T1548 (Abuse Elevation Control Mechanism), tactic Privilege
Escalation.
"""

from __future__ import annotations

import re

from pydantic import Field

from app.core.enums import EventOutcome, EventType, Severity
from app.detection.base import (
    AlertCandidate,
    DetectionContext,
    DetectionRule,
    RuleConfig,
    time_bucket,
)
from app.detection.registry import register

# Group names whose membership confers administrative control.
_SENSITIVE_GROUPS = re.compile(
    r"\b(domain admins|enterprise admins|administrators|root|wheel|sudo|"
    r"schema admins|account operators|backup operators)\b",
    re.I,
)


class PrivilegeEscalationConfig(RuleConfig):
    window_minutes: int = Field(default=30, ge=1, le=1440)
    # Successful elevation by an account that has never done so before is the
    # interesting case; this rule reports all of them and lets triage decide.
    alert_on_failed_attempts: bool = True


@register
class PrivilegeEscalationRule(DetectionRule):
    key = "privilege_escalation"
    name = "Privilege Escalation Indicator"
    description = (
        "An account is added to a privileged group, or elevates via a sudo-like "
        "mechanism, on a monitored host."
    )
    default_severity = Severity.HIGH
    default_confidence = 75
    mitre_tactic = "Privilege Escalation"
    mitre_technique_id = "T1548"
    mitre_technique_name = "Abuse Elevation Control Mechanism"
    config_model = PrivilegeEscalationConfig

    def evaluate(self, ctx: DetectionContext) -> list[AlertCandidate]:
        cfg = PrivilegeEscalationConfig(**ctx.config)

        candidates: list[AlertCandidate] = []
        for event in ctx.events:
            if event.event_type != EventType.PRIVILEGE_CHANGE.value:
                continue
            if (
                event.outcome == EventOutcome.FAILURE.value
                and not cfg.alert_on_failed_attempts
            ):
                continue

            haystack = " ".join(
                filter(None, [event.command_line, event.message, str(event.raw.get("group", ""))])
            )
            sensitive = _SENSITIVE_GROUPS.search(haystack)
            group = sensitive.group(0) if sensitive else None

            succeeded = event.outcome != EventOutcome.FAILURE.value
            if sensitive:
                severity = Severity.CRITICAL if succeeded else Severity.HIGH
                confidence = 85 if succeeded else 65
            else:
                severity = Severity.MEDIUM
                confidence = 55

            candidates.append(
                AlertCandidate(
                    dedup_key=(
                        f"{self.key}|{event.username or 'unknown'}|"
                        f"{event.hostname or 'unknown'}|"
                        f"{time_bucket(event.timestamp, cfg.window_minutes)}"
                    ),
                    title=(
                        f"Privilege escalation by '{event.username or 'unknown'}' "
                        f"on {event.hostname or 'unknown host'}"
                    ),
                    description=(
                        f"Account '{event.username or 'unknown'}' performed "
                        f"'{event.action}' on {event.hostname or 'an unknown host'}"
                        + (
                            f", affecting the privileged group '{group}'. Membership of "
                            f"this group confers administrative control."
                            if group
                            else "."
                        )
                        + (
                            ""
                            if succeeded
                            else " The attempt failed, which may indicate probing."
                        )
                    ),
                    severity=severity,
                    confidence=confidence,
                    event_ids=[event.id],
                    first_seen=event.timestamp,
                    last_seen=event.timestamp,
                    src_ip=event.src_ip,
                    username=event.username,
                    hostname=event.hostname,
                    evidence={
                        "action": event.action,
                        "sensitive_group": group,
                        "outcome": event.outcome,
                        "command_line": (event.command_line or "")[:500],
                    },
                )
            )
        return candidates
