"""Known-bad file hash observed on an endpoint.

MITRE ATT&CK: T1204.002 (User Execution: Malicious File), tactic Execution.

The indicator list is the IOC watchlist table, so an analyst adding an IOC
during an investigation immediately affects subsequent detections. Every hash
shipped with the project is invented for this simulation.
"""

from __future__ import annotations

from pydantic import Field
from sqlalchemy import select

from app.core.enums import IOCType, Severity
from app.detection.base import (
    AlertCandidate,
    DetectionContext,
    DetectionRule,
    RuleConfig,
    time_bucket,
)
from app.detection.registry import register
from app.models.audit import IOCWatchlistEntry


class MaliciousHashConfig(RuleConfig):
    window_minutes: int = Field(default=60, ge=1, le=1440)


@register
class MaliciousHashRule(DetectionRule):
    key = "malicious_file_hash"
    name = "Malicious File Hash Detected"
    description = (
        "A file hash observed on an endpoint matches an active entry on the "
        "indicator watchlist."
    )
    default_severity = Severity.CRITICAL
    default_confidence = 95
    mitre_tactic = "Execution"
    mitre_technique_id = "T1204.002"
    mitre_technique_name = "User Execution: Malicious File"
    config_model = MaliciousHashConfig

    def evaluate(self, ctx: DetectionContext) -> list[AlertCandidate]:
        cfg = MaliciousHashConfig(**ctx.config)

        observed = {e.file_hash.lower(): e for e in ctx.events if e.file_hash}
        if not observed:
            return []

        matches = (
            ctx.db.execute(
                select(IOCWatchlistEntry).where(
                    IOCWatchlistEntry.ioc_type == IOCType.FILE_HASH.value,
                    IOCWatchlistEntry.active.is_(True),
                    IOCWatchlistEntry.value.in_(list(observed.keys())),
                )
            )
            .scalars()
            .all()
        )
        if not matches:
            return []

        candidates: list[AlertCandidate] = []
        for ioc in matches:
            event = observed[ioc.value.lower()]
            candidates.append(
                AlertCandidate(
                    dedup_key=(
                        f"{self.key}|{ioc.value}|{event.hostname or 'unknown'}|"
                        f"{time_bucket(event.timestamp, cfg.window_minutes)}"
                    ),
                    title=f"Malicious file hash on {event.hostname or 'unknown host'}",
                    description=(
                        f"File '{event.file_path or event.process_name or 'unknown'}' on "
                        f"{event.hostname or 'an unknown host'} has hash {ioc.value}, which "
                        f"is on the active indicator watchlist. Watchlist note: "
                        f"{ioc.description or 'no description recorded'}."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=95,
                    event_ids=[event.id],
                    first_seen=event.timestamp,
                    last_seen=event.timestamp,
                    src_ip=event.src_ip,
                    username=event.username,
                    hostname=event.hostname,
                    evidence={
                        "ioc_value": ioc.value,
                        "ioc_type": ioc.ioc_type,
                        "ioc_description": ioc.description,
                        "file_path": event.file_path,
                        "process_name": event.process_name,
                    },
                )
            )
        return candidates
