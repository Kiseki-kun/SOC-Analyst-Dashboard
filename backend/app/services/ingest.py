"""Event ingestion pipeline: normalize -> persist -> detect."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.event import SecurityEvent
from app.schemas.event import RawEventIn
from app.services.detection_engine import run_detections
from app.services.normalization import NormalizationError, normalize

logger = get_logger(__name__)


@dataclass(slots=True)
class IngestOutcome:
    received: int = 0
    stored: int = 0
    duplicates: int = 0
    rejected: int = 0
    alerts_created: int = 0
    alerts_updated: int = 0


def ingest_events(db: Session, raw_events: list[RawEventIn]) -> IngestOutcome:
    """Normalize, persist and analyse a batch.

    The whole batch shares one transaction with detection, so an alert and the
    events that justify it are committed together — an alert referencing events
    that failed to persist would be unexplainable to the analyst investigating.
    """
    outcome = IngestOutcome(received=len(raw_events))
    if not raw_events:
        return outcome

    # Reject duplicates up front. The generator retries on network failure, and
    # replayed failed logins would otherwise inflate a brute-force count into a
    # false positive.
    incoming_uids = [e.event_uid for e in raw_events]
    existing_uids = set(
        db.execute(
            select(SecurityEvent.event_uid).where(SecurityEvent.event_uid.in_(incoming_uids))
        )
        .scalars()
        .all()
    )

    seen_in_batch: set[str] = set()
    persisted: list[SecurityEvent] = []

    for raw in raw_events:
        if raw.event_uid in existing_uids or raw.event_uid in seen_in_batch:
            outcome.duplicates += 1
            continue
        seen_in_batch.add(raw.event_uid)

        try:
            normalized = normalize(raw)
        except NormalizationError as exc:
            # A malformed event is dropped and counted, never fatal to the batch.
            outcome.rejected += 1
            logger.warning("ingest.normalization_failed", event_uid=raw.event_uid, error=str(exc))
            continue

        event = SecurityEvent(
            event_uid=normalized.event_uid,
            timestamp=normalized.timestamp,
            source=normalized.source,
            event_type=normalized.event_type.value,
            action=normalized.action,
            outcome=normalized.outcome.value,
            severity=normalized.severity.value,
            message=normalized.message,
            src_ip=normalized.src_ip,
            dst_ip=normalized.dst_ip,
            src_port=normalized.src_port,
            dst_port=normalized.dst_port,
            protocol=normalized.protocol,
            bytes_sent=normalized.bytes_sent,
            bytes_received=normalized.bytes_received,
            username=normalized.username,
            hostname=normalized.hostname,
            country_code=normalized.country_code,
            city=normalized.city,
            latitude=normalized.latitude,
            longitude=normalized.longitude,
            process_name=normalized.process_name,
            command_line=normalized.command_line,
            file_path=normalized.file_path,
            file_hash=normalized.file_hash,
            http_method=normalized.http_method,
            url_path=normalized.url_path,
            http_status=normalized.http_status,
            user_agent=normalized.user_agent,
            dns_query=normalized.dns_query,
            raw=normalized.raw,
            analyzed=False,
        )
        db.add(event)
        persisted.append(event)

    if persisted:
        # Flush so the events have identifiers and are visible to the windowed
        # queries the detection rules are about to run.
        db.flush()
        outcome.stored = len(persisted)

        detection = run_detections(db, persisted)
        outcome.alerts_created = detection.alerts_created
        outcome.alerts_updated = detection.alerts_updated

        for event in persisted:
            event.analyzed = True

    db.commit()
    logger.info(
        "ingest.batch_complete",
        received=outcome.received,
        stored=outcome.stored,
        duplicates=outcome.duplicates,
        rejected=outcome.rejected,
        alerts_created=outcome.alerts_created,
    )
    return outcome
