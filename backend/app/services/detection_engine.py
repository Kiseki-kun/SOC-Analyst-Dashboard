"""Detection engine.

Runs every enabled rule over a batch of freshly ingested events and turns the
resulting candidates into alerts, deduplicating against alerts that are already
open.

Execution model: synchronous, inside the ingest request. At this scale that is
a feature — detection is deterministic and testable, and an alert exists by the
time the ingest call returns. A production deployment handling real volume
would move this behind a queue; that trade-off is documented rather than
pretended away.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import insert, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

# Importing this package is what runs each rule's @register decorator.
# The registry also loads on demand, but stating the dependency here means
# a reader can see why the engine has any rules to run at all.
import app.detection.rules  # noqa: F401
from app.core.enums import ALERT_TERMINAL_STATUSES
from app.core.logging import get_logger
from app.db.base import utcnow
from app.detection.base import AlertCandidate, DetectionContext
from app.detection.registry import all_rules
from app.models.alert import Alert, alert_events
from app.models.detection import DetectionRule as DetectionRuleModel
from app.models.event import SecurityEvent

logger = get_logger(__name__)


@dataclass(slots=True)
class DetectionOutcome:
    alerts_created: int = 0
    alerts_updated: int = 0
    rules_run: int = 0
    rules_failed: int = 0


def _new_alert_uid() -> str:
    """Short, unique, human-quotable alert reference.

    Random rather than sequential: a sequence would need a lock or a database
    sequence, and two concurrent ingest batches would contend on it.
    """
    return f"ALT-{uuid.uuid4().hex[:10].upper()}"


def _linked_event_ids(db: Session, alert_id: uuid.UUID) -> set[uuid.UUID]:
    return set(
        db.execute(
            select(alert_events.c.event_id).where(alert_events.c.alert_id == alert_id)
        )
        .scalars()
        .all()
    )


def _link_events(db: Session, alert_id: uuid.UUID, event_ids: list[uuid.UUID]) -> int:
    """Attach events to an alert, skipping ones already attached."""
    if not event_ids:
        return 0
    existing = _linked_event_ids(db, alert_id)
    new_ids = [eid for eid in dict.fromkeys(event_ids) if eid not in existing]
    if not new_ids:
        return 0
    db.execute(
        insert(alert_events),
        [{"alert_id": alert_id, "event_id": eid} for eid in new_ids],
    )
    return len(new_ids)


def _apply_candidate(
    db: Session,
    candidate: AlertCandidate,
    rule_model: DetectionRuleModel,
    outcome: DetectionOutcome,
) -> None:
    existing = db.execute(
        select(Alert).where(Alert.dedup_key == candidate.dedup_key)
    ).scalar_one_or_none()

    if existing is not None:
        # An alert an analyst has already closed must not silently reopen and
        # lose that decision. A genuinely new burst produces a new time bucket
        # and therefore a new dedup key.
        if existing.status in ALERT_TERMINAL_STATUSES:
            return

        added = _link_events(db, existing.id, candidate.event_ids)
        existing.event_count = len(_linked_event_ids(db, existing.id))
        existing.last_seen = max(existing.last_seen, candidate.last_seen)
        existing.first_seen = min(existing.first_seen, candidate.first_seen)
        # Severity and confidence can only escalate: an attack that intensifies
        # should raise the alert, never quietly downgrade one an analyst has
        # already prioritised.
        if _severity_rank(candidate.severity.value) > _severity_rank(existing.severity):
            existing.severity = candidate.severity.value
        existing.confidence = max(existing.confidence, candidate.confidence)
        existing.description = candidate.description
        # Latest evidence supersedes: it reflects the full window, not the
        # first slice of it.
        existing.evidence = candidate.evidence
        if added:
            outcome.alerts_updated += 1
        return

    alert = Alert(
        alert_uid=_new_alert_uid(),
        rule_id=rule_model.id,
        rule_key=rule_model.rule_key,
        title=candidate.title[:300],
        description=candidate.description,
        severity=candidate.severity.value,
        confidence=candidate.confidence,
        dedup_key=candidate.dedup_key[:255],
        first_seen=candidate.first_seen,
        last_seen=candidate.last_seen,
        event_count=len(set(candidate.event_ids)),
        src_ip=candidate.src_ip,
        dst_ip=candidate.dst_ip,
        username=candidate.username,
        hostname=candidate.hostname,
        mitre_technique_id=rule_model.mitre_technique_id,
        mitre_technique_name=rule_model.mitre_technique_name,
        mitre_tactic=rule_model.mitre_tactic,
        evidence=candidate.evidence,
    )
    db.add(alert)
    try:
        db.flush()
    except IntegrityError:
        # Lost a race against a concurrent batch that inserted the same dedup
        # key. The database constraint is the arbiter; fold into the winner.
        db.rollback()
        return

    _link_events(db, alert.id, candidate.event_ids)
    outcome.alerts_created += 1


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _severity_rank(value: str) -> int:
    return _SEVERITY_RANK.get(value, 0)


def run_detections(
    db: Session, events: list[SecurityEvent], *, now=None
) -> DetectionOutcome:
    """Evaluate all enabled rules against `events`."""
    outcome = DetectionOutcome()
    if not events:
        return outcome

    now = now or utcnow()

    rule_models = (
        db.execute(select(DetectionRuleModel).where(DetectionRuleModel.enabled.is_(True)))
        .scalars()
        .all()
    )
    registered = all_rules()

    for rule_model in rule_models:
        rule_cls = registered.get(rule_model.rule_key)
        if rule_cls is None:
            # A row whose code has been removed. Log once rather than crash the
            # pipeline; the admin UI shows it as unavailable.
            logger.warning("detection.rule_not_implemented", rule_key=rule_model.rule_key)
            continue

        config = rule_cls.parse_config(rule_model.config).model_dump()
        context = DetectionContext(db=db, events=events, config=config, now=now)

        try:
            candidates = rule_cls().evaluate(context)
            outcome.rules_run += 1
        except Exception:
            # One broken rule must not stop the others or drop the batch.
            outcome.rules_failed += 1
            logger.exception("detection.rule_failed", rule_key=rule_model.rule_key)
            continue

        for candidate in candidates:
            try:
                _apply_candidate(db, candidate, rule_model, outcome)
            except Exception:
                logger.exception(
                    "detection.alert_creation_failed",
                    rule_key=rule_model.rule_key,
                    dedup_key=candidate.dedup_key,
                )

    return outcome


def sync_rules_to_database(db: Session) -> tuple[int, int]:
    """Ensure a DetectionRule row exists for every registered rule class.

    Returns (created, updated). Existing rows keep their tuned config and
    enabled flag — an operator's threshold change must survive a deployment.
    Only descriptive metadata is refreshed from code.
    """
    created = updated = 0
    for key, rule_cls in all_rules().items():
        row = db.execute(
            select(DetectionRuleModel).where(DetectionRuleModel.rule_key == key)
        ).scalar_one_or_none()

        if row is None:
            db.add(
                DetectionRuleModel(
                    rule_key=key,
                    name=rule_cls.name,
                    description=rule_cls.description,
                    severity=rule_cls.default_severity.value,
                    enabled=True,
                    config=rule_cls.default_config(),
                    mitre_tactic=rule_cls.mitre_tactic,
                    mitre_technique_id=rule_cls.mitre_technique_id,
                    mitre_technique_name=rule_cls.mitre_technique_name,
                )
            )
            created += 1
            continue

        changed = False
        for field, value in (
            ("name", rule_cls.name),
            ("description", rule_cls.description),
            ("mitre_tactic", rule_cls.mitre_tactic),
            ("mitre_technique_id", rule_cls.mitre_technique_id),
            ("mitre_technique_name", rule_cls.mitre_technique_name),
        ):
            if getattr(row, field) != value:
                setattr(row, field, value)
                changed = True
        if changed:
            updated += 1

    return created, updated
