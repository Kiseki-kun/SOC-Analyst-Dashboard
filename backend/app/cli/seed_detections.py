"""Seed detection rules and the synthetic IOC watchlist.

Idempotent: safe on every container start. Tuned thresholds and disabled rules
are preserved.
"""

from __future__ import annotations

import sys

from sqlalchemy import select
from sqlalchemy.orm import Session

import app.detection.rules  # noqa: F401  - registers every rule
from app.core.config import get_settings
from app.core.enums import IOCType
from app.core.logging import configure_logging, get_logger
from app.db.session import get_session_factory
from app.models.audit import IOCWatchlistEntry
from app.services.detection_engine import sync_rules_to_database

logger = get_logger(__name__)

# Entirely invented indicators for this simulation. These are not real malware
# hashes; they are syntactically valid SHA-256 strings generated for the demo.
SYNTHETIC_IOCS: list[tuple[IOCType, str, str]] = [
    (
        IOCType.FILE_HASH,
        "3f786850e387550fdab836ed7e6dc881de23001b3f786850e387550fdab836ed",
        "SIMULATED: commodity loader used in the demo endpoint scenario",
    ),
    (
        IOCType.FILE_HASH,
        "a1b2c3d4e5f60718293a4b5c6d7e8f9012a3b4c5d6e7f8091a2b3c4d5e6f7081",
        "SIMULATED: credential-dumping utility used in the demo",
    ),
    (
        IOCType.FILE_HASH,
        "0e1d2c3b4a59687776859403a2b1c0d9e8f7a6b5c4d3e2f109182736455463728",
        "SIMULATED: ransomware stager used in the demo",
    ),
    (
        IOCType.IP_ADDRESS,
        "203.0.113.66",
        "SIMULATED: command-and-control address (TEST-NET-3, reserved for docs)",
    ),
    (
        IOCType.DOMAIN,
        "updates.malicious-demo.invalid",
        "SIMULATED: C2 domain (.invalid TLD, reserved and unresolvable)",
    ),
]


def seed_iocs(db: Session) -> int:
    created = 0
    for ioc_type, value, description in SYNTHETIC_IOCS:
        exists = db.execute(
            select(IOCWatchlistEntry.id).where(
                IOCWatchlistEntry.ioc_type == ioc_type.value,
                IOCWatchlistEntry.value == value,
            )
        ).scalar_one_or_none()
        if exists:
            continue
        db.add(
            IOCWatchlistEntry(
                ioc_type=ioc_type.value,
                value=value,
                description=description,
                active=True,
                added_by_email="system@soc.example.com",
            )
        )
        created += 1
    return created


def main() -> int:
    settings = get_settings()
    configure_logging(settings.LOG_LEVEL, json_output=settings.is_production)
    session = get_session_factory()()
    try:
        rules_created, rules_updated = sync_rules_to_database(session)
        iocs_created = seed_iocs(session)
        session.commit()
        logger.info(
            "seed_detections.complete",
            rules_created=rules_created,
            rules_updated=rules_updated,
            iocs_created=iocs_created,
        )
    except Exception:
        session.rollback()
        logger.exception("seed_detections.failed")
        return 1
    finally:
        session.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
