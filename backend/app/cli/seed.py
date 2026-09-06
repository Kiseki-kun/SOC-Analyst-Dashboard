"""Idempotent bootstrap: demo users.

Run automatically by the container entrypoint when SEED_DEMO_USERS=true, and
safe to run repeatedly — it creates nothing that already exists and never
overwrites a password that has been changed.

Detection rules and the IOC watchlist are seeded by app.cli.seed_detections.
"""

from __future__ import annotations

import sys

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.logging import configure_logging, get_logger
from app.core.permissions import Role
from app.core.security import hash_password
from app.db.session import get_session_factory
from app.models.user import User

logger = get_logger(__name__)


def _demo_accounts(settings: Settings) -> list[tuple[str, str, str, Role]]:
    return [
        (settings.DEMO_ADMIN_EMAIL, settings.DEMO_ADMIN_PASSWORD, "Demo Administrator", Role.ADMIN),
        (settings.DEMO_ANALYST_EMAIL, settings.DEMO_ANALYST_PASSWORD, "Demo Analyst", Role.ANALYST),
        (settings.DEMO_RESPONDER_EMAIL, settings.DEMO_RESPONDER_PASSWORD, "Demo Responder", Role.RESPONDER),
        (settings.DEMO_VIEWER_EMAIL, settings.DEMO_VIEWER_PASSWORD, "Demo Viewer", Role.VIEWER),
    ]


def seed_users(db: Session, settings: Settings) -> int:
    """Create any missing demo account. Returns how many were created."""
    created = 0
    for email, password, full_name, role in _demo_accounts(settings):
        email = email.strip().lower()
        if not email or not password:
            logger.warning("seed.account_skipped", email=email or "<empty>",
                           reason="email or password not configured")
            continue
        if len(password) < 12:
            # Refuse rather than create a weak account. A demo credential is
            # still a credential, and this one is an administrator.
            logger.error("seed.account_rejected", email=email,
                         reason="password shorter than 12 characters")
            continue

        exists = db.execute(select(User.id).where(User.email == email)).scalar_one_or_none()
        if exists:
            continue

        db.add(
            User(
                email=email,
                full_name=full_name,
                role=role.value,
                hashed_password=hash_password(password, settings.BCRYPT_ROUNDS),
                is_active=True,
            )
        )
        created += 1
        logger.info("seed.account_created", email=email, role=role.value)
    return created


def main() -> int:
    settings = get_settings()
    configure_logging(settings.LOG_LEVEL, json_output=settings.is_production)

    if not settings.SEED_DEMO_USERS:
        logger.info("seed.disabled")
        return 0

    session = get_session_factory()()
    try:
        existing = session.execute(select(func.count()).select_from(User)).scalar_one()
        created = seed_users(session, settings)
        session.commit()
        logger.info("seed.complete", pre_existing_users=existing, created=created)
    except Exception:
        session.rollback()
        logger.exception("seed.failed")
        return 1
    finally:
        session.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
