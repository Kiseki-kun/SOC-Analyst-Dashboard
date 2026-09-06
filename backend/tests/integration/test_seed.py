"""The bootstrap must be safe to run on every container start."""

from __future__ import annotations

from sqlalchemy import func, select

from app.cli.seed import seed_users
from app.core.config import build_test_settings
from app.core.permissions import Role
from app.core.security import verify_password
from app.models.user import User


def _settings():
    return build_test_settings(
        SEED_DEMO_USERS=True,
        DEMO_ADMIN_EMAIL="admin@soc.example.com",
        DEMO_ADMIN_PASSWORD="Adm1n!DemoPassword",
        DEMO_ANALYST_EMAIL="analyst@soc.example.com",
        DEMO_ANALYST_PASSWORD="An@lyst!DemoPass1",
        DEMO_RESPONDER_EMAIL="responder@soc.example.com",
        DEMO_RESPONDER_PASSWORD="Resp0nder!DemoPas",
        DEMO_VIEWER_EMAIL="viewer@soc.example.com",
        DEMO_VIEWER_PASSWORD="V1ewer!DemoPasswd",
    )


def test_seed_creates_all_four_roles(db_session):
    created = seed_users(db_session, _settings())
    db_session.commit()
    assert created == 4
    roles = set(db_session.execute(select(User.role)).scalars().all())
    assert roles == {r.value for r in Role}


def test_seed_is_idempotent(db_session):
    settings = _settings()
    seed_users(db_session, settings)
    db_session.commit()
    second_run = seed_users(db_session, settings)
    db_session.commit()
    assert second_run == 0
    total = db_session.execute(select(func.count()).select_from(User)).scalar_one()
    assert total == 4


def test_seed_does_not_reset_a_changed_password(db_session):
    """A restart must not silently restore the documented demo password."""
    settings = _settings()
    seed_users(db_session, settings)
    db_session.commit()
    from app.core.security import hash_password

    admin = db_session.execute(
        select(User).where(User.email == "admin@soc.example.com")
    ).scalar_one()
    admin.hashed_password = hash_password("Operator!Chosen1", rounds=10)
    db_session.commit()

    seed_users(db_session, settings)
    db_session.commit()
    db_session.refresh(admin)
    assert verify_password("Operator!Chosen1", admin.hashed_password)
    assert not verify_password(settings.DEMO_ADMIN_PASSWORD, admin.hashed_password)


def test_seed_refuses_a_weak_demo_password(db_session):
    settings = _settings()
    settings.DEMO_ADMIN_PASSWORD = "short"
    created = seed_users(db_session, settings)
    db_session.commit()
    assert created == 3
    emails = set(db_session.execute(select(User.email)).scalars().all())
    assert "admin@soc.example.com" not in emails
