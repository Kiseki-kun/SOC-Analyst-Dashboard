"""Test fixtures.

The suite exercises the real application object against a real (SQLite)
database over a real HTTP client. Nothing is mocked at the boundary being
tested: an RBAC test that stubbed the permission check would prove nothing.
"""

from __future__ import annotations

import uuid
from collections.abc import Generator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import Settings, build_test_settings, get_settings
from app.core.permissions import Role
from app.core.security import hash_password
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.user import User
from app.services.throttle import login_throttle


@pytest.fixture
def settings() -> Settings:
    return build_test_settings()


@pytest.fixture
def engine():
    eng = create_engine(
        "sqlite+pysqlite:///:memory:",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(eng)
    try:
        yield eng
    finally:
        Base.metadata.drop_all(eng)
        eng.dispose()


@pytest.fixture
def db_session(engine) -> Generator[Session]:
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def app(settings: Settings, engine) -> FastAPI:
    application = create_app(settings)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def _get_db():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    application.dependency_overrides[get_db] = _get_db
    application.dependency_overrides[get_settings] = lambda: settings
    login_throttle.reset()
    return application


@pytest.fixture
def client(app: FastAPI) -> Generator[TestClient]:
    with TestClient(app) as c:
        yield c


# --------------------------------------------------------------------- users
TEST_PASSWORD = "Sup3rSecret!Passw0rd"


def make_user(
    session: Session,
    *,
    role: Role,
    email: str | None = None,
    active: bool = True,
    password: str = TEST_PASSWORD,
) -> User:
    user = User(
        id=uuid.uuid4(),
        email=email or f"{role.value}-{uuid.uuid4().hex[:8]}@soc.example.com",
        full_name=f"Test {role.value.title()}",
        hashed_password=hash_password(password, rounds=10),
        role=role.value,
        is_active=active,
    )
    session.add(user)
    session.commit()
    return user


@pytest.fixture
def user_factory(db_session: Session):
    def _factory(role: Role, **kwargs) -> User:
        return make_user(db_session, role=role, **kwargs)

    return _factory


@pytest.fixture
def viewer(db_session): return make_user(db_session, role=Role.VIEWER)


@pytest.fixture
def analyst(db_session): return make_user(db_session, role=Role.ANALYST)


@pytest.fixture
def responder(db_session): return make_user(db_session, role=Role.RESPONDER)


@pytest.fixture
def admin(db_session): return make_user(db_session, role=Role.ADMIN)


def login(client: TestClient, user: User, password: str = TEST_PASSWORD) -> str:
    """Log in through the real endpoint and return the access token."""
    response = client.post(
        "/api/v1/auth/login", json={"email": user.email, "password": password}
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def auth_headers(client: TestClient, user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {login(client, user)}"}


@pytest.fixture
def as_user(client: TestClient):
    def _headers(user: User) -> dict[str, str]:
        return auth_headers(client, user)

    return _headers


# ------------------------------------------------------------------ detection
@pytest.fixture
def seeded_rules(db_session: Session):
    """Register every detection rule in the database, as the entrypoint does."""
    import app.detection.rules  # noqa: F401
    from app.services.detection_engine import sync_rules_to_database

    sync_rules_to_database(db_session)
    db_session.commit()
    return db_session


@pytest.fixture
def ingest_headers(settings: Settings) -> dict[str, str]:
    return {"X-Ingest-Key": settings.INGEST_API_KEY}


@pytest.fixture
def sample_alert(seeded_rules):
    """A real alert, produced by the real detection engine from real events."""
    from sqlalchemy import select as _select

    from app.models.alert import Alert as _Alert
    from app.schemas.event import RawEventIn
    from app.services.ingest import ingest_events
    from tests import factories

    db = seeded_rules
    ingest_events(
        db,
        [RawEventIn(**factories.failed_login("203.0.113.99", "targetuser")) for _ in range(12)],
    )
    return db.execute(_select(_Alert)).scalars().first()
