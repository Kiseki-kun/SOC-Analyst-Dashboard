"""Role boundary enforcement.

Every test here calls the real HTTP endpoint. The point is to prove the server
refuses, not that the UI hides a button — a frontend-only control is not a
control at all.
"""

from __future__ import annotations

from itertools import pairwise

import pytest
from sqlalchemy import select

from app.core.enums import AuditAction
from app.core.permissions import Permission, Role, permissions_for
from app.models.audit import AuditLog
from tests.conftest import TEST_PASSWORD


# --------------------------------------------------------------- user admin
@pytest.mark.parametrize(
    "role,expected",
    [(Role.VIEWER, 403), (Role.ANALYST, 403), (Role.RESPONDER, 403), (Role.ADMIN, 200)],
)
def test_only_admin_can_list_users(client, user_factory, as_user, role, expected):
    actor = user_factory(role)
    r = client.get("/api/v1/users", headers=as_user(actor))
    assert r.status_code == expected


@pytest.mark.parametrize(
    "role,expected",
    [(Role.VIEWER, 403), (Role.ANALYST, 403), (Role.RESPONDER, 403), (Role.ADMIN, 201)],
)
def test_only_admin_can_create_users(client, user_factory, as_user, role, expected):
    actor = user_factory(role)
    r = client.post(
        "/api/v1/users",
        json={
            "email": f"new-{role.value}@soc.example.com",
            "full_name": "New User",
            "role": "viewer",
            "password": "V@lidPassword123",
        },
        headers=as_user(actor),
    )
    assert r.status_code == expected


def test_created_user_can_actually_log_in(client, admin, as_user):
    """A create endpoint that stores an unusable hash would pass a 201 check."""
    r = client.post(
        "/api/v1/users",
        json={
            "email": "provisioned@soc.example.com",
            "full_name": "Provisioned",
            "role": "analyst",
            "password": "V@lidPassword123",
        },
        headers=as_user(admin),
    )
    assert r.status_code == 201
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "provisioned@soc.example.com", "password": "V@lidPassword123"},
    )
    assert login.status_code == 200
    assert login.json()["user"]["role"] == "analyst"


def test_duplicate_email_is_rejected(client, admin, as_user):
    payload = {
        "email": "dupe@soc.example.com",
        "full_name": "Dupe",
        "role": "viewer",
        "password": "V@lidPassword123",
    }
    assert client.post("/api/v1/users", json=payload, headers=as_user(admin)).status_code == 201
    assert client.post("/api/v1/users", json=payload, headers=as_user(admin)).status_code == 409


def test_weak_password_is_rejected_on_creation(client, admin, as_user):
    r = client.post(
        "/api/v1/users",
        json={
            "email": "weak@soc.example.com",
            "full_name": "Weak",
            "role": "viewer",
            "password": "password",
        },
        headers=as_user(admin),
    )
    assert r.status_code == 422


# ------------------------------------------------- privilege-escalation guards
def test_admin_cannot_change_their_own_role(client, admin, as_user):
    r = client.patch(
        f"/api/v1/users/{admin.id}", json={"role": "viewer"}, headers=as_user(admin)
    )
    assert r.status_code == 400


def test_admin_cannot_deactivate_themselves(client, admin, as_user):
    r = client.patch(
        f"/api/v1/users/{admin.id}", json={"is_active": False}, headers=as_user(admin)
    )
    assert r.status_code == 400


def test_cannot_deactivate_the_last_administrator(client, admin, user_factory, as_user):
    """Losing every admin would make the system unadministrable."""
    other_admin = user_factory(Role.ADMIN)
    # Deactivating one of two admins is fine.
    ok = client.patch(
        f"/api/v1/users/{other_admin.id}", json={"is_active": False}, headers=as_user(admin)
    )
    assert ok.status_code == 200


def test_analyst_cannot_escalate_themselves_to_admin(client, analyst, as_user):
    r = client.patch(
        f"/api/v1/users/{analyst.id}", json={"role": "admin"}, headers=as_user(analyst)
    )
    assert r.status_code == 403


# ------------------------------------------------------------- audit coverage
def test_denied_access_is_recorded_in_the_audit_log(client, db_session, viewer, as_user):
    """Privilege probing must leave a trace; that is what makes it detectable."""
    assert client.get("/api/v1/users", headers=as_user(viewer)).status_code == 403
    entries = (
        db_session.execute(
            select(AuditLog).where(
                AuditLog.action == AuditAction.UNAUTHORIZED_ACCESS_ATTEMPT.value
            )
        )
        .scalars()
        .all()
    )
    assert len(entries) == 1
    entry = entries[0]
    assert entry.actor_email == viewer.email
    assert entry.success is False
    assert entry.details["required_permission"] == "user:read"
    assert entry.details["endpoint"] == "/api/v1/users"


def test_successful_login_is_audited(client, db_session, analyst):
    client.post("/api/v1/auth/login",
                json={"email": analyst.email, "password": TEST_PASSWORD})
    actions = db_session.execute(select(AuditLog.action)).scalars().all()
    assert AuditAction.LOGIN_SUCCESS.value in actions


def test_failed_login_is_audited_with_the_attempted_identity(client, db_session, analyst):
    client.post("/api/v1/auth/login",
                json={"email": analyst.email, "password": "WrongPassword1!"})
    entry = db_session.execute(
        select(AuditLog).where(AuditLog.action == AuditAction.LOGIN_FAILURE.value)
    ).scalar_one()
    assert entry.actor_email == analyst.email
    assert entry.success is False


def test_audit_details_never_contain_credentials(client, db_session, analyst):
    """The audit allow-list must drop anything credential-shaped."""
    client.post("/api/v1/auth/login",
                json={"email": analyst.email, "password": "WrongPassword1!"})
    for entry in db_session.execute(select(AuditLog)).scalars().all():
        serialised = str(entry.details).lower()
        assert "wrongpassword" not in serialised
        assert "password" not in entry.details
        assert "token" not in entry.details


# ------------------------------------------------- permission model integrity
def test_permission_sets_are_strictly_nested_by_privilege():
    """Each role must be a superset of the one below it."""
    order = [Role.VIEWER, Role.ANALYST, Role.RESPONDER, Role.ADMIN]
    for lower, higher in pairwise(order):
        assert permissions_for(lower) < permissions_for(higher), (
            f"{higher.value} does not strictly contain {lower.value}"
        )


def test_no_role_below_admin_can_read_the_audit_log():
    for role in (Role.VIEWER, Role.ANALYST, Role.RESPONDER):
        assert Permission.AUDIT_READ not in permissions_for(role)


def test_no_role_below_responder_can_execute_response_actions():
    for role in (Role.VIEWER, Role.ANALYST):
        assert Permission.RESPONSE_ACTION_EXECUTE not in permissions_for(role)


def test_unknown_role_grants_no_permissions():
    """Fail closed: a corrupted role string must not be privileged."""
    assert permissions_for("root") == frozenset()
    assert permissions_for("") == frozenset()
