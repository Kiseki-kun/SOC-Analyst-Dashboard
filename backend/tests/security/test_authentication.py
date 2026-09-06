"""Authentication behaviour, including the failure modes that matter."""

from __future__ import annotations

import pytest

from app.core.permissions import Role
from tests.conftest import TEST_PASSWORD, login


def test_login_succeeds_with_valid_credentials(client, analyst):
    r = client.post("/api/v1/auth/login",
                    json={"email": analyst.email, "password": TEST_PASSWORD})
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["user"]["email"] == analyst.email
    assert "alert:triage" in body["user"]["permissions"]


def test_login_sets_httponly_refresh_cookie(client, analyst):
    r = client.post("/api/v1/auth/login",
                    json={"email": analyst.email, "password": TEST_PASSWORD})
    cookie_header = r.headers.get("set-cookie", "")
    assert "soc_refresh_token=" in cookie_header
    # The whole point of the design: JavaScript must not be able to read it.
    assert "HttpOnly" in cookie_header
    assert "SameSite=lax" in cookie_header.replace("samesite", "SameSite")


def test_refresh_token_is_not_in_response_body(client, analyst):
    """A refresh token in the JSON body would end up in JS-reachable memory."""
    r = client.post("/api/v1/auth/login",
                    json={"email": analyst.email, "password": TEST_PASSWORD})
    assert "refresh_token" not in r.json()


def test_login_rejects_wrong_password(client, analyst):
    r = client.post("/api/v1/auth/login",
                    json={"email": analyst.email, "password": "WrongPassword1!"})
    assert r.status_code == 401


def test_login_rejects_unknown_account(client):
    r = client.post("/api/v1/auth/login",
                    json={"email": "nobody@soc.example.com", "password": TEST_PASSWORD})
    assert r.status_code == 401


def test_error_message_does_not_reveal_whether_account_exists(client, analyst):
    """Account enumeration: both failures must be indistinguishable."""
    known = client.post("/api/v1/auth/login",
                        json={"email": analyst.email, "password": "WrongPassword1!"})
    unknown = client.post("/api/v1/auth/login",
                          json={"email": "nobody@soc.example.com", "password": "WrongPassword1!"})
    assert known.status_code == unknown.status_code == 401
    assert known.json()["detail"] == unknown.json()["detail"]


def test_inactive_account_cannot_log_in(client, user_factory):
    disabled = user_factory(Role.ANALYST, active=False)
    r = client.post("/api/v1/auth/login",
                    json={"email": disabled.email, "password": TEST_PASSWORD})
    assert r.status_code == 401


def test_login_is_case_insensitive_on_email(client, user_factory):
    user_factory(Role.VIEWER, email="mixed.case@soc.example.com")
    r = client.post("/api/v1/auth/login",
                    json={"email": "Mixed.Case@SOC.Example.COM", "password": TEST_PASSWORD})
    assert r.status_code == 200


def test_protected_route_requires_a_token(client):
    assert client.get("/api/v1/auth/me").status_code == 401


@pytest.mark.parametrize(
    "header",
    ["Bearer not-a-token", "Bearer ", "Basic dXNlcjpwYXNz", "not-even-a-scheme"],
)
def test_malformed_authorization_headers_are_rejected(client, header):
    r = client.get("/api/v1/auth/me", headers={"Authorization": header})
    assert r.status_code == 401


def test_refresh_token_cannot_be_used_as_access_token(client, analyst):
    """Token confusion: a valid signature is not enough."""
    login_response = client.post(
        "/api/v1/auth/login", json={"email": analyst.email, "password": TEST_PASSWORD}
    )
    refresh = login_response.cookies.get("soc_refresh_token")
    assert refresh
    r = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {refresh}"})
    assert r.status_code == 401


def test_refresh_rotates_the_cookie(client, analyst):
    client.post("/api/v1/auth/login",
                json={"email": analyst.email, "password": TEST_PASSWORD})
    first = client.cookies.get("soc_refresh_token")
    r = client.post("/api/v1/auth/refresh")
    assert r.status_code == 200
    assert client.cookies.get("soc_refresh_token") != first


def test_refresh_without_cookie_is_unauthorised(client):
    assert client.post("/api/v1/auth/refresh").status_code == 401


def test_repeated_failures_are_rate_limited(client, analyst):
    """Unlimited login attempts are an unauthenticated brute-force primitive."""
    statuses = [
        client.post("/api/v1/auth/login",
                    json={"email": analyst.email, "password": "WrongPassword1!"}).status_code
        for _ in range(7)
    ]
    assert 429 in statuses, f"never rate limited: {statuses}"


def test_password_change_requires_the_current_password(client, analyst, as_user):
    r = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "WrongPassword1!", "new_password": "An0ther!Password"},
        headers=as_user(analyst),
    )
    assert r.status_code == 400


def test_password_change_enforces_strength(client, analyst, as_user):
    r = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": TEST_PASSWORD, "new_password": "short"},
        headers=as_user(analyst),
    )
    assert r.status_code == 422


def test_password_change_then_login_with_new_password(client, analyst, as_user):
    new_password = "Br@ndNewPassw0rd!"
    r = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": TEST_PASSWORD, "new_password": new_password},
        headers=as_user(analyst),
    )
    assert r.status_code == 200
    assert login(client, analyst, password=new_password)
    assert client.post("/api/v1/auth/login",
                       json={"email": analyst.email, "password": TEST_PASSWORD}).status_code == 401
