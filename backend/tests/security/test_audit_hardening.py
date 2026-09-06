"""Regression tests for issues found in the final security audit.

Each of these covers a control that was either absent or measurably broken.
"""

from __future__ import annotations

import time

import pytest

from app.core.config import build_test_settings
from app.core.permissions import Role
from app.core.security import (
    TOKEN_TYPE_ACCESS,
    create_access_token,
    decode_token,
    waste_password_cycles,
)
from tests.conftest import TEST_PASSWORD


# ------------------------------------------------ 1. login timing equalisation
class TestLoginTimingOracle:
    """The dummy hash must cost the same as a real one.

    It previously ran at cost 10 while accounts hashed at cost 12 — a 4.5x
    difference an attacker can measure, which defeated the account-enumeration
    defence the dummy hash exists to provide.
    """

    def test_dummy_hash_uses_the_configured_cost(self):
        import app.core.security as security

        security._dummy_hashes.clear()
        waste_password_cycles(12)
        assert 12 in security._dummy_hashes
        assert security._dummy_hashes[12].startswith("$2b$12$"), (
            f"dummy hash cost mismatch: {security._dummy_hashes[12][:7]}"
        )

    @pytest.mark.parametrize("rounds", [10, 12])
    def test_dummy_hash_is_generated_per_cost_factor(self, rounds):
        import app.core.security as security

        security._dummy_hashes.clear()
        waste_password_cycles(rounds)
        assert security._dummy_hashes[rounds].startswith(f"$2b${rounds:02d}$")

    def test_unknown_and_known_accounts_take_comparable_time(self, client, analyst):
        """The observable behaviour, not just the implementation detail.

        A generous tolerance: this runs on shared CI-class hardware and the
        point is to catch an order-of-magnitude gap, not to measure precisely.
        """
        def elapsed(email: str) -> float:
            start = time.perf_counter()
            client.post("/api/v1/auth/login", json={"email": email, "password": "Wrong1!Password"})
            return time.perf_counter() - start

        # Warm any lazy hash generation so it is not counted.
        client.post("/api/v1/auth/login",
                    json={"email": "warm@soc.example.com", "password": "Wrong1!Password"})

        known = min(elapsed(analyst.email) for _ in range(3))
        unknown = min(elapsed("definitely-not-registered@soc.example.com") for _ in range(3))

        ratio = max(known, unknown) / max(min(known, unknown), 1e-6)
        assert ratio < 3.0, (
            f"login timing differs by {ratio:.1f}x "
            f"(known {known*1000:.0f} ms vs unknown {unknown*1000:.0f} ms) — "
            "this is an account-enumeration oracle"
        )


# ------------------------------------------------------- 2. token_version
class TestTokenVersionRevocation:
    """`token_version` must actually revoke, not merely exist as a column."""

    def test_token_carries_the_version(self):
        settings = build_test_settings()
        token = create_access_token("11111111-1111-1111-1111-111111111111", "analyst",
                                    settings, token_version=7)
        payload = decode_token(token, settings, expected_type=TOKEN_TYPE_ACCESS)
        assert payload is not None
        assert payload.token_version == 7

    def test_token_without_a_version_claim_is_rejected(self):
        """An old token minted before this claim existed must not be accepted."""
        import jwt

        settings = build_test_settings()
        legacy = jwt.encode(
            {
                "sub": "11111111-1111-1111-1111-111111111111",
                "role": "admin",
                "typ": "access",
                "jti": "abc",
                "iat": int(time.time()),
                "nbf": int(time.time()),
                "exp": int(time.time()) + 900,
            },
            settings.SECRET_KEY,
            algorithm=settings.ALGORITHM,
        )
        assert decode_token(legacy, settings, expected_type=TOKEN_TYPE_ACCESS) is None

    def test_changing_password_invalidates_the_existing_access_token(
        self, client, analyst, as_user
    ):
        headers = as_user(analyst)
        assert client.get("/api/v1/auth/me", headers=headers).status_code == 200

        changed = client.post(
            "/api/v1/auth/change-password",
            json={"current_password": TEST_PASSWORD, "new_password": "Br@ndNewPassw0rd!"},
            headers=headers,
        )
        assert changed.status_code == 200

        # The same bearer token must now be refused.
        assert client.get("/api/v1/auth/me", headers=headers).status_code == 401

    def test_changing_password_invalidates_the_refresh_cookie(self, client, analyst):
        login = client.post("/api/v1/auth/login",
                            json={"email": analyst.email, "password": TEST_PASSWORD})
        assert login.status_code == 200
        token = login.json()["access_token"]

        assert client.post("/api/v1/auth/refresh").status_code == 200

        client.post(
            "/api/v1/auth/change-password",
            json={"current_password": TEST_PASSWORD, "new_password": "An0ther!Passw0rd"},
            headers={"Authorization": f"Bearer {token}"},
        )
        # The cookie the client still holds was minted at the old version.
        assert client.post("/api/v1/auth/refresh").status_code == 401


# --------------------------------------------------- 3. request body ceiling
class TestRequestBodyLimit:
    """Schema limits bound the payload's shape only after it is fully parsed.

    The ingest schema permits roughly 125 MB, so a ceiling is enforced on the
    Content-Length header before any of the body is buffered.
    """

    def test_oversized_body_is_rejected_with_413(self, client, ingest_headers):
        settings = build_test_settings()
        oversized = settings.MAX_REQUEST_BODY_BYTES + 1
        response = client.post(
            "/api/v1/ingest/events",
            headers={**ingest_headers, "Content-Type": "application/json",
                     "Content-Length": str(oversized)},
            content=b'{"events":[]}',
        )
        assert response.status_code == 413
        assert "limit" in response.json()["detail"].lower()

    def test_the_limit_applies_before_authentication(self, client):
        """A huge body must not be buffered just to discover the caller is anonymous."""
        settings = build_test_settings()
        response = client.post(
            "/api/v1/ingest/events",
            headers={"Content-Type": "application/json",
                     "Content-Length": str(settings.MAX_REQUEST_BODY_BYTES + 1)},
            content=b'{"events":[]}',
        )
        assert response.status_code == 413

    # The chunked branch cannot be exercised through the test client, which
    # always sets Content-Length. The policy is therefore tested directly.
    @pytest.mark.parametrize(
        "method,length,encoding,expected",
        [
            ("POST", None, "chunked", 411),
            ("PUT", None, "Chunked", 411),
            ("POST", "not-a-number", None, 400),
            ("POST", "-1", None, 400),
            ("POST", str(5 * 1024 * 1024), None, 413),
            ("POST", "1024", None, None),
            ("POST", None, None, None),
            ("GET", str(99 * 1024 * 1024), None, None),
            ("DELETE", None, "chunked", None),
        ],
    )
    def test_size_policy_decisions(self, method, length, encoding, expected):
        from app.main import evaluate_request_size

        result = evaluate_request_size(
            method=method,
            content_length=length,
            transfer_encoding=encoding,
            limit_bytes=4 * 1024 * 1024,
        )
        if expected is None:
            assert result is None
        else:
            assert result is not None and result[0] == expected

    def test_malformed_content_length_is_rejected(self, client, ingest_headers):
        response = client.post(
            "/api/v1/ingest/events",
            headers={**ingest_headers, "Content-Type": "application/json",
                     "Content-Length": "not-a-number"},
            content=b'{"events":[]}',
        )
        assert response.status_code == 400

    def test_a_normal_sized_batch_still_succeeds(self, client, ingest_headers, seeded_rules):
        """The ceiling must not interfere with realistic traffic."""
        from tests import factories

        events = [factories.failed_login("198.51.100.30", "someone") for _ in range(50)]
        response = client.post("/api/v1/ingest/events",
                               json={"events": events}, headers=ingest_headers)
        assert response.status_code == 202
        assert response.json()["stored"] == 50

    def test_get_requests_are_unaffected(self, client, analyst, as_user):
        assert client.get("/api/v1/alerts", headers=as_user(analyst)).status_code == 200


# --------------------------------------------------------- role boundary spot
def test_role_hierarchy_still_holds_after_the_changes(user_factory, client, as_user):
    """Cheap guard that the auth changes did not disturb authorisation."""
    expectations = {
        Role.VIEWER: 403,
        Role.ANALYST: 403,
        Role.RESPONDER: 403,
        Role.ADMIN: 200,
    }
    for role, expected in expectations.items():
        actor = user_factory(role)
        assert client.get("/api/v1/audit", headers=as_user(actor)).status_code == expected
