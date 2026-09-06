"""Every route must be protected.

The first test here is a coverage test rather than a behaviour test: it walks
the live OpenAPI schema and asserts that no endpoint outside a small documented
allow-list can be reached without credentials. A new router added later without
an auth dependency fails here automatically, which is the point — reviewers
forget, tests do not.
"""

from __future__ import annotations

# Endpoints that are unauthenticated by design.
PUBLIC_PATHS = {
    # Container healthcheck: must work before anyone can log in, and reports
    # nothing beyond liveness and database reachability.
    ("GET", "/api/v1/health"),
    ("GET", "/api/v1/health/ready"),
    # Authentication entry points.
    ("POST", "/api/v1/auth/login"),
    # Reads the refresh cookie rather than a bearer token.
    ("POST", "/api/v1/auth/refresh"),
    # Authenticated by a service key header, not a user session.
    ("POST", "/api/v1/ingest/events"),
}

# Placeholder values for path parameters, so a request actually reaches the
# dependency chain rather than failing validation first.
PATH_PARAM_VALUES = {
    "alert_id": "00000000-0000-0000-0000-000000000001",
    "incident_id": "00000000-0000-0000-0000-000000000001",
    "user_id": "00000000-0000-0000-0000-000000000001",
    "event_id": "00000000-0000-0000-0000-000000000001",
    "rule_id": "00000000-0000-0000-0000-000000000001",
    "ioc_id": "00000000-0000-0000-0000-000000000001",
    "ip_address": "203.0.113.1",
}


def _all_operations(app):
    for path, item in app.openapi()["paths"].items():
        for method in item:
            if method.upper() in {"GET", "POST", "PATCH", "PUT", "DELETE"}:
                yield method.upper(), path


def _concrete(path: str) -> str:
    for name, value in PATH_PARAM_VALUES.items():
        path = path.replace("{" + name + "}", value)
    return path


def test_no_endpoint_is_accidentally_public(app, client):
    """The regression guard for the most expensive class of mistake."""
    unprotected: list[str] = []

    for method, path in _all_operations(app):
        if (method, path) in PUBLIC_PATHS:
            continue
        response = client.request(method, _concrete(path), json={})
        # 401 = rejected for lack of credentials (correct).
        # 403 = authenticated-but-forbidden; unreachable here, so also fine.
        # 422 would mean validation ran BEFORE authentication, which leaks the
        # shape of the endpoint to anonymous callers.
        if response.status_code not in (401, 403):
            unprotected.append(f"{method} {path} -> {response.status_code}")

    assert not unprotected, "Endpoints reachable without authentication:\n" + "\n".join(unprotected)


def test_public_endpoints_are_the_documented_ones(app):
    """If a new public endpoint appears, it must be a deliberate decision."""
    operations = set(_all_operations(app))
    for entry in PUBLIC_PATHS:
        assert entry in operations, f"allow-listed endpoint no longer exists: {entry}"


def test_ingest_requires_the_service_key(client):
    payload = {"events": [{"event_uid": "x", "source": "auth",
                           "timestamp": "2026-01-01T00:00:00Z", "payload": {}}]}
    assert client.post("/api/v1/ingest/events", json=payload).status_code == 401


def test_ingest_rejects_a_wrong_service_key(client):
    payload = {"events": [{"event_uid": "x", "source": "auth",
                           "timestamp": "2026-01-01T00:00:00Z", "payload": {}}]}
    response = client.post(
        "/api/v1/ingest/events", json=payload, headers={"X-Ingest-Key": "wrong-key"}
    )
    assert response.status_code == 401


def test_ingest_accepts_the_correct_service_key(client, ingest_headers, seeded_rules):
    payload = {"events": [{
        "event_uid": "route-test-1", "source": "auth",
        "timestamp": "2026-01-01T00:00:00Z",
        "payload": {"action": "login", "outcome": "success", "user": "someone"},
    }]}
    response = client.post("/api/v1/ingest/events", json=payload, headers=ingest_headers)
    assert response.status_code == 202
    assert response.json()["stored"] == 1


def test_a_user_session_cannot_be_used_for_ingest(client, admin, as_user):
    """The ingest key is a separate credential; an admin JWT must not substitute."""
    payload = {"events": [{"event_uid": "y", "source": "auth",
                           "timestamp": "2026-01-01T00:00:00Z", "payload": {}}]}
    assert client.post("/api/v1/ingest/events", json=payload,
                       headers=as_user(admin)).status_code == 401


def test_security_headers_are_present(client):
    response = client.get("/api/v1/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Correlation-ID"]


def test_error_responses_do_not_leak_internals(client):
    """A 404 body must not expose a stack trace, SQL, or a file path."""
    response = client.get("/api/v1/events/00000000-0000-0000-0000-000000000001",
                          headers={"Authorization": "Bearer nope"})
    body = response.text.lower()
    for leak in ("traceback", "sqlalchemy", "/app/", "select ", "psycopg"):
        assert leak not in body, f"response leaked {leak!r}"
