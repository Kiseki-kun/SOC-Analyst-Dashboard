"""Detection rule administration, the IOC watchlist, and audit visibility."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.models.detection import DetectionRule


@pytest.fixture
def rule_id(seeded_rules):
    return str(
        seeded_rules.execute(
            select(DetectionRule).where(DetectionRule.rule_key == "brute_force_authentication")
        ).scalar_one().id
    )


def test_all_eight_rules_are_listed(client, seeded_rules, analyst, as_user):
    r = client.get("/api/v1/detections/rules", headers=as_user(analyst))
    assert r.status_code == 200
    rules = r.json()
    assert len(rules) == 8
    assert all(rule["implemented"] for rule in rules)
    assert all(rule["mitre_technique_id"] for rule in rules)


def test_every_rule_exposes_its_default_config(client, seeded_rules, analyst, as_user):
    """So an operator can see how far a tuned value has drifted."""
    rules = client.get("/api/v1/detections/rules", headers=as_user(analyst)).json()
    for rule in rules:
        assert rule["default_config"], f"{rule['rule_key']} has no default config"


def test_analyst_cannot_modify_a_rule(client, seeded_rules, rule_id, analyst, as_user):
    r = client.patch(f"/api/v1/detections/rules/{rule_id}",
                     json={"enabled": False}, headers=as_user(analyst))
    assert r.status_code == 403


def test_admin_can_tune_a_threshold(client, seeded_rules, rule_id, admin, as_user):
    r = client.patch(
        f"/api/v1/detections/rules/{rule_id}",
        json={"config": {"threshold": 4, "window_minutes": 10, "spray_account_threshold": 3}},
        headers=as_user(admin),
    )
    assert r.status_code == 200
    assert r.json()["config"]["threshold"] == 4


def test_invalid_config_is_rejected_not_stored(client, seeded_rules, rule_id, admin, as_user):
    """A bad threshold must not be persisted where it would silently break detection."""
    r = client.patch(f"/api/v1/detections/rules/{rule_id}",
                     json={"config": {"threshold": -5}}, headers=as_user(admin))
    assert r.status_code == 422

    unchanged = client.get(f"/api/v1/detections/rules/{rule_id}",
                           headers=as_user(admin)).json()
    assert unchanged["config"]["threshold"] > 0


def test_unknown_config_key_is_rejected(client, seeded_rules, rule_id, admin, as_user):
    r = client.patch(
        f"/api/v1/detections/rules/{rule_id}",
        json={"config": {"threshold": 5, "window_minutes": 5,
                         "spray_account_threshold": 5, "typo_field": 1}},
        headers=as_user(admin),
    )
    assert r.status_code == 422


def test_rule_change_is_audited(client, seeded_rules, rule_id, admin, as_user, db_session):
    from app.core.enums import AuditAction
    from app.models.audit import AuditLog

    client.patch(f"/api/v1/detections/rules/{rule_id}",
                 json={"enabled": False}, headers=as_user(admin))
    entry = db_session.execute(
        select(AuditLog).where(AuditLog.action == AuditAction.DETECTION_RULE_UPDATED.value)
    ).scalars().first()
    assert entry is not None
    assert entry.details["rule_key"] == "brute_force_authentication"


# ------------------------------------------------------------------- IOCs
def test_responder_can_add_an_indicator(client, seeded_rules, responder, as_user):
    r = client.post(
        "/api/v1/detections/iocs",
        json={"ioc_type": "ip_address", "value": "203.0.113.200",
              "description": "Observed during INC-2026-0001"},
        headers=as_user(responder),
    )
    assert r.status_code == 201
    assert r.json()["active"] is True


def test_analyst_cannot_add_an_indicator(client, seeded_rules, analyst, as_user):
    r = client.post("/api/v1/detections/iocs",
                    json={"ioc_type": "ip_address", "value": "203.0.113.201"},
                    headers=as_user(analyst))
    assert r.status_code == 403


@pytest.mark.parametrize("value", ["not-an-ip", "999.1.1.1", "10.0.0"])
def test_invalid_ip_indicator_is_rejected(client, seeded_rules, responder, as_user, value):
    r = client.post("/api/v1/detections/iocs",
                    json={"ioc_type": "ip_address", "value": value},
                    headers=as_user(responder))
    assert r.status_code == 422


@pytest.mark.parametrize("value", ["nothex", "abc123", "z" * 64])
def test_invalid_hash_indicator_is_rejected(client, seeded_rules, responder, as_user, value):
    """An indicator that can never match is worse than none: it looks like cover."""
    r = client.post("/api/v1/detections/iocs",
                    json={"ioc_type": "file_hash", "value": value},
                    headers=as_user(responder))
    assert r.status_code == 422


def test_duplicate_indicator_is_rejected(client, seeded_rules, responder, as_user):
    payload = {"ioc_type": "ip_address", "value": "203.0.113.202"}
    assert client.post("/api/v1/detections/iocs", json=payload,
                       headers=as_user(responder)).status_code == 201
    assert client.post("/api/v1/detections/iocs", json=payload,
                       headers=as_user(responder)).status_code == 409


def test_adding_an_ioc_immediately_affects_detection(client, seeded_rules, responder, as_user):
    """The watchlist is live detection input, not a passive list."""
    from app.models.alert import Alert
    from app.schemas.event import RawEventIn
    from app.services.ingest import ingest_events
    from tests import factories

    db = seeded_rules
    digest = "c" * 64

    # Before: the hash means nothing.
    ingest_events(db, [RawEventIn(**factories.process_execution(
        "WKS-99", "user", "thing.exe", "thing.exe", file_hash=digest))])
    assert db.execute(
        select(Alert).where(Alert.rule_key == "malicious_file_hash")
    ).scalars().first() is None

    client.post("/api/v1/detections/iocs",
                json={"ioc_type": "file_hash", "value": digest, "description": "SIMULATED"},
                headers=as_user(responder))

    # After: the same hash on a new event fires.
    ingest_events(db, [RawEventIn(**factories.process_execution(
        "WKS-98", "user", "thing.exe", "thing.exe", file_hash=digest))])
    assert db.execute(
        select(Alert).where(Alert.rule_key == "malicious_file_hash")
    ).scalars().first() is not None


# ------------------------------------------------------------------ audit
def test_only_admin_can_read_the_audit_log(client, seeded_rules, user_factory, as_user):
    from app.core.permissions import Role

    for role in (Role.VIEWER, Role.ANALYST, Role.RESPONDER):
        actor = user_factory(role)
        assert client.get("/api/v1/audit", headers=as_user(actor)).status_code == 403
    admin = user_factory(Role.ADMIN)
    assert client.get("/api/v1/audit", headers=as_user(admin)).status_code == 200


def test_audit_log_has_no_write_endpoints(app):
    """Immutability is enforced by absence, not by a comment."""
    paths = app.openapi()["paths"]
    for path, item in paths.items():
        if path.startswith("/api/v1/audit"):
            assert set(item) <= {"get"}, f"{path} exposes a write method: {set(item)}"


def test_audit_entries_are_filterable_by_action(client, seeded_rules, admin, as_user):
    headers = as_user(admin)
    client.get("/api/v1/audit", headers=headers)
    r = client.get("/api/v1/audit?action=login_success", headers=headers)
    assert r.status_code == 200
    assert all(item["action"] == "login_success" for item in r.json()["items"])


def test_audit_actions_endpoint_lists_observed_actions(client, seeded_rules, admin, as_user):
    r = client.get("/api/v1/audit/actions", headers=as_user(admin))
    assert r.status_code == 200
    assert "login_success" in r.json()
