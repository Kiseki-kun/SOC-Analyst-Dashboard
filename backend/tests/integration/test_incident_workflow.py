"""Incident lifecycle, simulated response, and the analyst-to-responder handoff."""

from __future__ import annotations

import pytest


@pytest.fixture
def incident(client, sample_alert, analyst, as_user):
    r = client.post(
        "/api/v1/incidents",
        json={
            "title": "Credential attack against targetuser",
            "description": "Sustained brute force from 203.0.113.99.",
            "severity": "high",
            "alert_ids": [str(sample_alert.id)],
        },
        headers=as_user(analyst),
    )
    assert r.status_code == 201, r.text
    return r.json()


def test_incident_reference_is_human_readable(incident):
    assert incident["incident_uid"].startswith("INC-")
    assert len(incident["incident_uid"].split("-")) == 3


def test_creating_an_incident_attaches_the_alert(incident, sample_alert):
    assert len(incident["alerts"]) == 1
    assert incident["alerts"][0]["id"] == str(sample_alert.id)


def test_creation_seeds_the_timeline(incident):
    kinds = [e["entry_type"] for e in incident["timeline_entries"]]
    assert "created" in kinds
    assert "alert_linked" in kinds


def test_creating_with_an_unknown_alert_is_rejected(client, analyst, as_user, seeded_rules):
    r = client.post(
        "/api/v1/incidents",
        json={"title": "Bogus", "severity": "low",
              "alert_ids": ["00000000-0000-0000-0000-000000000009"]},
        headers=as_user(analyst),
    )
    assert r.status_code == 400


def test_viewer_cannot_create_an_incident(client, viewer, as_user, seeded_rules):
    r = client.post("/api/v1/incidents", json={"title": "Nope", "severity": "low"},
                    headers=as_user(viewer))
    assert r.status_code == 403


def test_status_progression_stamps_lifecycle_timestamps(client, incident, responder, as_user):
    headers = as_user(responder)
    incident_id = incident["id"]

    r = client.patch(f"/api/v1/incidents/{incident_id}",
                     json={"status": "investigating"}, headers=headers)
    assert r.status_code == 200
    assert r.json()["acknowledged_at"] is not None

    r = client.patch(f"/api/v1/incidents/{incident_id}",
                     json={"status": "contained"}, headers=headers)
    assert r.json()["contained_at"] is not None


def test_resolving_requires_a_summary(client, incident, responder, as_user):
    r = client.patch(f"/api/v1/incidents/{incident['id']}",
                     json={"status": "resolved"}, headers=as_user(responder))
    assert r.status_code == 400
    assert "resolution summary" in r.json()["detail"].lower()


def test_resolving_with_a_summary_succeeds(client, incident, responder, as_user):
    r = client.patch(
        f"/api/v1/incidents/{incident['id']}",
        json={"status": "resolved",
              "resolution_summary": "Source address blocked at the perimeter; account reset."},
        headers=as_user(responder),
    )
    assert r.status_code == 200
    assert r.json()["resolved_at"] is not None


def test_analyst_cannot_close_an_incident(client, incident, analyst, as_user):
    """Analysts investigate; closing is a responder decision."""
    r = client.patch(
        f"/api/v1/incidents/{incident['id']}",
        json={"status": "closed", "resolution_summary": "Done."},
        headers=as_user(analyst),
    )
    assert r.status_code == 403


def test_analyst_can_progress_to_investigating(client, incident, analyst, as_user):
    r = client.patch(f"/api/v1/incidents/{incident['id']}",
                     json={"status": "investigating"}, headers=as_user(analyst))
    assert r.status_code == 200


def test_only_responders_can_assign(client, incident, analyst, responder, as_user):
    assert client.patch(f"/api/v1/incidents/{incident['id']}/assign",
                        json={"assignee_id": str(responder.id)},
                        headers=as_user(analyst)).status_code == 403
    r = client.patch(f"/api/v1/incidents/{incident['id']}/assign",
                     json={"assignee_id": str(responder.id)}, headers=as_user(responder))
    assert r.status_code == 200
    assert r.json()["assigned_to"]["email"] == responder.email


def test_cannot_assign_to_a_viewer(client, incident, responder, viewer, as_user):
    r = client.patch(f"/api/v1/incidents/{incident['id']}/assign",
                     json={"assignee_id": str(viewer.id)}, headers=as_user(responder))
    assert r.status_code == 400


def test_notes_appear_on_the_timeline(client, incident, analyst, as_user):
    headers = as_user(analyst)
    assert client.post(f"/api/v1/incidents/{incident['id']}/notes",
                       json={"body": "Confirmed the source is external."},
                       headers=headers).status_code == 201
    detail = client.get(f"/api/v1/incidents/{incident['id']}", headers=headers).json()
    assert len(detail["notes"]) == 1
    assert "note_added" in [e["entry_type"] for e in detail["timeline_entries"]]


# ------------------------------------------------- simulated response actions
def test_analyst_cannot_execute_a_response_action(client, incident, analyst, as_user):
    r = client.post(f"/api/v1/incidents/{incident['id']}/response-actions",
                    json={"action_type": "simulated_ip_block", "target": "203.0.113.99"},
                    headers=as_user(analyst))
    assert r.status_code == 403


def test_responder_can_record_a_simulated_action(client, incident, responder, as_user):
    r = client.post(
        f"/api/v1/incidents/{incident['id']}/response-actions",
        json={"action_type": "simulated_ip_block", "target": "203.0.113.99",
              "note": "Containment pending change approval."},
        headers=as_user(responder),
    )
    assert r.status_code == 201
    body = r.json()
    assert body["simulated"] is True
    assert body["target"] == "203.0.113.99"
    assert body["performed_by_email"] == responder.email


@pytest.mark.parametrize(
    "action_type",
    ["simulated_ip_block", "simulated_account_disable", "simulated_host_isolation",
     "simulated_credential_reset", "add_ioc_to_watchlist"],
)
def test_every_response_action_is_flagged_simulated(client, incident, responder, as_user, action_type):
    """The simulation flag must be impossible to miss on every action type."""
    r = client.post(f"/api/v1/incidents/{incident['id']}/response-actions",
                    json={"action_type": action_type, "target": "test-target"},
                    headers=as_user(responder))
    assert r.status_code == 201
    assert r.json()["simulated"] is True


def test_response_action_appears_on_the_timeline_marked_simulated(
    client, incident, responder, as_user
):
    headers = as_user(responder)
    client.post(f"/api/v1/incidents/{incident['id']}/response-actions",
                json={"action_type": "simulated_host_isolation", "target": "WKS-004"},
                headers=headers)
    detail = client.get(f"/api/v1/incidents/{incident['id']}", headers=headers).json()
    entries = [e for e in detail["timeline_entries"] if e["entry_type"] == "response_action"]
    assert len(entries) == 1
    assert entries[0]["summary"].startswith("SIMULATED")


def test_response_action_is_audited(client, incident, responder, as_user, db_session):
    from sqlalchemy import select

    from app.core.enums import AuditAction
    from app.models.audit import AuditLog

    client.post(f"/api/v1/incidents/{incident['id']}/response-actions",
                json={"action_type": "simulated_ip_block", "target": "203.0.113.99"},
                headers=as_user(responder))
    entry = db_session.execute(
        select(AuditLog).where(AuditLog.action == AuditAction.RESPONSE_ACTION_SIMULATED.value)
    ).scalar_one()
    assert entry.details["target"] == "203.0.113.99"
    assert entry.actor_email == responder.email


def test_incident_uids_increment(client, sample_alert, analyst, as_user):
    uids = []
    for index in range(3):
        r = client.post("/api/v1/incidents",
                        json={"title": f"Incident number {index}", "severity": "low"},
                        headers=as_user(analyst))
        assert r.status_code == 201
        uids.append(r.json()["incident_uid"])
    numbers = [int(u.rsplit("-", 1)[1]) for u in uids]
    assert numbers == sorted(numbers)
    assert len(set(uids)) == 3
