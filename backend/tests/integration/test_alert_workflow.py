"""Alert triage: the path an analyst actually walks."""

from __future__ import annotations


def test_alert_list_returns_the_detected_alert(client, sample_alert, analyst, as_user):
    r = client.get("/api/v1/alerts", headers=as_user(analyst))
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["rule_key"] == "brute_force_authentication"


def test_alert_detail_includes_evidence_and_linked_events(client, sample_alert, analyst, as_user):
    r = client.get(f"/api/v1/alerts/{sample_alert.id}", headers=as_user(analyst))
    assert r.status_code == 200
    body = r.json()
    assert body["evidence"]["failure_count"] == 12
    assert len(body["events"]) == 12
    assert body["mitre_technique_id"] == "T1110"


def test_viewer_can_read_but_not_triage(client, sample_alert, viewer, as_user):
    headers = as_user(viewer)
    assert client.get(f"/api/v1/alerts/{sample_alert.id}", headers=headers).status_code == 200
    r = client.patch(f"/api/v1/alerts/{sample_alert.id}/status",
                     json={"status": "in_review"}, headers=headers)
    assert r.status_code == 403


def test_analyst_can_move_an_alert_to_in_review(client, sample_alert, analyst, as_user):
    r = client.patch(f"/api/v1/alerts/{sample_alert.id}/status",
                     json={"status": "in_review"}, headers=as_user(analyst))
    assert r.status_code == 200
    assert r.json()["status"] == "in_review"


def test_closing_an_alert_requires_a_resolution_note(client, sample_alert, analyst, as_user):
    """Closing without reasoning is not triage, it is deletion with extra steps."""
    r = client.patch(f"/api/v1/alerts/{sample_alert.id}/status",
                     json={"status": "resolved"}, headers=as_user(analyst))
    assert r.status_code == 400
    assert "resolution note" in r.json()["detail"].lower()


def test_closing_an_alert_with_a_note_succeeds_and_stamps_the_time(
    client, sample_alert, analyst, as_user
):
    r = client.patch(
        f"/api/v1/alerts/{sample_alert.id}/status",
        json={"status": "false_positive",
              "resolution_note": "Known internal scanner, confirmed with the platform team."},
        headers=as_user(analyst),
    )
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "false_positive"
    assert body["resolved_at"] is not None
    assert body["resolution_note"].startswith("Known internal scanner")


def test_alert_can_be_assigned_and_unassigned(client, sample_alert, analyst, as_user):
    r = client.patch(f"/api/v1/alerts/{sample_alert.id}/assign",
                     json={"assignee_id": str(analyst.id)}, headers=as_user(analyst))
    assert r.status_code == 200
    assert r.json()["assigned_to"]["email"] == analyst.email

    r = client.patch(f"/api/v1/alerts/{sample_alert.id}/assign",
                     json={"assignee_id": None}, headers=as_user(analyst))
    assert r.json()["assigned_to"] is None


def test_cannot_assign_an_alert_to_someone_who_cannot_triage(
    client, sample_alert, analyst, viewer, as_user
):
    """A queue assigned to someone without permission never moves."""
    r = client.patch(f"/api/v1/alerts/{sample_alert.id}/assign",
                     json={"assignee_id": str(viewer.id)}, headers=as_user(analyst))
    assert r.status_code == 400


def test_notes_are_attributed_and_ordered(client, sample_alert, analyst, as_user):
    headers = as_user(analyst)
    for body in ("Reviewed source address.", "Confirmed against asset inventory."):
        assert client.post(f"/api/v1/alerts/{sample_alert.id}/notes",
                           json={"body": body}, headers=headers).status_code == 201

    detail = client.get(f"/api/v1/alerts/{sample_alert.id}", headers=headers).json()
    assert [n["body"] for n in detail["notes"]] == [
        "Reviewed source address.", "Confirmed against asset inventory."
    ]
    assert all(n["author_email"] == analyst.email for n in detail["notes"])


def test_viewer_cannot_add_notes(client, sample_alert, viewer, as_user):
    r = client.post(f"/api/v1/alerts/{sample_alert.id}/notes",
                    json={"body": "should not persist"}, headers=as_user(viewer))
    assert r.status_code == 403


def test_empty_note_is_rejected(client, sample_alert, analyst, as_user):
    r = client.post(f"/api/v1/alerts/{sample_alert.id}/notes",
                    json={"body": "   "}, headers=as_user(analyst))
    assert r.status_code in (400, 422)


def test_alert_filtering_by_severity_and_status(client, sample_alert, analyst, as_user):
    headers = as_user(analyst)
    assert client.get("/api/v1/alerts?severity=high", headers=headers).json()["total"] == 1
    assert client.get("/api/v1/alerts?severity=low", headers=headers).json()["total"] == 0
    assert client.get("/api/v1/alerts?status=new", headers=headers).json()["total"] == 1
    assert client.get("/api/v1/alerts?status=resolved", headers=headers).json()["total"] == 0


def test_alert_search_is_parameterised_against_injection(client, sample_alert, analyst, as_user):
    """A quote in the search box must be a literal, not a syntax error."""
    r = client.get("/api/v1/alerts?search=' OR 1=1--", headers=as_user(analyst))
    assert r.status_code == 200
    assert r.json()["total"] == 0


def test_severity_sorting_is_by_rank_not_alphabetical(client, seeded_rules, analyst, as_user):
    """Alphabetically, 'critical' < 'high' < 'info' - useless in a triage queue."""
    from sqlalchemy import select

    from app.db.base import utcnow
    from app.models.alert import Alert
    from app.models.detection import DetectionRule

    db = seeded_rules
    # Alerts are built directly here so every severity level is represented;
    # the detection engine would not produce an "info" alert on demand.
    rule = db.execute(select(DetectionRule)).scalars().first()
    now = utcnow()
    for index, severity in enumerate(["low", "critical", "info", "high", "medium"]):
        db.add(Alert(
            alert_uid=f"ALT-SORT{index}", rule_id=rule.id, rule_key=rule.rule_key,
            title=f"{severity} alert", severity=severity, confidence=50,
            dedup_key=f"sort-{index}", first_seen=now, last_seen=now,
        ))
    db.commit()

    r = client.get("/api/v1/alerts?sort_by=severity&sort_dir=desc&page_size=10",
                   headers=as_user(analyst))
    order = [a["severity"] for a in r.json()["items"]]
    assert order[0] == "critical"
    assert order[-1] == "info"
