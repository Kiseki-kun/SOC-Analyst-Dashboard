"""Analytics and IP investigation.

The recurring assertion here is that every number is derived from stored rows.
A dashboard figure that cannot be traced to data is a liability.
"""

from __future__ import annotations

import random

import pytest
from sqlalchemy import select

from app.models.event import SecurityEvent
from app.schemas.event import RawEventIn
from app.services.ingest import ingest_events
from tests import factories


@pytest.fixture
def populated(seeded_rules):
    """A realistic mix: benign noise plus two attacks from one address."""
    import sys
    from pathlib import Path

    generator_root = Path(__file__).resolve().parents[3] / "generator"
    if str(generator_root) not in sys.path:
        sys.path.insert(0, str(generator_root))
    from generator import scenarios

    db = seeded_rules
    rng = random.Random("analytics")
    ingest_events(db, [RawEventIn(**e) for e in scenarios.benign_batch(rng, 150)])
    ingest_events(db, [RawEventIn(**factories.failed_login("203.0.113.77", "victim")) for _ in range(15)])
    ingest_events(db, [
        RawEventIn(**factories.connection("203.0.113.77", "10.20.0.5", port))
        for port in range(3000, 3030)
    ])
    return db


def test_summary_counts_match_the_database(client, populated, analyst, as_user):
    r = client.get("/api/v1/analytics/summary", headers=as_user(analyst))
    assert r.status_code == 200
    body = r.json()

    actual_events = populated.execute(
        select(SecurityEvent).with_only_columns(SecurityEvent.id)
    ).all()
    assert body["total_events"] == len(actual_events)
    assert body["events_last_24h"] == len(actual_events)
    assert body["open_alerts"] >= 2


def test_summary_is_readable_by_a_viewer(client, populated, viewer, as_user):
    assert client.get("/api/v1/analytics/summary", headers=as_user(viewer)).status_code == 200


def test_overview_returns_every_section(client, populated, analyst, as_user):
    r = client.get("/api/v1/analytics/overview", headers=as_user(analyst))
    assert r.status_code == 200
    body = r.json()
    for section in (
        "summary", "events_over_time", "alerts_over_time", "authentication_trend",
        "top_source_ips", "top_destination_ips", "top_detection_rules",
        "mitre_distribution", "attack_categories", "event_type_distribution",
        "response_metrics",
    ):
        assert section in body, f"missing analytics section: {section}"


def test_top_source_ips_ranks_the_attacker_first(client, populated, analyst, as_user):
    body = client.get("/api/v1/analytics/overview", headers=as_user(analyst)).json()
    assert body["top_source_ips"][0]["ip"] == "203.0.113.77"
    assert body["top_source_ips"][0]["failure_count"] >= 15


def test_mitre_distribution_uses_real_technique_ids(client, populated, analyst, as_user):
    body = client.get("/api/v1/analytics/overview", headers=as_user(analyst)).json()
    ids = {e["technique_id"] for e in body["mitre_distribution"]}
    assert ids, "no MITRE techniques recorded"
    assert {"T1110", "T1046"} & ids
    for entry in body["mitre_distribution"]:
        assert entry["technique_id"].startswith("T")


def test_mean_time_metrics_are_null_not_zero_when_unmeasured(client, populated, analyst, as_user):
    """An average over no incidents is undefined, not zero."""
    body = client.get("/api/v1/analytics/overview", headers=as_user(analyst)).json()
    metrics = body["response_metrics"]
    assert metrics["mean_time_to_resolve_minutes"] is None
    assert metrics["incidents_resolved"] == 0


def test_mean_time_metrics_populate_once_an_incident_is_resolved(
    client, populated, responder, as_user
):
    headers = as_user(responder)
    created = client.post("/api/v1/incidents",
                          json={"title": "Measured incident", "severity": "high"},
                          headers=headers)
    incident_id = created.json()["id"]
    client.patch(f"/api/v1/incidents/{incident_id}", json={"status": "investigating"},
                 headers=headers)
    client.patch(f"/api/v1/incidents/{incident_id}",
                 json={"status": "resolved", "resolution_summary": "Contained and closed."},
                 headers=headers)

    metrics = client.get("/api/v1/analytics/overview", headers=headers).json()["response_metrics"]
    assert metrics["incidents_resolved"] == 1
    assert metrics["mean_time_to_resolve_minutes"] is not None
    assert metrics["mean_time_to_acknowledge_minutes"] is not None


def test_time_series_buckets_are_ordered(client, populated, analyst, as_user):
    body = client.get("/api/v1/analytics/overview", headers=as_user(analyst)).json()
    buckets = [p["bucket"] for p in body["events_over_time"]]
    assert buckets == sorted(buckets)
    assert sum(p["count"] for p in body["events_over_time"]) > 0


# ------------------------------------------------------------- investigation
def test_ip_investigation_aggregates_activity(client, populated, analyst, as_user):
    r = client.get("/api/v1/investigations/ip/203.0.113.77", headers=as_user(analyst))
    assert r.status_code == 200
    body = r.json()
    assert body["summary"]["failed_authentications"] == 15
    assert body["summary"]["distinct_destination_ports"] == 30
    assert "victim" in body["associated_usernames"]
    assert body["related_alerts"]


def test_reputation_is_labelled_as_local_only(client, populated, analyst, as_user):
    """The verdict must never look like external threat intelligence."""
    body = client.get("/api/v1/investigations/ip/203.0.113.77",
                      headers=as_user(analyst)).json()
    assert body["reputation"]["source"] == "local_synthetic_data_only"
    assert body["reputation"]["verdict"] in ("benign", "suspicious", "malicious")
    assert body["reputation"]["basis"], "verdict given with no stated basis"


def test_hostile_address_scores_worse_than_a_quiet_one(client, populated, analyst, as_user):
    headers = as_user(analyst)
    hostile = client.get("/api/v1/investigations/ip/203.0.113.77", headers=headers).json()
    quiet = client.get("/api/v1/investigations/ip/192.0.2.200", headers=headers).json()
    assert hostile["reputation"]["score"] > quiet["reputation"]["score"]
    assert quiet["reputation"]["verdict"] == "benign"


def test_unseen_address_returns_an_empty_but_valid_profile(client, populated, analyst, as_user):
    body = client.get("/api/v1/investigations/ip/192.0.2.201", headers=as_user(analyst)).json()
    assert body["summary"]["total_events"] == 0
    assert body["related_alerts"] == []
    assert body["reputation"]["verdict"] == "benign"


@pytest.mark.parametrize("bad", ["not-an-ip", "999.999.999.999", "'; DROP TABLE events;--"])
def test_invalid_address_is_rejected(client, populated, analyst, as_user, bad):
    r = client.get(f"/api/v1/investigations/ip/{bad}", headers=as_user(analyst))
    assert r.status_code == 400


def test_investigation_requires_authentication(client, populated):
    assert client.get("/api/v1/investigations/ip/203.0.113.77").status_code == 401
