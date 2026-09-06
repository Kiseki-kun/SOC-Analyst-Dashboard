"""Server-side sorting: correctness, severity ranking, and the allow-list."""

from __future__ import annotations

from datetime import timedelta

import pytest

from app.schemas.event import RawEventIn
from app.services.ingest import ingest_events
from tests import factories

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


@pytest.fixture
def spread(seeded_rules):
    """Events at distinct timestamps, outcomes and source addresses."""
    db = seeded_rules
    base = factories.now() - timedelta(hours=3)
    batch = []
    for index in range(6):
        batch.append(
            factories.failed_login(f"198.51.100.{index + 1}", f"user{index}",
                                   at=base + timedelta(minutes=index * 10))
        )
    for index in range(4):
        batch.append(
            factories.successful_login(f"10.0.0.{index + 1}", f"staff{index}",
                                       at=base + timedelta(minutes=90 + index * 10))
        )
    ingest_events(db, [RawEventIn(**e) for e in batch])
    return db


class TestEventSorting:
    def test_newest_first_is_the_default(self, client, spread, analyst, as_user):
        items = client.get("/api/v1/events?page_size=50",
                           headers=as_user(analyst)).json()["items"]
        stamps = [i["timestamp"] for i in items]
        assert stamps == sorted(stamps, reverse=True)

    def test_oldest_first(self, client, spread, analyst, as_user):
        items = client.get("/api/v1/events?page_size=50&sort_by=timestamp&sort_dir=asc",
                           headers=as_user(analyst)).json()["items"]
        stamps = [i["timestamp"] for i in items]
        assert stamps == sorted(stamps)

    def test_reversing_direction_reverses_the_result(self, client, spread, analyst, as_user):
        h = as_user(analyst)
        desc = client.get("/api/v1/events?page_size=50&sort_dir=desc", headers=h).json()["items"]
        asc = client.get("/api/v1/events?page_size=50&sort_dir=asc", headers=h).json()["items"]
        assert [i["event_uid"] for i in desc] == [i["event_uid"] for i in asc][::-1]

    def test_sorting_preserves_filters(self, client, spread, analyst, as_user):
        """Changing sort order must not widen the result set."""
        h = as_user(analyst)
        filtered = "/api/v1/events?outcome=failure&page_size=50"
        base = client.get(filtered, headers=h).json()
        sorted_asc = client.get(f"{filtered}&sort_dir=asc", headers=h).json()
        assert base["total"] == sorted_asc["total"] == 6
        assert all(i["outcome"] == "failure" for i in sorted_asc["items"])

    def test_sorting_preserves_search(self, client, spread, analyst, as_user):
        h = as_user(analyst)
        url = "/api/v1/events?username=user3&page_size=50"
        assert client.get(url, headers=h).json()["total"] == 1
        assert client.get(f"{url}&sort_dir=asc", headers=h).json()["total"] == 1

    @pytest.mark.parametrize("field", ["timestamp", "severity", "event_type", "outcome",
                                       "src_ip", "username"])
    def test_every_allow_listed_field_sorts(self, client, spread, analyst, as_user, field):
        for direction in ("asc", "desc"):
            r = client.get(f"/api/v1/events?sort_by={field}&sort_dir={direction}&page_size=50",
                           headers=as_user(analyst))
            assert r.status_code == 200, f"{field}/{direction} -> {r.status_code}"

    @pytest.mark.parametrize(
        "field",
        ["hashed_password", "id; drop table security_events", "raw", "../../etc/passwd", ""],
    )
    def test_fields_outside_the_allow_list_are_rejected(self, client, spread, analyst, as_user, field):
        r = client.get("/api/v1/events", params={"sort_by": field}, headers=as_user(analyst))
        assert r.status_code == 422

    def test_invalid_direction_is_rejected(self, client, spread, analyst, as_user):
        r = client.get("/api/v1/events?sort_dir=sideways", headers=as_user(analyst))
        assert r.status_code == 422

    def test_pagination_is_stable_across_pages(self, client, spread, analyst, as_user):
        """A tie-break on the primary key keeps pages from repeating rows."""
        h = as_user(analyst)
        seen = []
        for page in (1, 2, 3):
            body = client.get(f"/api/v1/events?page_size=4&page={page}&sort_by=severity",
                              headers=h).json()
            seen.extend(i["event_uid"] for i in body["items"])
        assert len(seen) == len(set(seen))


class TestSeverityRanking:
    """Severity is stored as text; sorting it alphabetically is worse than useless."""

    @pytest.fixture
    def alerts_of_every_severity(self, seeded_rules):
        from sqlalchemy import select

        from app.db.base import utcnow
        from app.models.alert import Alert
        from app.models.detection import DetectionRule

        db = seeded_rules
        rule = db.execute(select(DetectionRule)).scalars().first()
        now = utcnow()
        for index, severity in enumerate(["low", "critical", "info", "high", "medium"]):
            db.add(Alert(alert_uid=f"ALT-SEV{index}", rule_id=rule.id, rule_key=rule.rule_key,
                         title=f"{severity} alert", severity=severity, confidence=50,
                         dedup_key=f"sev-{index}", first_seen=now, last_seen=now))
        db.commit()
        return db

    def test_alerts_sort_by_real_severity_not_alphabetically(
        self, client, alerts_of_every_severity, analyst, as_user
    ):
        items = client.get("/api/v1/alerts?sort_by=severity&sort_dir=desc&page_size=20",
                           headers=as_user(analyst)).json()["items"]
        order = [i["severity"] for i in items]
        assert order[0] == "critical", f"expected critical first, got {order}"
        assert order[-1] == "info", f"expected info last, got {order}"
        # Alphabetically this would be critical, high, info, low, medium.
        assert order.index("high") < order.index("medium") < order.index("low")

    def test_ascending_puts_the_least_severe_first(
        self, client, alerts_of_every_severity, analyst, as_user
    ):
        items = client.get("/api/v1/alerts?sort_by=severity&sort_dir=asc&page_size=20",
                           headers=as_user(analyst)).json()["items"]
        order = [i["severity"] for i in items]
        assert order[0] == "info"
        assert order[-1] == "critical"

    def test_events_sort_by_real_severity_too(self, client, spread, analyst, as_user):
        """The same bug existed on the events table and was fixed with it."""
        from app.api.v1.sorting import SEVERITY_RANK

        items = client.get("/api/v1/events?sort_by=severity&sort_dir=desc&page_size=50",
                           headers=as_user(analyst)).json()["items"]
        ranks = [SEVERITY_RANK.get(i["severity"], 0) for i in items]
        assert ranks == sorted(ranks, reverse=True)


class TestAlertSorting:
    @pytest.mark.parametrize("field", ["created_at", "last_seen", "severity", "confidence",
                                       "status", "rule_key", "src_ip"])
    def test_every_allow_listed_alert_field_sorts(self, client, sample_alert, analyst,
                                                  as_user, field):
        for direction in ("asc", "desc"):
            r = client.get(f"/api/v1/alerts?sort_by={field}&sort_dir={direction}",
                           headers=as_user(analyst))
            assert r.status_code == 200

    @pytest.mark.parametrize("field", ["dedup_key", "evidence", "rule_id"])
    def test_non_allow_listed_alert_fields_are_rejected(self, client, sample_alert,
                                                        analyst, as_user, field):
        r = client.get("/api/v1/alerts", params={"sort_by": field}, headers=as_user(analyst))
        assert r.status_code == 422


def test_sort_helpers_cover_every_severity_value():
    """A severity with no rank would silently sort as the lowest."""
    from app.api.v1.sorting import SEVERITY_RANK
    from app.core.enums import Severity

    assert {s.value for s in Severity} == set(SEVERITY_RANK)
