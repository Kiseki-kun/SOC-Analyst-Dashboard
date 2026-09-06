"""Event explorer: filtering, sorting, pagination, and injection safety."""

from __future__ import annotations

from datetime import timedelta

import pytest

from app.schemas.event import RawEventIn
from app.services.ingest import ingest_events
from tests import factories


@pytest.fixture
def events(seeded_rules):
    db = seeded_rules
    base = factories.now() - timedelta(hours=2)
    batch = []
    for index in range(12):
        batch.append(factories.failed_login("198.51.100.5", "alice", at=base + timedelta(minutes=index)))
    for index in range(8):
        batch.append(factories.successful_login("10.0.0.20", "bob", at=base + timedelta(minutes=index)))
    for index in range(10):
        batch.append(factories.connection("10.0.0.21", "10.20.0.9", 8443 + index, at=base + timedelta(minutes=index)))
    batch.append(factories.http_request("10.0.0.22", "/reports/quarterly-summary.pdf"))
    ingest_events(db, [RawEventIn(**e) for e in batch])
    return db


def test_lists_events_with_a_real_total(client, events, analyst, as_user):
    body = client.get("/api/v1/events?page_size=5", headers=as_user(analyst)).json()
    assert body["total"] == 31
    assert len(body["items"]) == 5
    assert body["pages"] == 7


def test_pagination_does_not_repeat_or_skip_rows(client, events, analyst, as_user):
    """A tie-break on the primary key is what makes this hold."""
    headers = as_user(analyst)
    seen: list[str] = []
    for page in range(1, 5):
        body = client.get(f"/api/v1/events?page_size=10&page={page}", headers=headers).json()
        seen.extend(item["event_uid"] for item in body["items"])
    assert len(seen) == len(set(seen)), "pagination returned duplicate rows"
    assert len(seen) == 31


def test_filters_by_event_type(client, events, analyst, as_user):
    body = client.get("/api/v1/events?event_type=authentication", headers=as_user(analyst)).json()
    assert body["total"] == 20
    assert all(item["event_type"] == "authentication" for item in body["items"])


def test_filters_by_outcome(client, events, analyst, as_user):
    body = client.get("/api/v1/events?outcome=failure", headers=as_user(analyst)).json()
    assert body["total"] == 12


def test_filters_by_source_address(client, events, analyst, as_user):
    body = client.get("/api/v1/events?src_ip=198.51.100.5", headers=as_user(analyst)).json()
    assert body["total"] == 12
    assert all(item["src_ip"] == "198.51.100.5" for item in body["items"])


def test_filters_by_username(client, events, analyst, as_user):
    body = client.get("/api/v1/events?username=bob", headers=as_user(analyst)).json()
    assert body["total"] == 8


def test_combines_filters_conjunctively(client, events, analyst, as_user):
    body = client.get(
        "/api/v1/events?event_type=authentication&outcome=success&username=bob",
        headers=as_user(analyst),
    ).json()
    assert body["total"] == 8


def test_search_matches_across_text_fields(client, events, analyst, as_user):
    body = client.get("/api/v1/events?search=quarterly", headers=as_user(analyst)).json()
    assert body["total"] == 1
    assert "quarterly" in body["items"][0]["url_path"]


@pytest.mark.parametrize(
    "term",
    ["' OR 1=1--", "'; DROP TABLE security_events;--", "%", "_", "\\", "100%"],
)
def test_search_terms_are_bound_not_interpolated(client, events, analyst, as_user, term):
    """A quote must be a literal; a wildcard must not become a wildcard."""
    response = client.get("/api/v1/events", params={"search": term}, headers=as_user(analyst))
    assert response.status_code == 200
    # `%` alone would match everything if the term were not escaped.
    assert response.json()["total"] < 31


def test_the_table_still_exists_after_injection_attempts(client, events, analyst, as_user):
    body = client.get("/api/v1/events", headers=as_user(analyst)).json()
    assert body["total"] == 31


def test_time_range_filter(client, events, analyst, as_user):
    cutoff = (factories.now() - timedelta(minutes=30)).isoformat()
    # Passed via `params` so the "+" in the UTC offset is percent-encoded. In a
    # raw query string "+" decodes as a space and the timestamp fails to parse —
    # which is correct HTTP behaviour, and the reason the frontend builds every
    # query with URLSearchParams rather than string concatenation.
    response = client.get("/api/v1/events", params={"start": cutoff}, headers=as_user(analyst))
    assert response.status_code == 200, response.text
    assert response.json()["total"] == 1  # only the HTTP request is recent


def test_unencoded_timezone_offset_is_rejected_rather_than_misread(
    client, events, analyst, as_user
):
    """A malformed timestamp must fail loudly, not silently match everything."""
    cutoff = (factories.now() - timedelta(minutes=30)).isoformat()  # contains "+00:00"
    response = client.get(f"/api/v1/events?start={cutoff}", headers=as_user(analyst))
    assert response.status_code == 422


def test_sorting_by_timestamp_ascending_and_descending(client, events, analyst, as_user):
    headers = as_user(analyst)
    newest = client.get("/api/v1/events?sort_dir=desc&page_size=50", headers=headers).json()
    oldest = client.get("/api/v1/events?sort_dir=asc&page_size=50", headers=headers).json()
    assert newest["items"][0]["timestamp"] >= newest["items"][-1]["timestamp"]
    assert oldest["items"][0]["timestamp"] <= oldest["items"][-1]["timestamp"]
    assert newest["items"][0]["event_uid"] != oldest["items"][0]["event_uid"]


def test_sort_column_is_restricted_to_an_allow_list(client, events, analyst, as_user):
    """An arbitrary column name from the query string is rejected by validation."""
    response = client.get("/api/v1/events?sort_by=hashed_password", headers=as_user(analyst))
    assert response.status_code == 422


def test_page_size_is_capped_server_side(client, events, analyst, as_user):
    """An unbounded limit is a denial-of-service primitive."""
    assert client.get("/api/v1/events?page_size=100000", headers=as_user(analyst)).status_code == 422


def test_event_detail_includes_the_raw_document(client, events, analyst, as_user):
    headers = as_user(analyst)
    listed = client.get("/api/v1/events?page_size=1", headers=headers).json()["items"][0]
    detail = client.get(f"/api/v1/events/{listed['id']}", headers=headers).json()
    assert detail["raw"]
    assert detail["analyzed"] is True


def test_unknown_event_returns_404(client, events, analyst, as_user):
    response = client.get(
        "/api/v1/events/00000000-0000-0000-0000-000000000123", headers=as_user(analyst)
    )
    assert response.status_code == 404


def test_malformed_uuid_is_rejected_cleanly(client, events, analyst, as_user):
    response = client.get("/api/v1/events/not-a-uuid", headers=as_user(analyst))
    assert response.status_code == 422


def test_viewer_can_read_events(client, events, viewer, as_user):
    assert client.get("/api/v1/events", headers=as_user(viewer)).status_code == 200
