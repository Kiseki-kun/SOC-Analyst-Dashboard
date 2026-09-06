"""Normalization: different dialects in, one schema out."""

from __future__ import annotations

import pytest

from app.core.enums import EventOutcome, EventType
from app.schemas.event import RawEventIn
from app.services.normalization import normalize
from tests import factories


def _normalize(raw: dict):
    return normalize(RawEventIn(**raw))


def test_auth_source_maps_to_authentication():
    result = _normalize(factories.failed_login("198.51.100.7", "jdoe"))
    assert result.event_type is EventType.AUTHENTICATION
    assert result.outcome is EventOutcome.FAILURE
    assert result.username == "jdoe"
    assert result.src_ip == "198.51.100.7"


@pytest.mark.parametrize(
    "field_name",
    ["username", "user", "user_name", "account", "subject_account", "client_user"],
)
def test_username_is_reconciled_across_source_vocabularies(field_name):
    """The whole point of normalization: rules see one field name."""
    raw = factories.raw_event("auth", {"action": "login", "outcome": "success", field_name: "alice"})
    assert _normalize(raw).username == "alice"


@pytest.mark.parametrize(
    "raw_outcome,expected",
    [
        ("success", EventOutcome.SUCCESS),
        ("Accepted", EventOutcome.SUCCESS),  # case-insensitive vocabulary match
        ("allowed", EventOutcome.SUCCESS),
        ("failure", EventOutcome.FAILURE),
        ("DENIED", EventOutcome.FAILURE),
        ("blocked", EventOutcome.BLOCKED),
        ("something-else", EventOutcome.UNKNOWN),
    ],
)
def test_outcome_vocabulary_is_normalised(raw_outcome, expected):
    raw = factories.raw_event("auth", {"action": "login", "outcome": raw_outcome})
    assert _normalize(raw).outcome is expected


def test_invalid_ip_addresses_are_discarded_not_stored():
    """src_ip feeds dedup keys and the UI; it must never hold arbitrary text."""
    raw = factories.raw_event("auth", {"action": "login", "src_ip": "not-an-ip", "outcome": "failure"})
    assert _normalize(raw).src_ip is None


def test_out_of_range_ports_are_discarded():
    raw = factories.raw_event("firewall", {"action": "allow", "dst_port": 99999, "src_ip": "10.0.0.1"})
    assert _normalize(raw).dst_port is None


def test_control_characters_are_stripped_from_text_fields():
    """Log injection: a newline in a username can forge a second log line."""
    raw = factories.raw_event(
        "auth", {"action": "login", "username": "admin\n2026-01-01 FAKE LOG LINE", "outcome": "failure"}
    )
    username = _normalize(raw).username
    assert "\n" not in username


def test_malformed_hash_is_rejected():
    raw = factories.process_execution("host1", "u", "x.exe", "x", file_hash="not-a-hash")
    assert _normalize(raw).file_hash is None


def test_valid_hash_is_lowercased():
    digest = "A" * 64
    raw = factories.process_execution("host1", "u", "x.exe", "x", file_hash=digest)
    assert _normalize(raw).file_hash == "a" * 64


def test_out_of_range_coordinates_are_discarded():
    raw = factories.successful_login("10.0.0.1", "u", geo={"lat": 999.0, "lon": 0.0, "country": "GB"})
    result = _normalize(raw)
    assert result.latitude is None


def test_url_path_is_preserved_verbatim_for_detection():
    """Sanitising here would destroy the evidence web-attack rules match on."""
    hostile = "/index.php?id=1' UNION SELECT password FROM users--"
    result = _normalize(factories.http_request("203.0.113.9", hostile))
    assert result.url_path == hostile


def test_raw_payload_is_preserved():
    raw = factories.failed_login("198.51.100.7", "jdoe")
    assert _normalize(raw).raw == raw["payload"]


def test_unknown_source_is_rejected_cleanly():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        _normalize({"event_uid": "x", "source": "mainframe", "timestamp": factories.now().isoformat(), "payload": {}})
