"""Event normalization.

Each source speaks its own dialect: the auth log says `user`, the proxy says
`client_user`, the endpoint agent says `subject_account`. Detection rules must
not know or care. A normalizer per source maps its dialect onto
`NormalizedEvent`, and rules are written against that one schema.

Adding a log source is therefore a normalizer plus a registry entry — no
detection rule is touched, and none of them regress.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from typing import Any

from app.core.enums import EventOutcome, EventSource, EventType, Severity
from app.core.logging import get_logger
from app.schemas.event import NormalizedEvent, RawEventIn

logger = get_logger(__name__)


class NormalizationError(ValueError):
    """Raised when a payload cannot be mapped onto the normalized schema."""


# --------------------------------------------------------------------- helpers
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-\.]{0,126})$")
_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32,64}$")


def _first(payload: dict[str, Any], *names: str) -> Any:
    """Return the first present, non-empty value among `names`.

    This is what absorbs vocabulary differences between sources.
    """
    for name in names:
        value = payload.get(name)
        if value not in (None, ""):
            return value
    return None


def _clean_ip(value: Any) -> str | None:
    """Return a valid IP string, or None.

    Validation is not cosmetic: `src_ip` is used to build alert dedup keys and
    is displayed to analysts. Accepting arbitrary text would let a malformed
    source inject content into both.
    """
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _clean_port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def _clean_str(value: Any, max_length: int) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    # Strip control characters: they serve no purpose in a log field and are
    # the raw material for log-injection and terminal-escape tricks.
    text = "".join(ch for ch in text if ch == "\t" or ch >= " ")
    return text[:max_length] or None


def _clean_hostname(value: Any) -> str | None:
    text = _clean_str(value, 128)
    if text and _HOSTNAME_RE.match(text):
        return text
    return text[:128] if text else None


def _clean_hash(value: Any) -> str | None:
    text = _clean_str(value, 64)
    if text and _HASH_RE.match(text):
        return text.lower()
    return None


def _outcome(value: Any) -> EventOutcome:
    text = str(value or "").strip().lower()
    if text in {"success", "succeeded", "allow", "allowed", "accept", "accepted", "ok", "true"}:
        return EventOutcome.SUCCESS
    if text in {"failure", "failed", "fail", "denied", "deny", "reject", "rejected", "false"}:
        return EventOutcome.FAILURE
    if text in {"blocked", "block", "quarantined", "dropped"}:
        return EventOutcome.BLOCKED
    return EventOutcome.UNKNOWN


def _geo(payload: dict[str, Any]) -> dict[str, Any]:
    geo = payload.get("geo") or {}
    if not isinstance(geo, dict):
        geo = {}
    country = _clean_str(_first(geo, "country", "country_code") or payload.get("country_code"), 2)
    latitude = geo.get("lat", geo.get("latitude", payload.get("latitude")))
    longitude = geo.get("lon", geo.get("longitude", payload.get("longitude")))
    try:
        latitude = float(latitude) if latitude is not None else None
        longitude = float(longitude) if longitude is not None else None
    except (TypeError, ValueError):
        latitude = longitude = None
    if latitude is not None and not -90 <= latitude <= 90:
        latitude = None
    if longitude is not None and not -180 <= longitude <= 180:
        longitude = None
    return {
        "country_code": country.upper() if country else None,
        "city": _clean_str(_first(geo, "city") or payload.get("city"), 64),
        "latitude": latitude,
        "longitude": longitude,
    }


def _base(raw: RawEventIn, **kwargs: Any) -> NormalizedEvent:
    payload = raw.payload
    return NormalizedEvent(
        event_uid=raw.event_uid,
        timestamp=raw.timestamp,
        source=raw.source.value,
        src_ip=_clean_ip(_first(payload, "src_ip", "source_ip", "client_ip", "remote_addr")),
        dst_ip=_clean_ip(_first(payload, "dst_ip", "destination_ip", "server_ip", "target_ip")),
        src_port=_clean_port(_first(payload, "src_port", "source_port", "client_port")),
        dst_port=_clean_port(_first(payload, "dst_port", "destination_port", "server_port", "port")),
        protocol=_clean_str(_first(payload, "protocol", "proto", "transport"), 16),
        username=_clean_str(
            _first(payload, "username", "user", "user_name", "account", "subject_account", "client_user"),
            128,
        ),
        hostname=_clean_hostname(
            _first(payload, "hostname", "host", "computer", "device", "asset")
        ),
        raw=payload,
        **_geo(payload),
        **kwargs,
    )


# ----------------------------------------------------------------- normalizers
def normalize_auth(raw: RawEventIn) -> NormalizedEvent:
    p = raw.payload
    outcome = _outcome(_first(p, "outcome", "result", "status", "auth_result"))
    event = _base(
        raw,
        event_type=EventType.AUTHENTICATION,
        action=_clean_str(_first(p, "action", "event"), 64) or "login",
        outcome=outcome,
        severity=Severity.MEDIUM if outcome is EventOutcome.FAILURE else Severity.INFO,
        message=_clean_str(_first(p, "message", "msg"), 2000)
        or f"Authentication {outcome.value}",
    )
    event.process_name = _clean_str(_first(p, "service", "process", "app"), 128)
    return event


def normalize_firewall(raw: RawEventIn) -> NormalizedEvent:
    p = raw.payload
    outcome = _outcome(_first(p, "action", "disposition", "outcome"))
    return _base(
        raw,
        event_type=EventType.NETWORK_CONNECTION,
        action=_clean_str(_first(p, "action", "disposition"), 64) or "connection",
        outcome=outcome,
        severity=Severity.LOW if outcome is EventOutcome.BLOCKED else Severity.INFO,
        message=_clean_str(_first(p, "message", "msg"), 2000) or "Network connection",
        bytes_sent=_clean_port_free(_first(p, "bytes_sent", "bytes_out")),
        bytes_received=_clean_port_free(_first(p, "bytes_received", "bytes_in")),
    )


def _clean_port_free(value: Any) -> int | None:
    """Non-negative integer, unbounded by the port range."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def normalize_dns(raw: RawEventIn) -> NormalizedEvent:
    p = raw.payload
    event = _base(
        raw,
        event_type=EventType.DNS_QUERY,
        action="dns_query",
        outcome=_outcome(_first(p, "outcome", "response_code", "rcode")),
        severity=Severity.INFO,
        message=_clean_str(_first(p, "message"), 2000) or "DNS query",
    )
    event.dns_query = _clean_str(_first(p, "query", "domain", "qname"), 255)
    event.protocol = event.protocol or "udp"
    return event


def normalize_web_proxy(raw: RawEventIn) -> NormalizedEvent:
    p = raw.payload
    status_code = _clean_port_free(_first(p, "status", "http_status", "status_code"))
    event = _base(
        raw,
        event_type=EventType.HTTP_REQUEST,
        action=_clean_str(_first(p, "method", "http_method"), 10) or "GET",
        outcome=EventOutcome.SUCCESS
        if status_code and status_code < 400
        else EventOutcome.FAILURE,
        severity=Severity.INFO,
        message=_clean_str(_first(p, "message"), 2000) or "HTTP request",
    )
    event.http_method = _clean_str(_first(p, "method", "http_method"), 10)
    # Kept verbatim: this is the field web-attack detections inspect, and
    # sanitising it here would destroy the evidence. It is escaped at render
    # time by React, never interpolated into SQL.
    event.url_path = _clean_str(_first(p, "url", "path", "uri", "request_uri"), 4096)
    event.http_status = status_code
    event.user_agent = _clean_str(_first(p, "user_agent", "ua"), 1000)
    return event


def normalize_endpoint(raw: RawEventIn) -> NormalizedEvent:
    p = raw.payload
    action = _clean_str(_first(p, "action", "event_action"), 64) or "process_start"
    is_privilege = action in {"privilege_change", "group_add", "sudo", "role_assignment"}
    event = _base(
        raw,
        event_type=EventType.PRIVILEGE_CHANGE if is_privilege else EventType.PROCESS_EXECUTION,
        action=action,
        outcome=_outcome(_first(p, "outcome", "result")),
        severity=Severity.MEDIUM if is_privilege else Severity.INFO,
        message=_clean_str(_first(p, "message"), 2000) or "Endpoint activity",
    )
    event.process_name = _clean_str(_first(p, "process", "process_name", "image"), 128)
    event.command_line = _clean_str(_first(p, "command_line", "cmdline", "command"), 4096)
    event.file_hash = _clean_hash(_first(p, "hash", "sha256", "md5", "file_hash"))
    event.file_path = _clean_str(_first(p, "file_path", "path", "image_path"), 4096)
    return event


def normalize_file(raw: RawEventIn) -> NormalizedEvent:
    p = raw.payload
    event = _base(
        raw,
        event_type=EventType.FILE_ACCESS,
        action=_clean_str(_first(p, "action", "operation"), 64) or "read",
        outcome=_outcome(_first(p, "outcome", "result")),
        severity=Severity.INFO,
        message=_clean_str(_first(p, "message"), 2000) or "File access",
    )
    event.file_path = _clean_str(_first(p, "file_path", "path", "file"), 4096)
    event.file_hash = _clean_hash(_first(p, "hash", "sha256", "file_hash"))
    return event


def normalize_system(raw: RawEventIn) -> NormalizedEvent:
    p = raw.payload
    return _base(
        raw,
        event_type=EventType.SYSTEM_EVENT,
        action=_clean_str(_first(p, "action", "event"), 64) or "system",
        outcome=_outcome(_first(p, "outcome", "result")),
        severity=Severity.INFO,
        message=_clean_str(_first(p, "message"), 2000) or "System event",
    )


NORMALIZERS: dict[str, Callable[[RawEventIn], NormalizedEvent]] = {
    EventSource.AUTH.value: normalize_auth,
    EventSource.FIREWALL.value: normalize_firewall,
    EventSource.DNS.value: normalize_dns,
    EventSource.WEB_PROXY.value: normalize_web_proxy,
    EventSource.ENDPOINT.value: normalize_endpoint,
    EventSource.FILE.value: normalize_file,
    EventSource.SYSTEM.value: normalize_system,
}


def normalize(raw: RawEventIn) -> NormalizedEvent:
    normalizer = NORMALIZERS.get(raw.source.value)
    if normalizer is None:
        raise NormalizationError(f"No normalizer registered for source '{raw.source}'")
    try:
        return normalizer(raw)
    except NormalizationError:
        raise
    except Exception as exc:
        # One malformed event must never take down an ingest batch.
        raise NormalizationError(f"Failed to normalize {raw.event_uid}: {exc}") from exc
