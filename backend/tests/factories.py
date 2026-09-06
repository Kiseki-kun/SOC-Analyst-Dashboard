"""Builders for synthetic raw events, matching the generator's wire format."""

from __future__ import annotations

import itertools
from datetime import datetime, timezone
from typing import Any

_counter = itertools.count(1)


def uid(prefix: str = "evt") -> str:
    return f"{prefix}-{next(_counter):08d}"


def now() -> datetime:
    return datetime.now(timezone.utc)


def raw_event(source: str, payload: dict[str, Any], *, at: datetime | None = None) -> dict:
    return {
        "event_uid": uid(),
        "source": source,
        "timestamp": (at or now()).isoformat(),
        "payload": payload,
    }


def failed_login(src_ip: str, username: str, *, at: datetime | None = None) -> dict:
    return raw_event(
        "auth",
        {
            "action": "login",
            "outcome": "failure",
            "username": username,
            "src_ip": src_ip,
            "dst_ip": "10.20.0.10",
            "service": "sshd",
            "message": f"Failed password for {username}",
        },
        at=at,
    )


def successful_login(
    src_ip: str,
    username: str,
    *,
    at: datetime | None = None,
    geo: dict[str, Any] | None = None,
) -> dict:
    payload: dict[str, Any] = {
        "action": "login",
        "outcome": "success",
        "username": username,
        "src_ip": src_ip,
        "dst_ip": "10.20.0.10",
        "service": "sshd",
        "message": f"Accepted password for {username}",
    }
    if geo:
        payload["geo"] = geo
    return raw_event("auth", payload, at=at)


def connection(src_ip: str, dst_ip: str, dst_port: int, *, at: datetime | None = None) -> dict:
    return raw_event(
        "firewall",
        {
            "action": "allow",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "src_port": 44321,
            "protocol": "tcp",
        },
        at=at,
    )


def http_request(src_ip: str, path: str, *, at: datetime | None = None) -> dict:
    return raw_event(
        "web_proxy",
        {
            "method": "GET",
            "url": path,
            "status": 200,
            "src_ip": src_ip,
            "dst_ip": "10.20.0.80",
            "user_agent": "Mozilla/5.0 (synthetic)",
        },
        at=at,
    )


def process_execution(
    hostname: str, username: str, process: str, command_line: str,
    *, file_hash: str | None = None, at: datetime | None = None,
) -> dict:
    payload = {
        "action": "process_start",
        "process": process,
        "command_line": command_line,
        "hostname": hostname,
        "username": username,
        "outcome": "success",
    }
    if file_hash:
        payload["sha256"] = file_hash
    return raw_event("endpoint", payload, at=at)


def privilege_change(
    hostname: str, username: str, group: str, *, outcome: str = "success",
    at: datetime | None = None,
) -> dict:
    return raw_event(
        "endpoint",
        {
            "action": "privilege_change",
            "hostname": hostname,
            "username": username,
            "group": group,
            "outcome": outcome,
            "command_line": f"net localgroup \"{group}\" {username} /add",
            "message": f"{username} added to {group}",
        },
        at=at,
    )
