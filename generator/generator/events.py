"""Raw event builders.

These emit the *source-native* shapes on purpose — the auth log says `user`,
the proxy says `client_user` — so the backend's normalization layer is actually
exercised rather than being handed pre-normalized data.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone
from typing import Any

from generator import world


def _uid() -> str:
    return f"evt-{uuid.uuid4().hex[:20]}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _event(source: str, payload: dict[str, Any], at: datetime | None = None) -> dict:
    return {
        "event_uid": _uid(),
        "source": source,
        "timestamp": at.isoformat() if at else _now(),
        "payload": payload,
    }


def _geo(rng: random.Random, key: str | None = None, *, user: str | None = None) -> dict:
    """Resolve a location.

    Precedence: an explicit key (used by scenarios), then the user's stable
    home office, then a random home office for events with no account.
    """
    if key is None and user is not None:
        key = world.home_location_for(user)
    location = world.LOCATIONS[key or rng.choice(world.HOME_LOCATIONS)]
    return {
        "city": location.city,
        "country": location.country,
        "lat": location.lat,
        "lon": location.lon,
    }


def internal_ip(rng: random.Random) -> str:
    return world.INTERNAL_SUBNET.format(octet=rng.randint(1, 8), host=rng.randint(2, 250))


def external_ip(rng: random.Random, hostile: bool = False) -> str:
    template = world.EXTERNAL_HOSTILE if hostile else world.EXTERNAL_BENIGN
    return template.format(host=rng.randint(2, 250))


# ------------------------------------------------------------------- benign
def auth_success(rng: random.Random, user: str | None = None, *, location: str | None = None,
                 src_ip: str | None = None, at: datetime | None = None) -> dict:
    user = user or rng.choice(world.USERS)
    return _event("auth", {
        "action": "login",
        "result": "success",          # the auth source says "result"
        "user": user,                 # ...and "user"
        "src_ip": src_ip or internal_ip(rng),
        "dst_ip": rng.choice(["10.20.0.10", "10.20.0.11"]),
        "service": rng.choice(["sshd", "kerberos", "vpn", "webauth"]),
        "geo": _geo(rng, location, user=user),
        "message": f"Accepted credentials for {user}",
    }, at)


def auth_failure(rng: random.Random, user: str | None = None, *, src_ip: str | None = None,
                 location: str | None = None, at: datetime | None = None) -> dict:
    user = user or rng.choice(world.USERS)
    return _event("auth", {
        "action": "login",
        "result": "failure",
        "user": user,
        "src_ip": src_ip or internal_ip(rng),
        "dst_ip": "10.20.0.10",
        "service": rng.choice(["sshd", "webauth"]),
        "geo": _geo(rng, location, user=user),
        "message": f"Failed password for {user}",
    }, at)


def network_connection(rng: random.Random, *, src_ip: str | None = None, dst_ip: str | None = None,
                       dst_port: int | None = None, action: str = "allow",
                       at: datetime | None = None) -> dict:
    return _event("firewall", {
        "action": action,
        "source_ip": src_ip or internal_ip(rng),   # firewall says "source_ip"
        "destination_ip": dst_ip or internal_ip(rng),
        "destination_port": dst_port or rng.choice(world.COMMON_PORTS),
        "source_port": rng.randint(49152, 65535),
        "proto": rng.choice(["tcp", "udp"]),
        "bytes_out": rng.randint(200, 90000),
        "bytes_in": rng.randint(200, 900000),
    }, at)


def dns_query(rng: random.Random, *, domain: str | None = None, src_ip: str | None = None,
              at: datetime | None = None) -> dict:
    return _event("dns", {
        "qname": domain or rng.choice(world.BENIGN_DOMAINS),
        "src_ip": src_ip or internal_ip(rng),
        "dst_ip": "10.20.0.53",
        "rcode": "success",
        "host": rng.choice(world.WORKSTATIONS),
    }, at)


def http_request(rng: random.Random, *, url: str | None = None, src_ip: str | None = None,
                 status: int | None = None, at: datetime | None = None) -> dict:
    return _event("web_proxy", {
        "http_method": rng.choice(["GET", "GET", "GET", "POST"]),
        "uri": url or rng.choice(world.BENIGN_URLS),   # proxy says "uri"
        "status_code": status or rng.choice([200, 200, 200, 204, 301, 404]),
        "client_ip": src_ip or internal_ip(rng),
        "server_ip": "10.20.0.80",
        "client_user": rng.choice(world.USERS),
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SyntheticBrowser/1.0",
        "host": rng.choice(world.SERVERS),
    }, at)


def process_execution(rng: random.Random, *, process: str | None = None, command: str | None = None,
                      hostname: str | None = None, username: str | None = None,
                      file_hash: str | None = None, at: datetime | None = None) -> dict:
    if process is None or command is None:
        process, command = rng.choice(world.BENIGN_PROCESSES)
    payload = {
        "action": "process_start",
        "image": process,                     # endpoint agent says "image"
        "cmdline": command,
        "computer": hostname or rng.choice(world.WORKSTATIONS),
        "subject_account": username or rng.choice(world.USERS),
        "result": "success",
    }
    if file_hash:
        payload["sha256"] = file_hash
    return _event("endpoint", payload, at)


def file_access(rng: random.Random, *, at: datetime | None = None) -> dict:
    return _event("file", {
        "operation": rng.choice(["read", "write", "open"]),
        "path": rng.choice([
            "\\\\SRV-FILE-01\\Finance\\budget.xlsx",
            "\\\\SRV-FILE-01\\HR\\handbook.docx",
            "C:\\Users\\Public\\report.pdf",
        ]),
        "account": rng.choice(world.USERS),
        "device": rng.choice(world.WORKSTATIONS),
        "result": "success",
    }, at)


def system_event(rng: random.Random, *, at: datetime | None = None) -> dict:
    return _event("system", {
        "event": rng.choice(["service_start", "service_stop", "time_sync", "update_installed"]),
        "computer": rng.choice(world.SERVERS + world.WORKSTATIONS),
        "result": "success",
        "message": "Routine system activity",
    }, at)


def privilege_change(rng: random.Random, *, username: str, group: str, hostname: str,
                     outcome: str = "success", at: datetime | None = None) -> dict:
    return _event("endpoint", {
        "action": "privilege_change",
        "computer": hostname,
        "subject_account": username,
        "group": group,
        "result": outcome,
        "cmdline": f'net localgroup "{group}" {username} /add',
        "message": f"{username} added to {group}",
    }, at)
