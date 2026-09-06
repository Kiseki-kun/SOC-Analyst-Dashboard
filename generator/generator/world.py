"""The synthetic environment.

Every address, hostname and account below is invented for this simulation.

IP ranges are drawn from blocks IANA reserves for documentation and testing —
192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 (TEST-NET-1/2/3, RFC 5737) —
plus RFC 1918 private space for the internal network. None of them route on the
public internet, so nothing here can be mistaken for, or point at, a real host.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Location:
    city: str
    country: str
    lat: float
    lon: float


# Locations used for authentication geolocation.
LOCATIONS: dict[str, Location] = {
    "london": Location("London", "GB", 51.5074, -0.1278),
    "manchester": Location("Manchester", "GB", 53.4808, -2.2426),
    "dublin": Location("Dublin", "IE", 53.3498, -6.2603),
    "amsterdam": Location("Amsterdam", "NL", 52.3676, 4.9041),
    "new_york": Location("New York", "US", 40.7128, -74.0060),
    "singapore": Location("Singapore", "SG", 1.3521, 103.8198),
    "sydney": Location("Sydney", "AU", -33.8688, 151.2093),
    "sao_paulo": Location("Sao Paulo", "BR", -23.5505, -46.6333),
    "lagos": Location("Lagos", "NG", 6.5244, 3.3792),
}

# Where staff normally log in from.
HOME_LOCATIONS = ["london", "manchester", "dublin", "amsterdam"]
# Where an account takeover appears from.
FOREIGN_LOCATIONS = ["singapore", "sydney", "sao_paulo", "new_york"]

USERS: list[str] = [
    "a.okafor", "j.doe", "s.patel", "m.oconnell", "r.nakamura",
    "l.dubois", "k.andersson", "t.mensah", "c.rossi", "n.haddad",
    "svc_backup", "svc_scanner", "admin.jsmith",
]

def home_location_for(username: str) -> str:
    """The office a given account normally authenticates from.

    Stable per user, and derived from the name so it needs no shared state
    between the generator loop and the on-demand trigger command.

    This exists because randomising a user's location on every login makes
    ordinary traffic indistinguishable from account takeover: the same account
    appearing in Dublin and Amsterdam seconds apart is *genuinely* impossible
    travel, and the detection rule was correct to say so. People have a usual
    place of work, and benign telemetry has to reflect that for the
    impossible-travel detection to mean anything.
    """
    return HOME_LOCATIONS[sum(username.encode()) % len(HOME_LOCATIONS)]


WORKSTATIONS: list[str] = [f"WKS-{i:03d}" for i in range(1, 26)]
SERVERS: list[str] = [
    "SRV-DC-01", "SRV-DC-02", "SRV-FILE-01", "SRV-WEB-01",
    "SRV-WEB-02", "SRV-DB-01", "SRV-APP-01", "SRV-MAIL-01",
]

INTERNAL_SUBNET = "10.20.{octet}.{host}"
# TEST-NET blocks: reserved for documentation, guaranteed non-routable.
EXTERNAL_BENIGN = "198.51.100.{host}"
EXTERNAL_HOSTILE = "203.0.113.{host}"

BENIGN_DOMAINS = [
    "updates.internal.example", "cdn.example.com", "mail.example.com",
    "portal.example.com", "docs.example.com", "time.example.com",
]
SUSPICIOUS_DOMAINS = [
    "updates.malicious-demo.invalid", "cdn-delivery.suspicious-demo.invalid",
    "sync.exfil-demo.invalid",
]

BENIGN_PROCESSES = [
    ("chrome.exe", "chrome.exe --profile-directory=Default"),
    ("outlook.exe", "outlook.exe /recycle"),
    ("teams.exe", "teams.exe --system-initiated"),
    ("explorer.exe", "explorer.exe"),
    ("powershell.exe", "powershell.exe -Command Get-Service -Name Spooler"),
    ("powershell.exe", "powershell.exe -File C:\\Scripts\\Inventory.ps1"),
    ("sqlservr.exe", "sqlservr.exe -s MSSQLSERVER"),
]

BENIGN_URLS = [
    "/", "/dashboard", "/api/v1/orders?page=2", "/static/app.css",
    "/products?id=4821", "/search?q=quarterly+report", "/health",
    "/api/v1/users/me", "/downloads/handbook.pdf",
]

# Synthetic indicators, matching the seeded watchlist.
MALICIOUS_HASHES = [
    "3f786850e387550fdab836ed7e6dc881de23001b3f786850e387550fdab836ed",
    "a1b2c3d4e5f60718293a4b5c6d7e8f9012a3b4c5d6e7f8091a2b3c4d5e6f7081",
    "0e1d2c3b4a59687776859403a2b1c0d9e8f7a6b5c4d3e2f109182736455463728",
]

PRIVILEGED_GROUPS = ["Domain Admins", "Enterprise Admins", "Administrators", "sudo"]
ORDINARY_GROUPS = ["Printer Users", "Remote Desktop Users", "Finance Readers"]

COMMON_PORTS = [80, 443, 22, 3389, 445, 139, 53, 25, 587, 8080, 1433, 3306]
