"""Detection rule modules.

Importing this package registers every rule. A rule that is not imported here
does not exist as far as the engine is concerned, so this list is the
authoritative inventory of detections.
"""

from app.detection.rules import (
    brute_force,
    impossible_travel,
    malicious_hash,
    port_scan,
    privilege_escalation,
    suspicious_login,
    suspicious_powershell,
    web_attack,
)

__all__ = [
    "brute_force",
    "impossible_travel",
    "malicious_hash",
    "port_scan",
    "privilege_escalation",
    "suspicious_login",
    "suspicious_powershell",
    "web_attack",
]
