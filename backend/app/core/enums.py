"""Domain enumerations.

`StrEnumCompat` rather than `enum.StrEnum`: StrEnum requires Python 3.11, and
while the container runs 3.13, the test environment available during
development is 3.10. Subclassing `(str, Enum)` behaves identically for every
use here — comparison, serialisation, Pydantic coercion, SQLAlchemy storage —
and keeps the code runnable on both.
"""

from __future__ import annotations

from enum import Enum


class StrEnumCompat(str, Enum):
    """String enum whose `str()` is the bare value on every Python version."""

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def values(cls) -> list[str]:
        return [member.value for member in cls]


class Severity(StrEnumCompat):
    """Shared severity scale for events, alerts and incidents.

    One scale across all three so "critical" means the same thing everywhere and
    the dashboard can colour them from a single ramp.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER: dict[str, int] = {
    Severity.CRITICAL.value: 4,
    Severity.HIGH.value: 3,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 1,
    Severity.INFO.value: 0,
}


class EventSource(StrEnumCompat):
    """Where a raw event claims to come from."""

    AUTH = "auth"
    FIREWALL = "firewall"
    DNS = "dns"
    WEB_PROXY = "web_proxy"
    ENDPOINT = "endpoint"
    SYSTEM = "system"
    FILE = "file"


class EventType(StrEnumCompat):
    """Normalized event category. Detection rules match on this, not on source."""

    AUTHENTICATION = "authentication"
    NETWORK_CONNECTION = "network_connection"
    DNS_QUERY = "dns_query"
    HTTP_REQUEST = "http_request"
    FILE_ACCESS = "file_access"
    PROCESS_EXECUTION = "process_execution"
    PRIVILEGE_CHANGE = "privilege_change"
    SYSTEM_EVENT = "system_event"


class EventOutcome(StrEnumCompat):
    SUCCESS = "success"
    FAILURE = "failure"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


class AlertStatus(StrEnumCompat):
    NEW = "new"
    IN_REVIEW = "in_review"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


# Statuses that mean an analyst has finished with the alert.
ALERT_TERMINAL_STATUSES = frozenset(
    {AlertStatus.RESOLVED.value, AlertStatus.FALSE_POSITIVE.value}
)


class IncidentStatus(StrEnumCompat):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


INCIDENT_TERMINAL_STATUSES = frozenset(
    {IncidentStatus.RESOLVED.value, IncidentStatus.CLOSED.value}
)


class ResponseActionType(StrEnumCompat):
    """Simulated containment actions.

    Every one of these records an intent in this application's database and
    does nothing else. No network, host, account or file on any real system is
    touched — see docs/security.md.
    """

    SIMULATED_IP_BLOCK = "simulated_ip_block"
    SIMULATED_ACCOUNT_DISABLE = "simulated_account_disable"
    SIMULATED_HOST_ISOLATION = "simulated_host_isolation"
    SIMULATED_CREDENTIAL_RESET = "simulated_credential_reset"
    ADD_IOC_TO_WATCHLIST = "add_ioc_to_watchlist"


class IOCType(StrEnumCompat):
    IP_ADDRESS = "ip_address"
    FILE_HASH = "file_hash"
    DOMAIN = "domain"
    URL = "url"


class AuditAction(StrEnumCompat):
    """Auditable actions. Kept as an enum so the audit log is queryable."""

    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    TOKEN_REFRESH = "token_refresh"
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DEACTIVATED = "user_deactivated"
    USER_ROLE_CHANGED = "user_role_changed"
    PASSWORD_CHANGED = "password_changed"
    ALERT_STATUS_CHANGED = "alert_status_changed"
    ALERT_ASSIGNED = "alert_assigned"
    ALERT_NOTE_ADDED = "alert_note_added"
    ALERT_LINKED_TO_INCIDENT = "alert_linked_to_incident"
    INCIDENT_CREATED = "incident_created"
    INCIDENT_UPDATED = "incident_updated"
    INCIDENT_ASSIGNED = "incident_assigned"
    INCIDENT_STATUS_CHANGED = "incident_status_changed"
    INCIDENT_NOTE_ADDED = "incident_note_added"
    RESPONSE_ACTION_SIMULATED = "response_action_simulated"
    DETECTION_RULE_UPDATED = "detection_rule_updated"
    IOC_ADDED = "ioc_added"
    IOC_REMOVED = "ioc_removed"
    UNAUTHORIZED_ACCESS_ATTEMPT = "unauthorized_access_attempt"
