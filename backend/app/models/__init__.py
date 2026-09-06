"""SQLAlchemy models.

Importing this package registers every mapper on `Base.metadata`, which is what
Alembic autogenerate and `create_all` rely on. Import order matters only in that
all models must be imported before either is used.
"""

from app.models.alert import Alert, AlertNote, alert_events
from app.models.audit import AuditLog, IOCWatchlistEntry
from app.models.detection import DetectionRule
from app.models.event import SecurityEvent
from app.models.incident import (
    Incident,
    IncidentNote,
    IncidentTimelineEntry,
    ResponseAction,
)
from app.models.user import User

__all__ = [
    "Alert",
    "AlertNote",
    "AuditLog",
    "DetectionRule",
    "IOCWatchlistEntry",
    "Incident",
    "IncidentNote",
    "IncidentTimelineEntry",
    "ResponseAction",
    "SecurityEvent",
    "User",
    "alert_events",
]
