"""Audit log schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from app.schemas.common import ORMModel


class AuditLogRead(ORMModel):
    id: uuid.UUID
    timestamp: datetime
    actor_email: str | None
    actor_role: str | None
    action: str
    resource_type: str | None
    resource_id: str | None
    success: bool
    ip_address: str | None
    details: dict[str, Any]
