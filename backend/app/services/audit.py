"""Audit logging service.

Single entry point for writing audit records. Nothing else in the codebase
constructs an AuditLog directly, which keeps the redaction rule in one place.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from app.core.enums import AuditAction
from app.core.logging import get_logger
from app.models.audit import AuditLog
from app.models.user import User

logger = get_logger(__name__)

# Only these keys may be stored in an audit record's details blob. An allow-list
# rather than a deny-list: a new field added elsewhere in the codebase cannot
# accidentally leak into the audit trail just because nobody remembered to add
# it to a blocked list.
_ALLOWED_DETAIL_KEYS = frozenset(
    {
        "from_status",
        "to_status",
        "from_role",
        "to_role",
        "severity",
        "assigned_to",
        "alert_uid",
        "incident_uid",
        "rule_key",
        "action_type",
        "target",
        "ioc_type",
        "ioc_value",
        "reason",
        "note_length",
        "count",
        "field",
        "endpoint",
        "method",
        "required_permission",
        "attempted_email",
    }
)


def _client_ip(request: Request | None) -> str | None:
    """Best-effort client IP.

    X-Forwarded-For is read only for its first hop and is not trusted for any
    security decision — it is attacker-controlled. It is recorded for context,
    and `request.client.host` is preferred when present.
    """
    if request is None:
        return None
    if request.client and request.client.host:
        return request.client.host
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()[:45]
    return None


def record(
    db: Session,
    *,
    action: AuditAction | str,
    actor: User | None = None,
    actor_email: str | None = None,
    resource_type: str | None = None,
    resource_id: str | uuid.UUID | None = None,
    success: bool = True,
    request: Request | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """Append one audit record. The caller is responsible for committing.

    Sharing the caller's transaction is intentional: if the action being audited
    rolls back, its audit entry must roll back with it rather than claiming
    something happened that did not.
    """
    safe_details: dict[str, Any] = {}
    if details:
        for key, value in details.items():
            if key in _ALLOWED_DETAIL_KEYS:
                safe_details[key] = value
            else:
                logger.debug("audit.detail_dropped", key=key, action=str(action))

    entry = AuditLog(
        action=str(action),
        actor_id=actor.id if actor else None,
        actor_email=(actor.email if actor else actor_email),
        actor_role=(actor.role if actor else None),
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        success=success,
        ip_address=_client_ip(request),
        user_agent=(request.headers.get("user-agent")[:500] if request and request.headers.get("user-agent") else None),
        details=safe_details,
    )
    db.add(entry)

    logger.info(
        "audit",
        action=str(action),
        actor=entry.actor_email,
        resource=f"{resource_type}:{resource_id}" if resource_type else None,
        success=success,
    )
    return entry
