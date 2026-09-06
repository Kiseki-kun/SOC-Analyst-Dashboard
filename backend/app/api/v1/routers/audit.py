"""Audit log. Read-only, administrator-gated.

There is deliberately no create, update or delete endpoint. Records are written
only by `app.services.audit.record`, inside the transaction of the action being
audited. An API that could edit the audit trail would defeat its purpose.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import func, select

from app.api.deps import DbDep, PaginationDep, require
from app.core.permissions import Permission
from app.models.audit import AuditLog
from app.models.user import User
from app.schemas.audit import AuditLogRead
from app.schemas.common import Page

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=Page[AuditLogRead])
def list_audit_logs(
    db: DbDep,
    pagination: PaginationDep,
    _: User = require(Permission.AUDIT_READ),
    action: Annotated[list[str] | None, Query()] = None,
    actor_id: uuid.UUID | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    success: bool | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
) -> Page[AuditLogRead]:
    def apply(stmt):
        if action:
            stmt = stmt.where(AuditLog.action.in_(action))
        if actor_id:
            stmt = stmt.where(AuditLog.actor_id == actor_id)
        if resource_type:
            stmt = stmt.where(AuditLog.resource_type == resource_type)
        if resource_id:
            stmt = stmt.where(AuditLog.resource_id == resource_id)
        if success is not None:
            stmt = stmt.where(AuditLog.success.is_(success))
        if start is not None:
            stmt = stmt.where(AuditLog.timestamp >= start)
        if end is not None:
            stmt = stmt.where(AuditLog.timestamp <= end)
        return stmt

    total = db.execute(apply(select(func.count()).select_from(AuditLog))).scalar_one()
    rows = (
        db.execute(
            apply(select(AuditLog))
            .order_by(AuditLog.timestamp.desc(), AuditLog.id)
            .offset(pagination.offset)
            .limit(pagination.page_size)
        )
        .scalars()
        .all()
    )
    return Page.build(
        [AuditLogRead.model_validate(r) for r in rows], total, pagination.page, pagination.page_size
    )


@router.get("/actions", response_model=list[str])
def list_audit_actions(
    db: DbDep,
    _: User = require(Permission.AUDIT_READ),
) -> list[str]:
    """Distinct actions present in the log, for populating a filter control."""
    return sorted(
        row[0] for row in db.execute(select(AuditLog.action).group_by(AuditLog.action)).all()
    )
