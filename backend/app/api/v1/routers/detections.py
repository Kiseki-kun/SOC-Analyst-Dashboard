"""Detection rule configuration and the IOC watchlist."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.api.deps import DbDep, PaginationDep, require
from app.core.enums import AuditAction, IOCType
from app.core.permissions import Permission
from app.detection.registry import get_rule
from app.models.audit import IOCWatchlistEntry
from app.models.detection import DetectionRule
from app.models.user import User
from app.schemas.common import Page
from app.schemas.detection import (
    DetectionRuleDetail,
    DetectionRuleRead,
    DetectionRuleUpdate,
    IOCCreate,
    IOCRead,
    IOCUpdate,
)
from app.services import audit
from app.services.investigation import is_valid_ip

router = APIRouter(prefix="/detections", tags=["detections"])


def _detail(rule: DetectionRule) -> DetectionRuleDetail:
    rule_cls = get_rule(rule.rule_key)
    return DetectionRuleDetail(
        **DetectionRuleRead.model_validate(rule).model_dump(),
        default_config=rule_cls.default_config() if rule_cls else {},
        # False when a row exists but no code implements it — visible in the
        # UI rather than silently never firing.
        implemented=rule_cls is not None,
    )


@router.get("/rules", response_model=list[DetectionRuleDetail])
def list_rules(
    db: DbDep,
    _: User = require(Permission.DETECTION_READ),
) -> list[DetectionRuleDetail]:
    rules = db.execute(select(DetectionRule).order_by(DetectionRule.name)).scalars().all()
    return [_detail(r) for r in rules]


@router.get("/rules/{rule_id}", response_model=DetectionRuleDetail)
def get_rule_detail(
    rule_id: uuid.UUID,
    db: DbDep,
    _: User = require(Permission.DETECTION_READ),
) -> DetectionRuleDetail:
    rule = db.get(DetectionRule, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Detection rule not found.")
    return _detail(rule)


@router.patch("/rules/{rule_id}", response_model=DetectionRuleDetail)
def update_rule(
    rule_id: uuid.UUID,
    payload: DetectionRuleUpdate,
    request: Request,
    db: DbDep,
    actor: User = require(Permission.DETECTION_MANAGE),
) -> DetectionRuleDetail:
    rule = db.get(DetectionRule, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Detection rule not found.")

    changes: dict[str, object] = {}

    if payload.config is not None:
        rule_cls = get_rule(rule.rule_key)
        if rule_cls is None:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "This rule has no implementation, so its configuration cannot be validated.",
            )
        try:
            # Validated against the rule's own schema, which rejects unknown
            # keys and out-of-range thresholds. Storing an unvalidated blob
            # would let one bad value silently disable a detection.
            validated = rule_cls.config_model(**payload.config)
        except Exception as exc:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"Invalid configuration for this rule: {exc}",
            ) from None
        rule.config = validated.model_dump()
        changes["field"] = "config"

    if payload.enabled is not None and payload.enabled != rule.enabled:
        rule.enabled = payload.enabled
        changes["field"] = "enabled"
    if payload.severity is not None:
        rule.severity = payload.severity.value
        changes["severity"] = rule.severity

    audit.record(
        db,
        action=AuditAction.DETECTION_RULE_UPDATED,
        actor=actor,
        resource_type="detection_rule",
        resource_id=rule.id,
        request=request,
        details={"rule_key": rule.rule_key, **changes},
    )
    db.commit()
    db.refresh(rule)
    return _detail(rule)


# ------------------------------------------------------------------- IOCs
@router.get("/iocs", response_model=Page[IOCRead])
def list_iocs(
    db: DbDep,
    pagination: PaginationDep,
    _: User = require(Permission.DETECTION_READ),
    ioc_type: IOCType | None = None,
    active: bool | None = None,
) -> Page[IOCRead]:
    from sqlalchemy import func

    def apply(stmt):
        if ioc_type is not None:
            stmt = stmt.where(IOCWatchlistEntry.ioc_type == ioc_type.value)
        if active is not None:
            stmt = stmt.where(IOCWatchlistEntry.active.is_(active))
        return stmt

    total = db.execute(apply(select(func.count()).select_from(IOCWatchlistEntry))).scalar_one()
    rows = (
        db.execute(
            apply(select(IOCWatchlistEntry))
            .order_by(IOCWatchlistEntry.created_at.desc())
            .offset(pagination.offset)
            .limit(pagination.page_size)
        )
        .scalars()
        .all()
    )
    return Page.build(
        [IOCRead.model_validate(r) for r in rows], total, pagination.page, pagination.page_size
    )


@router.post("/iocs", response_model=IOCRead, status_code=status.HTTP_201_CREATED)
def create_ioc(
    payload: IOCCreate,
    request: Request,
    db: DbDep,
    actor: User = require(Permission.IOC_MANAGE),
) -> IOCRead:
    value = payload.value.strip()

    # Type-appropriate validation. An "IP" indicator that is not an address
    # would never match anything and would quietly sit there looking useful.
    if payload.ioc_type is IOCType.IP_ADDRESS and not is_valid_ip(value):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Not a valid IP address.")
    if payload.ioc_type is IOCType.FILE_HASH:
        value = value.lower()
        if len(value) not in (32, 40, 64) or not all(c in "0123456789abcdef" for c in value):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "File hash must be a hexadecimal MD5, SHA-1 or SHA-256 digest.",
            )

    entry = IOCWatchlistEntry(
        ioc_type=payload.ioc_type.value,
        value=value,
        description=payload.description,
        active=True,
        added_by_id=actor.id,
        added_by_email=actor.email,
    )
    db.add(entry)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "That indicator is already on the watchlist."
        ) from None

    audit.record(
        db, action=AuditAction.IOC_ADDED, actor=actor,
        resource_type="ioc", resource_id=entry.id, request=request,
        details={"ioc_type": entry.ioc_type, "ioc_value": entry.value},
    )
    db.commit()
    db.refresh(entry)
    return IOCRead.model_validate(entry)


@router.patch("/iocs/{ioc_id}", response_model=IOCRead)
def update_ioc(
    ioc_id: uuid.UUID,
    payload: IOCUpdate,
    request: Request,
    db: DbDep,
    actor: User = require(Permission.IOC_MANAGE),
) -> IOCRead:
    entry = db.get(IOCWatchlistEntry, ioc_id)
    if entry is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Indicator not found.")

    if payload.active is not None:
        entry.active = payload.active
    if payload.description is not None:
        entry.description = payload.description

    audit.record(
        db,
        # Deactivation is recorded as a removal: the row is retained for
        # history, but the indicator has stopped being enforced.
        action=AuditAction.IOC_REMOVED if payload.active is False else AuditAction.IOC_ADDED,
        actor=actor, resource_type="ioc", resource_id=entry.id, request=request,
        details={"ioc_type": entry.ioc_type, "ioc_value": entry.value},
    )
    db.commit()
    db.refresh(entry)
    return IOCRead.model_validate(entry)
