"""User administration. Every route here requires an admin-level permission."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import func, select

from app.api.deps import DbDep, PaginationDep, SettingsDep, require
from app.core.enums import AuditAction
from app.core.permissions import Permission, Role, can_manage_user
from app.core.security import hash_password
from app.models.user import User
from app.schemas.common import Page
from app.schemas.user import UserCreate, UserRead, UserUpdate
from app.services import audit

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=Page[UserRead])
def list_users(
    db: DbDep,
    pagination: PaginationDep,
    _: User = require(Permission.USER_READ),
) -> Page[UserRead]:
    total = db.execute(select(func.count()).select_from(User)).scalar_one()
    rows = (
        db.execute(
            select(User)
            .order_by(User.created_at.desc())
            .offset(pagination.offset)
            .limit(pagination.page_size)
        )
        .scalars()
        .all()
    )
    return Page.build(
        [UserRead.model_validate(r) for r in rows],
        total,
        pagination.page,
        pagination.page_size,
    )


@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    request: Request,
    db: DbDep,
    settings: SettingsDep,
    actor: User = require(Permission.USER_MANAGE),
) -> UserRead:
    """Create a user.

    There is no public registration endpoint. In a SOC platform, accounts are
    provisioned by an administrator — self-registration would let anyone who can
    reach the login page create themselves a viewer account and read security
    telemetry.
    """
    if not can_manage_user(actor.role, payload.role):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Cannot create a user of that role.")

    exists = db.execute(
        select(User.id).where(User.email == payload.email)
    ).scalar_one_or_none()
    if exists:
        # 409 rather than a 200 that silently does nothing. This endpoint is
        # admin-only, so confirming an address is in use is not an enumeration
        # risk here the way it would be on a public signup form.
        raise HTTPException(status.HTTP_409_CONFLICT, "A user with that email already exists.")

    user = User(
        email=payload.email,
        full_name=payload.full_name,
        role=payload.role.value,
        hashed_password=hash_password(payload.password, settings.BCRYPT_ROUNDS),
    )
    db.add(user)
    db.flush()
    audit.record(
        db,
        action=AuditAction.USER_CREATED,
        actor=actor,
        resource_type="user",
        resource_id=user.id,
        request=request,
        details={"to_role": user.role},
    )
    db.commit()
    return UserRead.model_validate(user)


@router.get("/{user_id}", response_model=UserRead)
def get_user(
    user_id: uuid.UUID,
    db: DbDep,
    _: User = require(Permission.USER_READ),
) -> UserRead:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")
    return UserRead.model_validate(user)


@router.patch("/{user_id}", response_model=UserRead)
def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    request: Request,
    db: DbDep,
    actor: User = require(Permission.USER_MANAGE),
) -> UserRead:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")

    if not can_manage_user(actor.role, user.role):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Cannot modify a user of that role.")

    if payload.role is not None and payload.role.value != user.role:
        if not actor.has_permission(Permission.ROLE_MANAGE):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Cannot change roles.")
        if user.id == actor.id:
            # Prevents an administrator locking the last admin out of the
            # system by demoting themselves.
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Cannot change your own role.")
        previous = user.role
        user.role = payload.role.value
        audit.record(
            db,
            action=AuditAction.USER_ROLE_CHANGED,
            actor=actor,
            resource_type="user",
            resource_id=user.id,
            request=request,
            details={"from_role": previous, "to_role": user.role},
        )

    if payload.full_name is not None:
        user.full_name = payload.full_name

    if payload.is_active is not None and payload.is_active != user.is_active:
        if user.id == actor.id and not payload.is_active:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "Cannot deactivate your own account."
            )
        if not payload.is_active:
            remaining_admins = db.execute(
                select(func.count())
                .select_from(User)
                .where(User.role == Role.ADMIN.value, User.is_active.is_(True), User.id != user.id)
            ).scalar_one()
            if user.role == Role.ADMIN.value and remaining_admins == 0:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    "Cannot deactivate the last active administrator.",
                )
        user.is_active = payload.is_active
        audit.record(
            db,
            action=AuditAction.USER_DEACTIVATED if not payload.is_active else AuditAction.USER_UPDATED,
            actor=actor,
            resource_type="user",
            resource_id=user.id,
            request=request,
        )

    db.commit()
    return UserRead.model_validate(user)
