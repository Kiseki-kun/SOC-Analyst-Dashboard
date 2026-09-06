"""Shared FastAPI dependencies: authentication, authorization, pagination.

Authorization is expressed as `Depends(require(Permission.X))`. A route that
forgets to declare one is unauthenticated by construction and will fail the
route-coverage test in tests/security/, rather than quietly shipping open.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Query, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.enums import AuditAction
from app.core.logging import get_logger
from app.core.permissions import Permission
from app.core.security import (
    TOKEN_TYPE_ACCESS,
    compare_secret,
    decode_token,
)
from app.db.session import get_db
from app.models.user import User
from app.services import audit

logger = get_logger(__name__)

# auto_error=False so a missing header produces our own 401 with a consistent
# body, instead of FastAPI's default shape.
_bearer = HTTPBearer(auto_error=False, description="JWT access token")

SettingsDep = Annotated[Settings, Depends(get_settings)]
DbDep = Annotated[Session, Depends(get_db)]

_UNAUTHENTICATED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    # One message for every authentication failure — expired, malformed, wrong
    # type, unknown user, deactivated. Distinguishing them would let an
    # unauthenticated caller enumerate valid accounts.
    detail="Not authenticated.",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_current_user(
    request: Request,
    db: DbDep,
    settings: SettingsDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None,
) -> User:
    if credentials is None or not credentials.credentials:
        raise _UNAUTHENTICATED

    payload = decode_token(
        credentials.credentials, settings, expected_type=TOKEN_TYPE_ACCESS
    )
    if payload is None:
        raise _UNAUTHENTICATED

    try:
        import uuid as _uuid

        user_id = _uuid.UUID(payload.subject)
    except (ValueError, AttributeError):
        raise _UNAUTHENTICATED from None

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise _UNAUTHENTICATED

    # Reject tokens minted before the user's last credential change. This is
    # what makes `token_version` an actual revocation mechanism rather than an
    # unused column that merely looks like one.
    if payload.token_version != user.token_version:
        raise _UNAUTHENTICATED

    # The role is re-read from the database rather than trusted from the token.
    # An admin demoted five minutes ago must lose access immediately, not when
    # their access token happens to expire.
    request.state.current_user = user
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


@dataclass(frozen=True, slots=True)
class PermissionChecker:
    """Callable dependency that enforces one permission."""

    permission: Permission

    def __call__(self, request: Request, db: DbDep, user: CurrentUser) -> User:
        if not user.has_permission(self.permission):
            # A denied attempt by an authenticated user is a security event in
            # its own right: it is how privilege probing becomes visible.
            audit.record(
                db,
                action=AuditAction.UNAUTHORIZED_ACCESS_ATTEMPT,
                actor=user,
                success=False,
                request=request,
                details={
                    "required_permission": str(self.permission),
                    "endpoint": request.url.path,
                    "method": request.method,
                },
            )
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action.",
            )
        return user


def require(permission: Permission):
    """Build an authorization dependency for `permission`.

    Usage — note the annotation is the plain model type, not `CurrentUser`:

        def endpoint(db: DbDep, actor: User = require(Permission.ALERT_TRIAGE)):

    `CurrentUser` is already `Annotated[User, Depends(...)]`, and FastAPI
    rejects a parameter that carries a dependency in both the annotation and
    the default. The checker returns the authenticated user, so the plain
    annotation loses nothing.
    """
    return Depends(PermissionChecker(permission))


def require_ingest_key(
    request: Request,
    settings: SettingsDep,
) -> None:
    """Authenticate the generator service to the ingest endpoint.

    A shared secret rather than a user account: the generator is a machine with
    exactly one capability, and giving it a JWT would mean giving it a user row
    that could be assigned incidents. Compared in constant time.
    """
    provided = request.headers.get("x-ingest-key", "")
    if not provided or not compare_secret(provided, settings.INGEST_API_KEY):
        logger.warning("ingest.auth_failed", path=request.url.path)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid ingest credentials.",
        )


@dataclass(frozen=True, slots=True)
class Pagination:
    page: int
    page_size: int

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


def pagination_params(
    settings: SettingsDep,
    page: Annotated[int, Query(ge=1, le=10_000)] = 1,
    page_size: Annotated[int | None, Query(ge=1, le=200)] = None,
) -> Pagination:
    """Bounded pagination.

    page_size is capped server-side. An unbounded limit is a denial-of-service
    primitive: one request for 10,000,000 events would exhaust memory.
    """
    effective = page_size or settings.DEFAULT_PAGE_SIZE
    return Pagination(page=page, page_size=min(effective, settings.MAX_PAGE_SIZE))


PaginationDep = Annotated[Pagination, Depends(pagination_params)]
