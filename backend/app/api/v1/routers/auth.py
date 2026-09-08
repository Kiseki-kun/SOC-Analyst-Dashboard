"""Authentication endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import select

from app.api.deps import CurrentUser, DbDep, SettingsDep
from app.core.config import Settings
from app.core.enums import AuditAction
from app.core.logging import get_logger
from app.core.security import (
    TOKEN_TYPE_REFRESH,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
    waste_password_cycles,
)
from app.db.base import utcnow
from app.models.user import User
from app.schemas.auth import LoginRequest, TokenResponse
from app.schemas.common import MessageResponse
from app.schemas.user import PasswordChange, UserWithPermissions
from app.services import audit
from app.services.throttle import login_throttle

logger = get_logger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

# One message for every credential failure. Saying "no such user" versus
# "wrong password" hands an attacker a free account-enumeration oracle.
_INVALID_CREDENTIALS = "Incorrect email or password."


def _serialise_user(user: User) -> UserWithPermissions:
    return UserWithPermissions(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,  # type: ignore[arg-type]
        is_active=user.is_active,
        last_login_at=user.last_login_at,
        created_at=user.created_at,
        permissions=sorted(str(p) for p in user.permissions),
    )


def _set_refresh_cookie(response: Response, token: str, settings: Settings) -> None:
    response.set_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        value=token,
        # httponly: unreadable from JavaScript, so XSS cannot exfiltrate it.
        httponly=True,
        # Configurable because it depends on deployment topology. "lax" (the
        # default) blocks the basic CSRF shape without breaking a same-site SPA.
        # A separately hosted frontend is cross-site and needs "none", which is
        # only valid alongside Secure - the configuration refuses that pairing.
        samesite=settings.COOKIE_SAMESITE,
        # Only over HTTPS outside local development.
        secure=settings.COOKIE_SECURE,
        # Scoped to the auth routes: the cookie is not attached to every API
        # call, so it is not exposed on endpoints that have no use for it.
        path=f"{settings.API_V1_PREFIX}/auth",
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
    )


@router.post("/login", response_model=TokenResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: DbDep,
    settings: SettingsDep,
) -> TokenResponse:
    """Exchange credentials for an access token and a refresh cookie."""
    client_ip = request.client.host if request.client else "unknown"
    throttle_key = f"{payload.email}|{client_ip}"

    locked, retry_after = login_throttle.is_locked(throttle_key)
    if locked:
        audit.record(
            db,
            action=AuditAction.LOGIN_FAILURE,
            actor_email=payload.email,
            success=False,
            request=request,
            details={"reason": "rate_limited"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    user = db.execute(
        select(User).where(User.email == payload.email)
    ).scalar_one_or_none()

    if user is None:
        # Spend comparable CPU so response time does not reveal whether the
        # account exists.
        # Same cost factor real passwords use; a cheaper dummy hash would
        # make 'no such account' measurably faster.
        waste_password_cycles(settings.BCRYPT_ROUNDS)
        login_throttle.record_failure(throttle_key)
        audit.record(
            db,
            action=AuditAction.LOGIN_FAILURE,
            actor_email=payload.email,
            success=False,
            request=request,
            details={"reason": "unknown_account"},
        )
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _INVALID_CREDENTIALS)

    if not verify_password(payload.password, user.hashed_password):
        login_throttle.record_failure(throttle_key)
        audit.record(
            db,
            action=AuditAction.LOGIN_FAILURE,
            actor=user,
            success=False,
            request=request,
            details={"reason": "bad_password"},
        )
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _INVALID_CREDENTIALS)

    if not user.is_active:
        # Same message and status as bad credentials: a deactivated account
        # should not be distinguishable from a non-existent one.
        login_throttle.record_failure(throttle_key)
        audit.record(
            db,
            action=AuditAction.LOGIN_FAILURE,
            actor=user,
            success=False,
            request=request,
            details={"reason": "inactive_account"},
        )
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _INVALID_CREDENTIALS)

    login_throttle.record_success(throttle_key)
    user.last_login_at = utcnow()

    access = create_access_token(str(user.id), user.role, settings, user.token_version)
    refresh = create_refresh_token(str(user.id), user.role, settings, user.token_version)
    _set_refresh_cookie(response, refresh, settings)

    audit.record(db, action=AuditAction.LOGIN_SUCCESS, actor=user, request=request)
    db.commit()

    return TokenResponse(
        access_token=access,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=_serialise_user(user),
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(
    request: Request,
    response: Response,
    db: DbDep,
    settings: SettingsDep,
) -> TokenResponse:
    """Mint a new access token from the refresh cookie."""
    cookie = request.cookies.get(settings.REFRESH_COOKIE_NAME)
    if not cookie:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated.")

    payload = decode_token(cookie, settings, expected_type=TOKEN_TYPE_REFRESH)
    if payload is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated.")

    try:
        import uuid as _uuid

        user = db.get(User, _uuid.UUID(payload.subject))
    except ValueError:
        user = None

    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated.")

    # A password change increments token_version, so refresh tokens minted
    # before it are rejected here rather than continuing to work for days.
    if payload.token_version != user.token_version:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated.")

    access = create_access_token(str(user.id), user.role, settings, user.token_version)
    # Rotate the refresh token on every use, so a captured one has a short
    # useful life and reuse of an old one fails.
    _set_refresh_cookie(
        response,
        create_refresh_token(str(user.id), user.role, settings, user.token_version),
        settings,
    )

    audit.record(db, action=AuditAction.TOKEN_REFRESH, actor=user, request=request)
    db.commit()

    return TokenResponse(
        access_token=access,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=_serialise_user(user),
    )


@router.post("/logout", response_model=MessageResponse)
def logout(
    request: Request,
    response: Response,
    db: DbDep,
    settings: SettingsDep,
    user: CurrentUser,
) -> MessageResponse:
    response.delete_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        path=f"{settings.API_V1_PREFIX}/auth",
        httponly=True,
        # Must match the attributes used when the cookie was set, or the browser
        # treats it as a different cookie and the deletion silently misses.
        samesite=settings.COOKIE_SAMESITE,
        secure=settings.COOKIE_SECURE,
    )
    audit.record(db, action=AuditAction.LOGOUT, actor=user, request=request)
    db.commit()
    return MessageResponse(message="Logged out.")


@router.get("/me", response_model=UserWithPermissions)
def read_current_user(user: CurrentUser) -> UserWithPermissions:
    return _serialise_user(user)


@router.post("/change-password", response_model=MessageResponse)
def change_password(
    payload: PasswordChange,
    request: Request,
    db: DbDep,
    settings: SettingsDep,
    user: CurrentUser,
) -> MessageResponse:
    if not verify_password(payload.current_password, user.hashed_password):
        audit.record(
            db,
            action=AuditAction.PASSWORD_CHANGED,
            actor=user,
            success=False,
            request=request,
            details={"reason": "bad_current_password"},
        )
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect.")

    if payload.new_password == payload.current_password:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "New password must differ from the current one."
        )

    user.hashed_password = hash_password(payload.new_password, settings.BCRYPT_ROUNDS)
    # Bumping the version gives a future revocation check something to compare
    # against, so outstanding tokens can be invalidated on a password change.
    user.token_version += 1
    audit.record(db, action=AuditAction.PASSWORD_CHANGED, actor=user, request=request)
    db.commit()
    return MessageResponse(message="Password updated.")
