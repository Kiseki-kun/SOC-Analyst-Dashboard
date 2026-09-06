"""Password hashing and JWT issuance/verification.

Design notes worth defending in review:

* bcrypt is called directly rather than through passlib. passlib 1.7.4 predates
  bcrypt 4.x and raises on its version probe; pinning around that is a
  maintenance trap for a dependency doing one function's worth of work.
* Access and refresh tokens carry a `typ` claim and are rejected if presented
  in the wrong place. Without it, a refresh token — which is long-lived and
  sits in a cookie — would be accepted as an access token.
* Every token carries a `jti`, so a future revocation list has something to key
  on, and so two tokens minted in the same second are distinguishable.
"""

from __future__ import annotations

import hmac
import secrets
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Final

import bcrypt
import jwt
from jwt.exceptions import InvalidTokenError

from app.core.config import Settings

TOKEN_TYPE_ACCESS: Final = "access"
TOKEN_TYPE_REFRESH: Final = "refresh"

# bcrypt truncates silently at 72 bytes. Rejecting longer input is safer than
# letting two different passwords share a hash.
_BCRYPT_MAX_BYTES: Final = 72


class PasswordTooLongError(ValueError):
    """Raised when a password exceeds bcrypt's 72-byte input limit."""


def hash_password(password: str, rounds: int = 12) -> str:
    encoded = password.encode("utf-8")
    if len(encoded) > _BCRYPT_MAX_BYTES:
        raise PasswordTooLongError(
            f"Password exceeds {_BCRYPT_MAX_BYTES} bytes once UTF-8 encoded."
        )
    return bcrypt.hashpw(encoded, bcrypt.gensalt(rounds=rounds)).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    """Constant-time-ish password check that never raises on malformed input."""
    try:
        encoded = password.encode("utf-8")
        if len(encoded) > _BCRYPT_MAX_BYTES:
            return False
        return bcrypt.checkpw(encoded, hashed.encode("utf-8"))
    except (ValueError, TypeError):
        # A corrupt or non-bcrypt hash must read as "wrong password", not as a
        # 500 that tells an attacker the account exists and is broken.
        return False


# Throwaway hashes used to burn comparable CPU when an account does not exist,
# so login latency does not reveal which addresses are registered.
#
# Keyed by cost factor, and generated lazily. An earlier version hard-coded
# cost 10 while real accounts hashed at cost 12 — a 4.5x difference that an
# attacker can measure, which defeated the entire purpose of the control.
_dummy_hashes: dict[int, str] = {}
_dummy_lock = threading.Lock()


def waste_password_cycles(rounds: int) -> None:
    """Equalise timing between 'no such user' and 'wrong password'.

    `rounds` must be the same cost factor real passwords are hashed with,
    otherwise this leaks the very distinction it exists to hide.
    """
    hashed = _dummy_hashes.get(rounds)
    if hashed is None:
        with _dummy_lock:
            hashed = _dummy_hashes.get(rounds)
            if hashed is None:
                hashed = hash_password(secrets.token_urlsafe(16), rounds=rounds)
                _dummy_hashes[rounds] = hashed
    bcrypt.checkpw(b"timing-equalisation", hashed.encode("utf-8"))


def compare_secret(candidate: str, expected: str) -> bool:
    """Constant-time comparison for shared secrets (the ingest API key)."""
    return hmac.compare_digest(candidate.encode("utf-8"), expected.encode("utf-8"))


@dataclass(frozen=True, slots=True)
class TokenPayload:
    subject: str
    role: str
    token_type: str
    jti: str
    expires_at: datetime
    # Snapshot of the user's token_version when the token was minted. A
    # password change increments the stored value, so any token carrying an
    # older one is rejected. Without this the column was decorative.
    token_version: int


def _create_token(
    *,
    subject: str,
    role: str,
    token_type: str,
    expires_delta: timedelta,
    settings: Settings,
    token_version: int = 0,
) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "typ": token_type,
        "ver": token_version,
        "jti": uuid.uuid4().hex,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_access_token(
    subject: str, role: str, settings: Settings, token_version: int = 0
) -> str:
    return _create_token(
        subject=subject,
        role=role,
        token_type=TOKEN_TYPE_ACCESS,
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        settings=settings,
        token_version=token_version,
    )


def create_refresh_token(
    subject: str, role: str, settings: Settings, token_version: int = 0
) -> str:
    return _create_token(
        subject=subject,
        role=role,
        token_type=TOKEN_TYPE_REFRESH,
        expires_delta=timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        settings=settings,
        token_version=token_version,
    )


def decode_token(
    token: str, settings: Settings, *, expected_type: str
) -> TokenPayload | None:
    """Decode and fully validate a token. Returns None on any failure.

    Signature, expiry and the required claim set are all verified. The algorithm
    is pinned to a single value: accepting a list, or trusting the header's
    `alg`, is how "alg: none" and HS/RS confusion attacks get in.
    """
    try:
        claims = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={
                "require": ["exp", "iat", "nbf", "sub", "typ", "jti", "ver"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
            },
        )
    except InvalidTokenError:
        return None

    if claims.get("typ") != expected_type:
        # An access token presented as a refresh token (or the reverse) is
        # rejected even though its signature is perfectly valid.
        return None

    subject = claims.get("sub")
    role = claims.get("role")
    if not isinstance(subject, str) or not isinstance(role, str):
        return None

    version = claims.get("ver")
    if not isinstance(version, int):
        return None

    return TokenPayload(
        subject=subject,
        role=role,
        token_type=claims["typ"],
        jti=claims["jti"],
        expires_at=datetime.fromtimestamp(claims["exp"], tz=timezone.utc),
        token_version=version,
    )
