"""User schemas."""

from __future__ import annotations

import re
import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.core.permissions import Role
from app.schemas.common import ORMModel

# Deliberately not a single unreadable regex: each rule is checked separately so
# the error message can say exactly which one failed.
_PASSWORD_MIN_LENGTH = 12
_PASSWORD_MAX_BYTES = 72  # bcrypt's hard input limit


def validate_password_strength(password: str) -> str:
    encoded = password.encode("utf-8")
    if len(password) < _PASSWORD_MIN_LENGTH:
        raise ValueError(f"Password must be at least {_PASSWORD_MIN_LENGTH} characters.")
    if len(encoded) > _PASSWORD_MAX_BYTES:
        raise ValueError(
            f"Password must be at most {_PASSWORD_MAX_BYTES} bytes when UTF-8 encoded."
        )
    checks = (
        (r"[a-z]", "one lowercase letter"),
        (r"[A-Z]", "one uppercase letter"),
        (r"[0-9]", "one digit"),
        (r"[^A-Za-z0-9]", "one symbol"),
    )
    missing = [label for pattern, label in checks if not re.search(pattern, password)]
    if missing:
        raise ValueError("Password must contain at least " + ", ".join(missing) + ".")
    return password


class UserBase(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=200)
    role: Role = Role.VIEWER

    @field_validator("email")
    @classmethod
    def _normalise_email(cls, value: str) -> str:
        # Lower-cased on the way in so the unique index is meaningful and login
        # is not case-sensitive.
        return value.strip().lower()


class UserCreate(UserBase):
    password: str

    @field_validator("password")
    @classmethod
    def _strength(cls, value: str) -> str:
        return validate_password_strength(value)


class UserUpdate(BaseModel):
    full_name: str | None = Field(default=None, min_length=1, max_length=200)
    role: Role | None = None
    is_active: bool | None = None


class PasswordChange(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def _strength(cls, value: str) -> str:
        return validate_password_strength(value)


class UserRead(ORMModel):
    id: uuid.UUID
    email: EmailStr
    full_name: str
    role: Role
    is_active: bool
    last_login_at: datetime | None
    created_at: datetime


class UserWithPermissions(UserRead):
    """Returned by /auth/me so the UI can hide controls the user cannot use.

    Hiding a button is a usability nicety, never a control: every one of these
    permissions is enforced again on the server for each request.
    """

    permissions: list[str]
