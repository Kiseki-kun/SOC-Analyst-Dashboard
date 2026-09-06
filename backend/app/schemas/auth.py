"""Authentication request/response schemas."""

from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.schemas.user import UserWithPermissions


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=200)

    @field_validator("email")
    @classmethod
    def _normalise(cls, value: str) -> str:
        return value.strip().lower()


class TokenResponse(BaseModel):
    """Login/refresh response.

    Only the access token appears in the body. The refresh token is set as an
    httpOnly cookie and is never readable by JavaScript, so cross-site scripting
    cannot steal a long-lived credential.
    """

    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
    user: UserWithPermissions
