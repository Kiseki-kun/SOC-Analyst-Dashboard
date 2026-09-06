"""Shared response envelopes and query primitives."""

from __future__ import annotations

from datetime import datetime
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class ORMModel(BaseModel):
    """Base for schemas read from SQLAlchemy objects."""

    model_config = ConfigDict(from_attributes=True)


class Page(BaseModel, Generic[T]):
    """Uniform pagination envelope used by every list endpoint.

    `total` is a real COUNT, not len(items) — the event explorer needs an
    accurate result count to show "1-50 of 12,431".
    """

    items: list[T]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)
    pages: int = Field(ge=0)

    @classmethod
    def build(cls, items: list[T], total: int, page: int, page_size: int) -> Page[T]:
        pages = (total + page_size - 1) // page_size if page_size else 0
        return cls(items=items, total=total, page=page, page_size=page_size, pages=pages)


class MessageResponse(BaseModel):
    message: str


class ErrorResponse(BaseModel):
    """Consistent error shape.

    Deliberately carries no stack trace, no SQL, and no internal identifier.
    `detail` is written for the user; anything diagnostic goes to the log with a
    correlation id the user can quote.
    """

    detail: str
    error_code: str | None = None
    correlation_id: str | None = None


class TimeRange(BaseModel):
    start: datetime | None = None
    end: datetime | None = None
