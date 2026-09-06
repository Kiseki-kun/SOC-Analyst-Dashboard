"""Declarative base and portable column types.

The production database is PostgreSQL. The test suite runs on SQLite so the
detection engine, RBAC rules and service layer can be exercised without a
database server. The variant types below are what make one model definition
serve both: on PostgreSQL they compile to JSONB and native UUID, on SQLite to
JSON and CHAR(32).
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, MetaData, func
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import JSON, TypeDecorator

# Explicit constraint naming. Without this, Alembic autogenerate produces
# migrations that cannot drop an unnamed constraint on PostgreSQL.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

# JSONB on PostgreSQL (indexable, binary), plain JSON elsewhere.
JSONVariant = JSON().with_variant(postgresql.JSONB(), "postgresql")


def utcnow() -> datetime:
    """Timezone-aware timezone.utc now.

    `datetime.utcnow()` returns a naive value and is deprecated; mixing naive
    and aware datetimes is a reliable source of off-by-hours bugs in time-window
    detection logic.
    """
    return datetime.now(timezone.utc)


class UTCDateTime(TypeDecorator):
    """A timestamp that is always timezone-aware timezone.utc in Python.

    PostgreSQL returns aware datetimes for TIMESTAMPTZ; SQLite returns naive
    ones. Without this, any arithmetic mixing a stored timestamp with an
    in-memory one raises "can't subtract offset-naive and offset-aware
    datetimes" — and the detection engine does exactly that arithmetic
    constantly (time windows, travel speed, alert first/last seen).

    Normalising here rather than in each rule means the invariant holds for
    every query in the application, including ones written later.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            # A naive value reaching the database is a bug upstream, but
            # assuming timezone.utc is far safer than storing an ambiguous local time.
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


def as_utc(moment: datetime) -> datetime:
    """Coerce any datetime to timezone-aware timezone.utc."""
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class TimestampMixin:
    """created_at / updated_at maintained by the database where possible."""

    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime,
        nullable=False,
        default=utcnow,
        server_default=func.now(),
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime,
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
        server_default=func.now(),
    )
