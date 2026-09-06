"""Shared, allow-listed sort helpers.

Sort fields are never taken from the request as a column name. Each router
declares a `Literal` of permitted values and a mapping to real columns, so an
unknown field is rejected by validation before any query is built.

Severity needs its own ordering. It is stored as text, so `ORDER BY severity`
yields critical < high < info < low < medium — alphabetical, and actively
misleading in a triage queue where the whole point is that the worst thing is
at the top.
"""

from __future__ import annotations

from typing import Literal

from sqlalchemy import case
from sqlalchemy.sql.elements import UnaryExpression

SortDirection = Literal["asc", "desc"]

# Higher is worse. Kept here rather than in each router so the three tables
# that expose severity sorting cannot drift apart.
SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def severity_ordering(column, direction: SortDirection) -> UnaryExpression:
    """Order by real severity rather than alphabetically."""
    ranked = case(SEVERITY_RANK, value=column, else_=0)
    return ranked.desc() if direction == "desc" else ranked.asc()


def column_ordering(column, direction: SortDirection) -> UnaryExpression:
    return column.desc() if direction == "desc" else column.asc()
