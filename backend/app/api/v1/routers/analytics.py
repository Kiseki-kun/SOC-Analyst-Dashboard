"""Dashboard and analytics endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query

from app.api.deps import DbDep, require
from app.core.permissions import Permission
from app.models.user import User
from app.schemas.analytics import AnalyticsOverview, DashboardSummary
from app.services import analytics

router = APIRouter(prefix="/analytics", tags=["analytics"])


@router.get("/summary", response_model=DashboardSummary)
def dashboard_summary(
    db: DbDep,
    _: User = require(Permission.DASHBOARD_READ),
) -> DashboardSummary:
    return DashboardSummary(**analytics.dashboard_summary(db))


@router.get("/overview", response_model=AnalyticsOverview)
def analytics_overview(
    db: DbDep,
    _: User = require(Permission.ANALYTICS_READ),
    hours: Annotated[int, Query(ge=1, le=720)] = 24,
    days: Annotated[int, Query(ge=1, le=90)] = 7,
) -> AnalyticsOverview:
    """Everything the analytics page needs, in one round trip.

    A single composite endpoint rather than ten separate ones: the page renders
    them together, and ten parallel requests would each re-scan overlapping
    windows of the same table.
    """
    return AnalyticsOverview(
        summary=analytics.dashboard_summary(db),
        events_over_time=analytics.events_over_time(db, hours=hours),
        alerts_over_time=analytics.alerts_over_time(db, hours=hours),
        authentication_trend=analytics.authentication_trend(db, hours=hours),
        top_source_ips=analytics.top_source_ips(db, hours=hours),
        top_destination_ips=analytics.top_destination_ips(db, hours=hours),
        top_detection_rules=analytics.top_detection_rules(db, days=days),
        mitre_distribution=analytics.mitre_distribution(db, days=days),
        attack_categories=analytics.attack_categories(db, days=days),
        event_type_distribution=analytics.event_type_distribution(db, hours=hours),
        response_metrics=analytics.response_metrics(db),
    )
