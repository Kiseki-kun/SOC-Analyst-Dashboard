"""Investigation pivots."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, Query, status

from app.api.deps import DbDep, require
from app.core.permissions import Permission
from app.models.user import User
from app.schemas.alert import AlertRead
from app.schemas.event import EventRead
from app.schemas.investigation import IPInvestigation
from app.services import investigation

router = APIRouter(prefix="/investigations", tags=["investigations"])


@router.get("/ip/{ip_address}", response_model=IPInvestigation)
def investigate_ip(
    db: DbDep,
    ip_address: Annotated[str, Path(max_length=45)],
    _: User = require(Permission.INVESTIGATION_READ),
    event_limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> IPInvestigation:
    """Everything this system knows about one address.

    The address is validated as an IP before use. It is bound as a query
    parameter throughout, never interpolated — but rejecting non-addresses up
    front also stops the endpoint being used to probe with arbitrary strings.
    """
    if not investigation.is_valid_ip(ip_address):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Not a valid IP address.")

    result = investigation.investigate_ip(db, ip_address, event_limit=event_limit)
    return IPInvestigation(
        ip_address=result["ip_address"],
        summary=result["summary"],
        reputation=result["reputation"],
        associated_usernames=result["associated_usernames"],
        associated_hostnames=result["associated_hostnames"],
        top_destination_ports=result["top_destination_ports"],
        related_alerts=[AlertRead.model_validate(a) for a in result["related_alerts"]],
        related_incident_uids=result["related_incident_uids"],
        recent_events=[EventRead.model_validate(e) for e in result["recent_events"]],
    )
