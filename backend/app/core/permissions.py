"""Role-based access control.

Two ideas, kept separate on purpose:

*Roles* are what a user is assigned. *Permissions* are what an endpoint
requires. Endpoints never test a role name — they require a permission, and the
mapping below decides which roles hold it.

Why not a plain hierarchy? A pure ranking (`viewer < analyst < responder <
admin`) cannot express "a responder may close an incident but may not create
users", and every real SOC has capabilities that do not nest. The explicit map
also makes the authorisation model reviewable in one screen, which is the point
of writing it down.

The ranking is still kept, but only for display ordering and for the narrow
case of "may this actor manage a user of that role".
"""

from __future__ import annotations

from app.core.enums import StrEnumCompat


class Role(StrEnumCompat):
    VIEWER = "viewer"
    ANALYST = "analyst"
    RESPONDER = "responder"
    ADMIN = "admin"


# Display/administrative ordering only. Not used for permission checks.
ROLE_RANK: dict[Role, int] = {
    Role.VIEWER: 0,
    Role.ANALYST: 1,
    Role.RESPONDER: 2,
    Role.ADMIN: 3,
}


class Permission(StrEnumCompat):
    """Every capability the API enforces.

    Naming is `<resource>:<verb>` so an audit reader can scan them.
    """

    # --- read-only surface -------------------------------------------------
    DASHBOARD_READ = "dashboard:read"
    EVENT_READ = "event:read"
    ALERT_READ = "alert:read"
    INCIDENT_READ = "incident:read"
    ANALYTICS_READ = "analytics:read"
    DETECTION_READ = "detection:read"
    INVESTIGATION_READ = "investigation:read"

    # --- analyst work ------------------------------------------------------
    ALERT_TRIAGE = "alert:triage"          # change status, assign to self
    ALERT_NOTE_CREATE = "alert:note:create"
    INCIDENT_CREATE = "incident:create"
    INCIDENT_UPDATE = "incident:update"
    INCIDENT_NOTE_CREATE = "incident:note:create"

    # --- responder work ----------------------------------------------------
    INCIDENT_ASSIGN = "incident:assign"
    INCIDENT_CLOSE = "incident:close"
    RESPONSE_ACTION_EXECUTE = "response:execute"   # simulated only
    IOC_MANAGE = "ioc:manage"

    # --- administration ----------------------------------------------------
    USER_READ = "user:read"
    USER_MANAGE = "user:manage"
    ROLE_MANAGE = "role:manage"
    DETECTION_MANAGE = "detection:manage"
    AUDIT_READ = "audit:read"
    SYSTEM_MANAGE = "system:manage"


_VIEWER_PERMISSIONS: frozenset[Permission] = frozenset(
    {
        Permission.DASHBOARD_READ,
        Permission.EVENT_READ,
        Permission.ALERT_READ,
        Permission.INCIDENT_READ,
        Permission.ANALYTICS_READ,
        Permission.DETECTION_READ,
        Permission.INVESTIGATION_READ,
    }
)

_ANALYST_PERMISSIONS: frozenset[Permission] = _VIEWER_PERMISSIONS | frozenset(
    {
        Permission.ALERT_TRIAGE,
        Permission.ALERT_NOTE_CREATE,
        Permission.INCIDENT_CREATE,
        Permission.INCIDENT_UPDATE,
        Permission.INCIDENT_NOTE_CREATE,
    }
)

_RESPONDER_PERMISSIONS: frozenset[Permission] = _ANALYST_PERMISSIONS | frozenset(
    {
        Permission.INCIDENT_ASSIGN,
        Permission.INCIDENT_CLOSE,
        Permission.RESPONSE_ACTION_EXECUTE,
        Permission.IOC_MANAGE,
    }
)

_ADMIN_PERMISSIONS: frozenset[Permission] = _RESPONDER_PERMISSIONS | frozenset(
    {
        Permission.USER_READ,
        Permission.USER_MANAGE,
        Permission.ROLE_MANAGE,
        Permission.DETECTION_MANAGE,
        Permission.AUDIT_READ,
        Permission.SYSTEM_MANAGE,
    }
)

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: _VIEWER_PERMISSIONS,
    Role.ANALYST: _ANALYST_PERMISSIONS,
    Role.RESPONDER: _RESPONDER_PERMISSIONS,
    Role.ADMIN: _ADMIN_PERMISSIONS,
}


def permissions_for(role: Role | str) -> frozenset[Permission]:
    """Permissions granted to a role. An unknown role grants nothing."""
    try:
        return ROLE_PERMISSIONS[Role(role)]
    except ValueError:
        # Fail closed. A role string the code does not recognise — a stale row,
        # a hand-edited database — must not be treated as privileged.
        return frozenset()


def role_has_permission(role: Role | str, permission: Permission) -> bool:
    return permission in permissions_for(role)


def can_manage_user(actor_role: Role | str, target_role: Role | str) -> bool:
    """Whether `actor_role` may create, modify or delete a user of `target_role`.

    Only admins manage users at all, and this exists so the rule stays in one
    place if a future "team lead" role needs to manage analysts but not admins.
    """
    try:
        actor = Role(actor_role)
        target = Role(target_role)
    except ValueError:
        return False
    if actor is not Role.ADMIN:
        return False
    return ROLE_RANK[actor] >= ROLE_RANK[target]
