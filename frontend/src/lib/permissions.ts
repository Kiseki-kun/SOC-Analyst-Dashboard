import type { CurrentUser } from '@/types/api'

/**
 * Permission strings, mirroring app/core/permissions.py.
 *
 * These drive what the UI *shows*. They are never the security boundary: the
 * server re-checks every one of them on every request, and hiding a button is
 * a convenience for the operator, not a control.
 */
export const Permission = {
  DASHBOARD_READ: 'dashboard:read',
  EVENT_READ: 'event:read',
  ALERT_READ: 'alert:read',
  ALERT_TRIAGE: 'alert:triage',
  ALERT_NOTE_CREATE: 'alert:note:create',
  INCIDENT_READ: 'incident:read',
  INCIDENT_CREATE: 'incident:create',
  INCIDENT_UPDATE: 'incident:update',
  INCIDENT_NOTE_CREATE: 'incident:note:create',
  INCIDENT_ASSIGN: 'incident:assign',
  INCIDENT_CLOSE: 'incident:close',
  RESPONSE_ACTION_EXECUTE: 'response:execute',
  IOC_MANAGE: 'ioc:manage',
  ANALYTICS_READ: 'analytics:read',
  INVESTIGATION_READ: 'investigation:read',
  DETECTION_READ: 'detection:read',
  DETECTION_MANAGE: 'detection:manage',
  USER_READ: 'user:read',
  USER_MANAGE: 'user:manage',
  AUDIT_READ: 'audit:read',
} as const

export type PermissionValue = (typeof Permission)[keyof typeof Permission]

export function can(user: CurrentUser | null, permission: PermissionValue): boolean {
  return Boolean(user?.permissions.includes(permission))
}
