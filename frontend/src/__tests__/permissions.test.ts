import { describe, expect, it } from 'vitest'

import { Permission, can } from '@/lib/permissions'
import type { CurrentUser } from '@/types/api'

function user(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    email: 'a@soc.example.com',
    full_name: 'A',
    role: 'analyst',
    is_active: true,
    last_login_at: null,
    created_at: '2026-01-01T00:00:00Z',
    permissions,
  }
}

describe('permission gate', () => {
  it('grants a held permission', () => {
    expect(can(user([Permission.ALERT_TRIAGE]), Permission.ALERT_TRIAGE)).toBe(true)
  })

  it('denies one that is absent', () => {
    expect(can(user([Permission.ALERT_READ]), Permission.ALERT_TRIAGE)).toBe(false)
  })

  it('denies everything when signed out', () => {
    // Fail closed: no session means no capability, never a default allow.
    expect(can(null, Permission.EVENT_READ)).toBe(false)
  })

  it('does not treat a prefix as a match', () => {
    // 'alert:read' must not satisfy 'alert:read:all' or vice versa.
    expect(can(user(['alert:read']), 'alert:read:all' as never)).toBe(false)
  })
})
