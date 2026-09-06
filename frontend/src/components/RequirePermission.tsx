import { Navigate, useLocation } from 'react-router-dom'
import type { ReactNode } from 'react'

import { Spinner } from '@/components/ui'
import { useAuth } from '@/lib/auth'
import { can } from '@/lib/permissions'
import type { PermissionValue } from '@/lib/permissions'

/**
 * Route guard.
 *
 * This is a usability control, not a security boundary. It stops a viewer from
 * landing on an admin page that would only render errors; it is NOT what keeps
 * them out of the data. The API re-checks the same permission on every request,
 * and a user who edits their way past this guard gets a 403 from the server and
 * an entry in the audit log.
 */
export function RequirePermission({
  permission,
  children,
}: {
  permission?: PermissionValue
  children: ReactNode
}) {
  const { user, initialising } = useAuth()
  const location = useLocation()

  if (initialising) {
    return (
      <div className="min-h-screen grid place-items-center">
        <Spinner label="Restoring session" />
      </div>
    )
  }

  if (!user) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />
  }

  if (permission && !can(user, permission)) {
    return (
      <div className="py-16 text-center">
        <p className="text-sm text-ink-100">You do not have access to this area.</p>
        <p className="mt-1 text-2xs text-ink-400">
          Your role is not permitted to view it. Ask an administrator if you need access.
        </p>
      </div>
    )
  }

  return <>{children}</>
}
