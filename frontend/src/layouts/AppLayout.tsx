import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import clsx from 'clsx'
import { useState } from 'react'

import { useAuth } from '@/lib/auth'
import { Permission, can } from '@/lib/permissions'
import type { PermissionValue } from '@/lib/permissions'
import { Button } from '@/components/ui'
import { titleCase } from '@/lib/format'

interface NavItem {
  to: string
  label: string
  permission: PermissionValue
}

const NAV: NavItem[] = [
  { to: '/', label: 'Dashboard', permission: Permission.DASHBOARD_READ },
  { to: '/alerts', label: 'Alerts', permission: Permission.ALERT_READ },
  { to: '/incidents', label: 'Incidents', permission: Permission.INCIDENT_READ },
  { to: '/events', label: 'Events', permission: Permission.EVENT_READ },
  { to: '/investigate', label: 'IP investigation', permission: Permission.INVESTIGATION_READ },
  { to: '/analytics', label: 'Analytics', permission: Permission.ANALYTICS_READ },
  { to: '/detections', label: 'Detections', permission: Permission.DETECTION_READ },
  { to: '/audit', label: 'Audit log', permission: Permission.AUDIT_READ },
  { to: '/users', label: 'Users', permission: Permission.USER_READ },
]

export default function AppLayout() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [menuOpen, setMenuOpen] = useState(false)

  // Navigation is filtered by permission for usability, not security: the
  // routes are guarded independently and the API re-checks every request.
  const visible = NAV.filter((item) => can(user, item.permission))

  const handleLogout = async () => {
    await logout()
    navigate('/login', { replace: true })
  }

  return (
    <div className="min-h-screen flex bg-surface-950">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:m-2 focus:rounded focus:bg-surface-800 focus:px-3 focus:py-2 focus:text-xs focus:text-ink-100"
      >
        Skip to content
      </a>

      <aside
        className={clsx(
          'w-56 shrink-0 border-r border-surface-800 bg-surface-900 flex flex-col',
          'fixed inset-y-0 z-40 md:static md:translate-x-0 transition-transform',
          menuOpen ? 'translate-x-0' : '-translate-x-full',
        )}
      >
        <div className="px-4 py-4 border-b border-surface-800">
          <p className="text-sm font-semibold text-ink-100">SOC Dashboard</p>
          <p className="text-2xs text-ink-400 mt-0.5">Synthetic telemetry only</p>
        </div>

        <nav className="flex-1 overflow-y-auto p-2" aria-label="Main">
          <ul className="space-y-0.5">
            {visible.map((item) => (
              <li key={item.to}>
                <NavLink
                  to={item.to}
                  end={item.to === '/'}
                  onClick={() => setMenuOpen(false)}
                  className={({ isActive }) =>
                    clsx(
                      'block rounded px-2.5 py-1.5 text-xs transition-colors',
                      isActive
                        ? 'bg-surface-800 text-ink-100 font-medium'
                        : 'text-ink-300 hover:bg-surface-850 hover:text-ink-100',
                    )
                  }
                >
                  {item.label}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>

        <div className="border-t border-surface-800 p-3">
          <p className="text-xs text-ink-100 truncate">{user?.full_name}</p>
          <p className="text-2xs text-ink-400 truncate">{user?.email}</p>
          <p className="mt-1 inline-flex rounded bg-surface-800 border border-surface-700 px-1.5 py-0.5 text-2xs text-ink-200">
            {titleCase(user?.role ?? '')}
          </p>
          <div className="mt-2 flex gap-1.5">
            <NavLink to="/profile" className="flex-1">
              <Button size="sm" className="w-full">
                Profile
              </Button>
            </NavLink>
            <Button size="sm" variant="ghost" onClick={handleLogout}>
              Sign out
            </Button>
          </div>
        </div>
      </aside>

      <div className="flex-1 min-w-0 flex flex-col">
        <header className="md:hidden flex items-center gap-2 border-b border-surface-800 bg-surface-900 px-3 py-2">
          <Button size="sm" onClick={() => setMenuOpen((open) => !open)} aria-expanded={menuOpen}>
            Menu
          </Button>
          <span className="text-xs font-semibold text-ink-100">SOC Dashboard</span>
        </header>

        <main id="main" className="flex-1 overflow-y-auto p-4 md:p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
