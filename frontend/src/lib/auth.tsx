import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'

import { request, setAccessToken, setUnauthenticatedHandler } from '@/lib/api'
import type { CurrentUser, TokenResponse } from '@/types/api'

interface AuthState {
  user: CurrentUser | null
  // Distinguishes "still checking for an existing session" from "definitely
  // logged out". Without it, a page refresh flashes the login screen for every
  // authenticated user before the silent refresh completes.
  initialising: boolean
  login: (email: string, password: string) => Promise<void>
  logout: () => Promise<void>
  refreshUser: () => Promise<void>
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<CurrentUser | null>(null)
  const [initialising, setInitialising] = useState(true)

  const clearSession = useCallback(() => {
    setAccessToken(null)
    setUser(null)
  }, [])

  useEffect(() => {
    setUnauthenticatedHandler(clearSession)
    return () => setUnauthenticatedHandler(null)
  }, [clearSession])

  // On mount, try to restore a session from the refresh cookie. The access
  // token is in memory only, so it is gone after a reload — but the httpOnly
  // cookie survives, which is what keeps the user logged in across refreshes
  // without ever exposing a long-lived credential to JavaScript.
  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const data = await request<TokenResponse>('/auth/refresh', {
          method: 'POST',
          skipRefresh: true,
        })
        if (cancelled) return
        setAccessToken(data.access_token)
        setUser(data.user)
      } catch {
        if (!cancelled) clearSession()
      } finally {
        if (!cancelled) setInitialising(false)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [clearSession])

  const login = useCallback(async (email: string, password: string) => {
    const data = await request<TokenResponse>('/auth/login', {
      method: 'POST',
      body: { email, password },
      skipRefresh: true,
    })
    setAccessToken(data.access_token)
    setUser(data.user)
  }, [])

  const logout = useCallback(async () => {
    try {
      await request('/auth/logout', { method: 'POST', skipRefresh: true })
    } catch {
      // A failed logout call must still clear local state: the user asked to
      // leave, and leaving them apparently signed in would be worse.
    } finally {
      clearSession()
    }
  }, [clearSession])

  const refreshUser = useCallback(async () => {
    const me = await request<CurrentUser>('/auth/me')
    setUser(me)
  }, [])

  const value = useMemo(
    () => ({ user, initialising, login, logout, refreshUser }),
    [user, initialising, login, logout, refreshUser],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthState {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth must be used inside an AuthProvider')
  return context
}
