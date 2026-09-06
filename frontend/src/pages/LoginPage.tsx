import { useState } from 'react'
import type { FormEvent } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'

import { ApiError } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { Button, Input, Spinner } from '@/components/ui'

export default function LoginPage() {
  const { user, login, initialising } = useAuth()
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  if (initialising) {
    return (
      <div className="min-h-screen grid place-items-center">
        <Spinner label="Restoring session" />
      </div>
    )
  }
  if (user) return <Navigate to="/" replace />

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      await login(email, password)
      navigate('/', { replace: true })
    } catch (err) {
      // The server returns one message for every credential failure. Echoing
      // it unchanged keeps the client from leaking a distinction the API
      // deliberately withholds.
      setError(
        err instanceof ApiError
          ? err.message
          : 'Could not reach the server. Check that the API is running.',
      )
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="min-h-screen grid place-items-center bg-surface-950 p-4">
      <div className="w-full max-w-sm">
        <div className="mb-6 text-center">
          <h1 className="text-lg font-semibold text-ink-100">SOC Analyst Dashboard</h1>
          <p className="mt-1 text-xs text-ink-400">
            All telemetry in this system is synthetic.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="card p-5 space-y-4">
          <div>
            <label htmlFor="email" className="block text-2xs text-ink-300 mb-1">
              Email
            </label>
            <Input
              id="email"
              type="email"
              autoComplete="username"
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="analyst@soc.example.com"
            />
          </div>

          <div>
            <label htmlFor="password" className="block text-2xs text-ink-300 mb-1">
              Password
            </label>
            <Input
              id="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </div>

          {error ? (
            <p role="alert" className="text-2xs text-severity-high">
              {error}
            </p>
          ) : null}

          <Button type="submit" variant="primary" className="w-full" disabled={submitting}>
            {submitting ? 'Signing in…' : 'Sign in'}
          </Button>
        </form>

        <p className="mt-4 text-center text-2xs text-ink-400">
          Demo credentials are documented in the project README.
        </p>
      </div>
    </div>
  )
}
