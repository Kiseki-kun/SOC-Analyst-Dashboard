import { useState } from 'react'

import { Button, Card, CardHeader, Input, Pill } from '@/components/ui'
import { useToast } from '@/components/ui/toast'
import { useChangePassword } from '@/hooks/queries'
import { ApiError } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { formatTimestamp, titleCase } from '@/lib/format'

export default function ProfilePage() {
  const { user } = useAuth()
  const toast = useToast()
  const changePassword = useChangePassword()

  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')

  const submit = async () => {
    if (next !== confirm) {
      toast.push('The new passwords do not match.', 'error')
      return
    }
    try {
      await changePassword.mutateAsync({ current_password: current, new_password: next })
      toast.push('Password updated.', 'success')
      setCurrent('')
      setNext('')
      setConfirm('')
    } catch (error) {
      toast.push(
        error instanceof ApiError
          ? [error.message, ...error.fieldErrors.map((f) => f.message)].join(' ')
          : 'Could not change the password.',
        'error',
      )
    }
  }

  if (!user) return null

  return (
    <div className="space-y-4 max-w-3xl">
      <h1 className="text-base font-semibold text-ink-100">Profile</h1>

      <Card>
        <CardHeader title="Account" />
        <dl className="p-4 space-y-1.5 text-2xs">
          {[
            ['Name', user.full_name],
            ['Email', user.email],
            ['Role', titleCase(user.role)],
            ['Last sign-in', formatTimestamp(user.last_login_at)],
            ['Account created', formatTimestamp(user.created_at)],
          ].map(([label, value]) => (
            <div key={String(label)} className="flex justify-between gap-3">
              <dt className="text-ink-400">{label}</dt>
              <dd className="text-ink-100">{value}</dd>
            </div>
          ))}
        </dl>
      </Card>

      <Card>
        <CardHeader
          title="Your permissions"
          subtitle="Enforced by the server on every request — this list is informational"
        />
        <div className="p-4 flex flex-wrap gap-1.5">
          {user.permissions.map((permission) => (
            <Pill key={permission}>{permission}</Pill>
          ))}
        </div>
      </Card>

      <Card>
        <CardHeader title="Change password" />
        <div className="p-4 space-y-3 max-w-sm">
          <div>
            <label htmlFor="current" className="block text-2xs text-ink-300 mb-1">
              Current password
            </label>
            <Input
              id="current"
              type="password"
              autoComplete="current-password"
              value={current}
              onChange={(event) => setCurrent(event.target.value)}
            />
          </div>
          <div>
            <label htmlFor="next" className="block text-2xs text-ink-300 mb-1">
              New password
            </label>
            <Input
              id="next"
              type="password"
              autoComplete="new-password"
              value={next}
              onChange={(event) => setNext(event.target.value)}
            />
            <p className="mt-1 text-2xs text-ink-400">
              At least 12 characters, with upper case, lower case, a digit and a symbol.
            </p>
          </div>
          <div>
            <label htmlFor="confirm" className="block text-2xs text-ink-300 mb-1">
              Confirm new password
            </label>
            <Input
              id="confirm"
              type="password"
              autoComplete="new-password"
              value={confirm}
              onChange={(event) => setConfirm(event.target.value)}
            />
          </div>
          <Button
            variant="primary"
            disabled={!current || !next || changePassword.isPending}
            onClick={submit}
          >
            Update password
          </Button>
        </div>
      </Card>
    </div>
  )
}
