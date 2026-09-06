import { useState } from 'react'

import {
  Button,
  Card,
  EmptyState,
  ErrorState,
  Input,
  LoadingBlock,
  Modal,
  Pagination,
  Select,
} from '@/components/ui'
import { useToast } from '@/components/ui/toast'
import { useCreateUser, useUpdateUser, useUsers } from '@/hooks/queries'
import { ApiError } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { Permission, can } from '@/lib/permissions'
import { formatTimestamp, titleCase } from '@/lib/format'
import type { AppUser, Role } from '@/types/api'

const ROLES: Role[] = ['viewer', 'analyst', 'responder', 'admin']

function UserRow({ user, canManage, selfId }: { user: AppUser; canManage: boolean; selfId?: string }) {
  const update = useUpdateUser(user.id)
  const toast = useToast()
  const isSelf = user.id === selfId

  return (
    <tr className="hover:bg-surface-850">
      <td className="px-4 py-2.5 text-xs text-ink-100">
        {user.full_name}
        {isSelf ? <span className="ml-1.5 text-2xs text-ink-400">(you)</span> : null}
      </td>
      <td className="px-4 py-2.5 text-2xs text-ink-300">{user.email}</td>
      <td className="px-4 py-2.5">
        {canManage && !isSelf ? (
          <Select
            value={user.role}
            disabled={update.isPending}
            onChange={async (event) => {
              try {
                await update.mutateAsync({ role: event.target.value })
                toast.push(`${user.email} is now ${event.target.value}.`, 'success')
              } catch (error) {
                toast.push(
                  error instanceof ApiError ? error.message : 'Could not change role.',
                  'error',
                )
              }
            }}
            aria-label={`Role for ${user.email}`}
          >
            {ROLES.map((role) => (
              <option key={role} value={role}>
                {role}
              </option>
            ))}
          </Select>
        ) : (
          <span className="text-2xs text-ink-200">{titleCase(user.role)}</span>
        )}
      </td>
      <td className="px-4 py-2.5 text-2xs text-ink-400">{formatTimestamp(user.last_login_at)}</td>
      <td className="px-4 py-2.5 text-right">
        {canManage && !isSelf ? (
          <Button
            size="sm"
            variant={user.is_active ? 'ghost' : 'primary'}
            disabled={update.isPending}
            onClick={async () => {
              try {
                await update.mutateAsync({ is_active: !user.is_active })
                toast.push(
                  `${user.email} ${user.is_active ? 'deactivated' : 'reactivated'}.`,
                  'success',
                )
              } catch (error) {
                toast.push(
                  error instanceof ApiError ? error.message : 'Could not update the account.',
                  'error',
                )
              }
            }}
          >
            {user.is_active ? 'Active' : 'Inactive'}
          </Button>
        ) : (
          <span className="text-2xs text-ink-300">{user.is_active ? 'Active' : 'Inactive'}</span>
        )}
      </td>
    </tr>
  )
}

export default function UsersPage() {
  const { user } = useAuth()
  const toast = useToast()
  const [page, setPage] = useState(1)
  const query = useUsers({ page, page_size: 25 })
  const create = useCreateUser()

  const [adding, setAdding] = useState(false)
  const [form, setForm] = useState({ email: '', full_name: '', role: 'viewer', password: '' })

  const canManage = can(user, Permission.USER_MANAGE)

  const submit = async () => {
    try {
      await create.mutateAsync(form)
      toast.push(`Created ${form.email}.`, 'success')
      setAdding(false)
      setForm({ email: '', full_name: '', role: 'viewer', password: '' })
    } catch (error) {
      toast.push(
        error instanceof ApiError
          ? [error.message, ...error.fieldErrors.map((f) => f.message)].join(' ')
          : 'Could not create the account.',
        'error',
      )
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-base font-semibold text-ink-100">Users</h1>
          <p className="mt-0.5 text-2xs text-ink-400">
            Accounts are provisioned by an administrator. There is no public registration.
          </p>
        </div>
        {canManage ? (
          <Button variant="primary" onClick={() => setAdding(true)}>
            Add user
          </Button>
        ) : null}
      </div>

      <Card>
        {query.isLoading ? (
          <LoadingBlock />
        ) : query.isError ? (
          <ErrorState message="Could not load users." onRetry={() => query.refetch()} />
        ) : query.data?.items.length ? (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-surface-800 text-2xs uppercase tracking-wide text-ink-400">
                    <th className="px-4 py-2 font-medium">Name</th>
                    <th className="px-4 py-2 font-medium">Email</th>
                    <th className="px-4 py-2 font-medium">Role</th>
                    <th className="px-4 py-2 font-medium">Last sign-in</th>
                    <th className="px-4 py-2 font-medium text-right">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-surface-800">
                  {query.data.items.map((entry) => (
                    <UserRow
                      key={entry.id}
                      user={entry}
                      canManage={canManage}
                      selfId={user?.id}
                    />
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination
              page={query.data.page}
              pages={query.data.pages}
              total={query.data.total}
              pageSize={query.data.page_size}
              onChange={setPage}
            />
          </>
        ) : (
          <EmptyState title="No users" />
        )}
      </Card>

      <Modal open={adding} title="Create a user" onClose={() => setAdding(false)}>
        <div className="space-y-3">
          <div>
            <label htmlFor="user-name" className="block text-2xs text-ink-300 mb-1">
              Full name
            </label>
            <Input
              id="user-name"
              value={form.full_name}
              onChange={(event) => setForm({ ...form, full_name: event.target.value })}
            />
          </div>
          <div>
            <label htmlFor="user-email" className="block text-2xs text-ink-300 mb-1">
              Email
            </label>
            <Input
              id="user-email"
              type="email"
              value={form.email}
              onChange={(event) => setForm({ ...form, email: event.target.value })}
            />
          </div>
          <div>
            <label htmlFor="user-role" className="block text-2xs text-ink-300 mb-1">
              Role
            </label>
            <Select
              id="user-role"
              value={form.role}
              onChange={(event) => setForm({ ...form, role: event.target.value })}
              className="w-full"
            >
              {ROLES.map((role) => (
                <option key={role} value={role}>
                  {role}
                </option>
              ))}
            </Select>
          </div>
          <div>
            <label htmlFor="user-password" className="block text-2xs text-ink-300 mb-1">
              Initial password
            </label>
            <Input
              id="user-password"
              type="password"
              value={form.password}
              onChange={(event) => setForm({ ...form, password: event.target.value })}
            />
            <p className="mt-1 text-2xs text-ink-400">
              At least 12 characters, with upper case, lower case, a digit and a symbol.
            </p>
          </div>
          <div className="flex justify-end gap-2">
            <Button onClick={() => setAdding(false)}>Cancel</Button>
            <Button variant="primary" disabled={create.isPending} onClick={submit}>
              Create
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
