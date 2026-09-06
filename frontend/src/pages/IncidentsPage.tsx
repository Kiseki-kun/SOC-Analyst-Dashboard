import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'

import { PlainHeader, SortableHeader } from '@/components/SortableHeader'
import type { SortDirection } from '@/components/SortableHeader'
import {
  Button,
  Card,
  EmptyState,
  ErrorState,
  Input,
  LoadingBlock,
  Modal,
  Mono,
  Pagination,
  Select,
  SeverityBadge,
  StatusBadge,
  Textarea,
} from '@/components/ui'
import { useToast } from '@/components/ui/toast'
import { useCreateIncident, useIncidents } from '@/hooks/queries'
import { ApiError } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { Permission, can } from '@/lib/permissions'
import { formatRelative, truncate } from '@/lib/format'

export default function IncidentsPage() {
  const [params, setParams] = useSearchParams()
  const { user } = useAuth()
  const toast = useToast()
  const create = useCreateIncident()

  const [creating, setCreating] = useState(false)
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [severity, setSeverity] = useState('medium')

  const page = Number(params.get('page') ?? 1)
  const status = params.getAll('status')
  const search = params.get('search') ?? ''

  const sort = {
    by: params.get('sort_by') ?? 'created_at',
    dir: (params.get('sort_dir') ?? 'desc') as SortDirection,
  }

  const query = useIncidents({
    page,
    page_size: 25,
    status,
    search: search || undefined,
    sort_by: sort.by,
    sort_dir: sort.dir,
  })

  const onSort = (field: string, direction: SortDirection) => {
    const next = new URLSearchParams(params)
    next.set('sort_by', field)
    next.set('sort_dir', direction)
    next.delete('page')
    setParams(next)
  }

  const update = (key: string, value: string | null) => {
    const next = new URLSearchParams(params)
    next.delete('page')
    if (!value) next.delete(key)
    else next.set(key, value)
    setParams(next)
  }

  const submit = async () => {
    try {
      const incident = await create.mutateAsync({ title, description, severity })
      toast.push(`Created ${incident.incident_uid}.`, 'success')
      setCreating(false)
      setTitle('')
      setDescription('')
    } catch (error) {
      toast.push(
        error instanceof ApiError ? error.message : 'Could not create incident.',
        'error',
      )
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-base font-semibold text-ink-100">Incidents</h1>
          <p className="mt-0.5 text-2xs text-ink-400">
            {query.data ? `${query.data.total.toLocaleString()} matching` : 'Loading…'}
          </p>
        </div>
        {can(user, Permission.INCIDENT_CREATE) ? (
          <Button variant="primary" onClick={() => setCreating(true)}>
            New incident
          </Button>
        ) : null}
      </div>

      <Card className="p-3 flex flex-wrap gap-2">
        <Input
          className="max-w-xs"
          placeholder="Search title or reference…"
          defaultValue={search}
          onKeyDown={(event) => {
            if (event.key === 'Enter') update('search', (event.target as HTMLInputElement).value)
          }}
          aria-label="Search incidents"
        />
        <Select
          value={status[0] ?? ''}
          onChange={(event) => update('status', event.target.value || null)}
          aria-label="Status filter"
        >
          <option value="">Any status</option>
          {['open', 'investigating', 'contained', 'resolved', 'closed'].map((value) => (
            <option key={value} value={value}>
              {value.replace(/_/g, ' ')}
            </option>
          ))}
        </Select>
      </Card>

      <Card>
        {query.isLoading ? (
          <LoadingBlock label="Loading incidents" />
        ) : query.isError ? (
          <ErrorState message="Could not load incidents." onRetry={() => query.refetch()} />
        ) : query.data && query.data.items.length ? (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-left" data-testid="incidents-table">
                <thead>
                  <tr className="border-b border-surface-800">
                    <PlainHeader label="Reference" />
                    <PlainHeader label="Title" />
                    <SortableHeader
                      label="Severity" field="severity" sort={sort} onSort={onSort}
                      defaultDirection="desc"
                      ascLabel="least severe first" descLabel="most severe first"
                    />
                    <SortableHeader label="Status" field="status" sort={sort} onSort={onSort} />
                    <PlainHeader label="Owner" />
                    <SortableHeader
                      label="Opened" field="created_at" sort={sort} onSort={onSort}
                      defaultDirection="desc" align="right" className="text-right"
                      ascLabel="oldest first" descLabel="newest first"
                    />
                  </tr>
                </thead>
                <tbody className="divide-y divide-surface-800">
                  {query.data.items.map((incident) => (
                    <tr key={incident.id} className="hover:bg-surface-850">
                      <td className="px-4 py-2.5">
                        <Link to={`/incidents/${incident.id}`}>
                          <Mono className="text-accent">{incident.incident_uid}</Mono>
                        </Link>
                      </td>
                      <td className="px-4 py-2.5 max-w-md">
                        <Link
                          to={`/incidents/${incident.id}`}
                          className="text-xs text-ink-100 hover:text-accent"
                        >
                          {truncate(incident.title, 70)}
                        </Link>
                      </td>
                      <td className="px-4 py-2.5">
                        <SeverityBadge severity={incident.severity} />
                      </td>
                      <td className="px-4 py-2.5">
                        <StatusBadge status={incident.status} />
                      </td>
                      <td className="px-4 py-2.5 text-2xs text-ink-300 truncate max-w-[10rem]">
                        {incident.assigned_to?.email ?? (
                          <span className="text-ink-400">Unassigned</span>
                        )}
                      </td>
                      <td className="px-4 py-2.5 text-2xs text-ink-400 tabular text-right whitespace-nowrap">
                        {formatRelative(incident.created_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination
              page={query.data.page}
              pages={query.data.pages}
              total={query.data.total}
              pageSize={query.data.page_size}
              onChange={(next) => update('page', String(next))}
            />
          </>
        ) : (
          <EmptyState
            title="No incidents"
            hint="Escalate an alert, or open one manually."
          />
        )}
      </Card>

      <Modal open={creating} title="Open a new incident" onClose={() => setCreating(false)}>
        <div className="space-y-3">
          <div>
            <label htmlFor="incident-title" className="block text-2xs text-ink-300 mb-1">
              Title
            </label>
            <Input
              id="incident-title"
              value={title}
              onChange={(event) => setTitle(event.target.value)}
              placeholder="Short description of what happened"
            />
          </div>
          <div>
            <label htmlFor="incident-severity" className="block text-2xs text-ink-300 mb-1">
              Severity
            </label>
            <Select
              id="incident-severity"
              value={severity}
              onChange={(event) => setSeverity(event.target.value)}
            >
              {['critical', 'high', 'medium', 'low', 'info'].map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </Select>
          </div>
          <div>
            <label htmlFor="incident-description" className="block text-2xs text-ink-300 mb-1">
              Description
            </label>
            <Textarea
              id="incident-description"
              rows={4}
              value={description}
              onChange={(event) => setDescription(event.target.value)}
            />
          </div>
          <div className="flex justify-end gap-2">
            <Button onClick={() => setCreating(false)}>Cancel</Button>
            <Button
              variant="primary"
              disabled={title.trim().length < 3 || create.isPending}
              onClick={submit}
            >
              Create
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
