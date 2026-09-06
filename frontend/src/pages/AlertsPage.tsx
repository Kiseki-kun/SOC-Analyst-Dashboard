import { Link, useSearchParams } from 'react-router-dom'

import { PlainHeader, SortableHeader } from '@/components/SortableHeader'
import type { SortDirection } from '@/components/SortableHeader'
import {
  Card,
  EmptyState,
  ErrorState,
  Input,
  LoadingBlock,
  Mono,
  Pagination,
  Select,
  SeverityBadge,
  StatusBadge,
} from '@/components/ui'
import { useAlerts } from '@/hooks/queries'
import { formatRelative, truncate } from '@/lib/format'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
const STATUSES = ['new', 'in_review', 'escalated', 'resolved', 'false_positive']

export default function AlertsPage() {
  // Filters live in the URL so an analyst can bookmark a queue and share it
  // with a colleague — "the unassigned criticals" becomes a link.
  const [params, setParams] = useSearchParams()

  const page = Number(params.get('page') ?? 1)
  const severity = params.getAll('severity')
  const status = params.getAll('status')
  const search = params.get('search') ?? ''
  const unassigned = params.get('unassigned') === 'true'

  const sort = {
    by: params.get('sort_by') ?? 'created_at',
    dir: (params.get('sort_dir') ?? 'desc') as SortDirection,
  }

  const query = useAlerts({
    page,
    page_size: 25,
    severity,
    status,
    search: search || undefined,
    unassigned: unassigned || undefined,
    sort_by: sort.by,
    sort_dir: sort.dir,
  })

  const update = (key: string, value: string | null) => {
    const next = new URLSearchParams(params)
    next.delete('page')
    if (value === null || value === '') next.delete(key)
    else next.set(key, value)
    setParams(next)
  }

  const onSort = (field: string, direction: SortDirection) => {
    const next = new URLSearchParams(params)
    next.set('sort_by', field)
    next.set('sort_dir', direction)
    // Filters and search are untouched; only the page resets.
    next.delete('page')
    setParams(next)
  }

  const toggleMulti = (key: string, value: string) => {
    const next = new URLSearchParams(params)
    const existing = next.getAll(key)
    next.delete(key)
    next.delete('page')
    const updated = existing.includes(value)
      ? existing.filter((item) => item !== value)
      : [...existing, value]
    updated.forEach((item) => next.append(key, item))
    setParams(next)
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-base font-semibold text-ink-100">Alerts</h1>
          <p className="mt-0.5 text-2xs text-ink-400">
            {query.data ? `${query.data.total.toLocaleString()} matching` : 'Loading…'}
          </p>
        </div>
      </div>

      {/* Filters in one row above the table, per the console convention. */}
      <Card className="p-3 space-y-2.5">
        <div className="flex flex-wrap items-center gap-2">
          <Input
            className="max-w-xs"
            placeholder="Search title, address or account…"
            defaultValue={search}
            onKeyDown={(event) => {
              if (event.key === 'Enter') update('search', (event.target as HTMLInputElement).value)
            }}
            aria-label="Search alerts"
          />
          <Select
            value={unassigned ? 'true' : ''}
            onChange={(event) => update('unassigned', event.target.value || null)}
            aria-label="Assignment filter"
          >
            <option value="">Any assignment</option>
            <option value="true">Unassigned only</option>
          </Select>
        </div>

        <div className="flex flex-wrap gap-1.5">
          <span className="text-2xs text-ink-400 self-center mr-1">Severity</span>
          {SEVERITIES.map((value) => (
            <button
              key={value}
              onClick={() => toggleMulti('severity', value)}
              aria-pressed={severity.includes(value)}
              className={`rounded border px-2 py-0.5 text-2xs capitalize transition-colors ${
                severity.includes(value)
                  ? 'border-accent bg-accent/15 text-ink-100'
                  : 'border-surface-700 text-ink-300 hover:text-ink-100'
              }`}
            >
              {value}
            </button>
          ))}
        </div>

        <div className="flex flex-wrap gap-1.5">
          <span className="text-2xs text-ink-400 self-center mr-1">Status</span>
          {STATUSES.map((value) => (
            <button
              key={value}
              onClick={() => toggleMulti('status', value)}
              aria-pressed={status.includes(value)}
              className={`rounded border px-2 py-0.5 text-2xs transition-colors ${
                status.includes(value)
                  ? 'border-accent bg-accent/15 text-ink-100'
                  : 'border-surface-700 text-ink-300 hover:text-ink-100'
              }`}
            >
              {value.replace(/_/g, ' ')}
            </button>
          ))}
        </div>
      </Card>

      <Card>
        {query.isLoading ? (
          <LoadingBlock label="Loading alerts" />
        ) : query.isError ? (
          <ErrorState message="Could not load alerts." onRetry={() => query.refetch()} />
        ) : query.data && query.data.items.length > 0 ? (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-left" data-testid="alerts-table">
                <thead>
                  <tr className="border-b border-surface-800">
                    <SortableHeader
                      label="Severity" field="severity" sort={sort} onSort={onSort}
                      defaultDirection="desc"
                      ascLabel="least severe first" descLabel="most severe first"
                    />
                    <SortableHeader
                      label="Alert" field="rule_key" sort={sort} onSort={onSort}
                    />
                    <SortableHeader label="Source" field="src_ip" sort={sort} onSort={onSort} />
                    <PlainHeader label="ATT&amp;CK" />
                    <SortableHeader label="Status" field="status" sort={sort} onSort={onSort} />
                    <PlainHeader label="Assignee" />
                    <SortableHeader
                      label="Age" field="created_at" sort={sort} onSort={onSort}
                      defaultDirection="desc" align="right" className="text-right"
                      ascLabel="oldest first" descLabel="newest first"
                    />
                  </tr>
                </thead>
                <tbody className="divide-y divide-surface-800">
                  {query.data.items.map((alert) => (
                    <tr key={alert.id} className="hover:bg-surface-850">
                      <td className="px-4 py-2.5">
                        <SeverityBadge severity={alert.severity} />
                      </td>
                      <td className="px-4 py-2.5 max-w-md">
                        <Link
                          to={`/alerts/${alert.id}`}
                          className="text-xs text-ink-100 hover:text-accent"
                        >
                          {truncate(alert.title, 70)}
                        </Link>
                        <p className="text-2xs text-ink-400 mt-0.5">
                          {alert.alert_uid} · {alert.event_count} events · {alert.confidence}%
                          confidence
                        </p>
                      </td>
                      <td className="px-4 py-2.5">
                        {alert.src_ip ? (
                          <Link
                            to={`/investigate?ip=${encodeURIComponent(alert.src_ip)}`}
                            className="hover:text-accent"
                          >
                            <Mono>{alert.src_ip}</Mono>
                          </Link>
                        ) : (
                          <span className="text-2xs text-ink-400">—</span>
                        )}
                      </td>
                      <td className="px-4 py-2.5">
                        <Mono className="text-ink-300">{alert.mitre_technique_id ?? '—'}</Mono>
                      </td>
                      <td className="px-4 py-2.5">
                        <StatusBadge status={alert.status} />
                      </td>
                      <td className="px-4 py-2.5 text-2xs text-ink-300 truncate max-w-[10rem]">
                        {alert.assigned_to?.email ?? (
                          <span className="text-ink-400">Unassigned</span>
                        )}
                      </td>
                      <td className="px-4 py-2.5 text-2xs text-ink-400 tabular text-right whitespace-nowrap">
                        {formatRelative(alert.created_at)}
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
            title="No alerts match these filters"
            hint="Clear a filter, or wait for the generator to produce suspicious activity."
          />
        )}
      </Card>
    </div>
  )
}
