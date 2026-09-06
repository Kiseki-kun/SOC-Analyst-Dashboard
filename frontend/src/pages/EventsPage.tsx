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
} from '@/components/ui'
import { useEvents } from '@/hooks/queries'
import { formatTimestamp, titleCase, truncate } from '@/lib/format'

const EVENT_TYPES = [
  'authentication',
  'network_connection',
  'dns_query',
  'http_request',
  'file_access',
  'process_execution',
  'privilege_change',
  'system_event',
]

export default function EventsPage() {
  const [params, setParams] = useSearchParams()

  const page = Number(params.get('page') ?? 1)
  const query = useEvents({
    page,
    page_size: 50,
    search: params.get('search') || undefined,
    event_type: params.getAll('event_type'),
    severity: params.getAll('severity'),
    outcome: params.getAll('outcome'),
    src_ip: params.get('src_ip') || undefined,
    username: params.get('username') || undefined,
    sort_by: params.get('sort_by') ?? 'timestamp',
    sort_dir: params.get('sort_dir') ?? 'desc',
  })

  const update = (key: string, value: string | null) => {
    const next = new URLSearchParams(params)
    next.delete('page')
    if (!value) next.delete(key)
    else next.set(key, value)
    setParams(next)
  }

  // Sort state lives in the URL alongside the filters, so an analyst can
  // bookmark or share "failed logins from this address, oldest first".
  const sort = {
    by: params.get('sort_by') ?? 'timestamp',
    dir: (params.get('sort_dir') ?? 'desc') as SortDirection,
  }

  const onSort = (field: string, direction: SortDirection) => {
    const next = new URLSearchParams(params)
    next.set('sort_by', field)
    next.set('sort_dir', direction)
    // Only the page is reset. Every filter and search term is preserved:
    // re-ordering a result set must never widen it. Returning to page 1 is
    // deliberate - staying on page 7 of a re-sorted list shows rows that have
    // no relationship to what the analyst was just looking at.
    next.delete('page')
    setParams(next)
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-base font-semibold text-ink-100">Event explorer</h1>
        <p className="mt-0.5 text-2xs text-ink-400">
          {query.data ? `${query.data.total.toLocaleString()} events match` : 'Loading…'}
        </p>
      </div>

      <Card className="p-3 flex flex-wrap gap-2">
        <Input
          className="max-w-sm"
          placeholder="Search message, account, host, URL, command…"
          defaultValue={params.get('search') ?? ''}
          onKeyDown={(event) => {
            if (event.key === 'Enter') update('search', (event.target as HTMLInputElement).value)
          }}
          aria-label="Search events"
        />
        <Select
          value={params.getAll('event_type')[0] ?? ''}
          onChange={(event) => update('event_type', event.target.value || null)}
          aria-label="Event type filter"
        >
          <option value="">Any type</option>
          {EVENT_TYPES.map((value) => (
            <option key={value} value={value}>
              {titleCase(value)}
            </option>
          ))}
        </Select>
        <Select
          value={params.getAll('severity')[0] ?? ''}
          onChange={(event) => update('severity', event.target.value || null)}
          aria-label="Severity filter"
        >
          <option value="">Any severity</option>
          {['critical', 'high', 'medium', 'low', 'info'].map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </Select>
        <Select
          value={params.getAll('outcome')[0] ?? ''}
          onChange={(event) => update('outcome', event.target.value || null)}
          aria-label="Outcome filter"
        >
          <option value="">Any outcome</option>
          {['success', 'failure', 'blocked', 'unknown'].map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </Select>
        <Input
          className="max-w-[10rem]"
          placeholder="Source IP"
          defaultValue={params.get('src_ip') ?? ''}
          onKeyDown={(event) => {
            if (event.key === 'Enter') update('src_ip', (event.target as HTMLInputElement).value)
          }}
          aria-label="Source IP filter"
        />
        <Input
          className="max-w-[10rem]"
          placeholder="Account"
          defaultValue={params.get('username') ?? ''}
          onKeyDown={(event) => {
            if (event.key === 'Enter') update('username', (event.target as HTMLInputElement).value)
          }}
          aria-label="Account filter"
        />
      </Card>

      <Card>
        {query.isLoading ? (
          <LoadingBlock label="Loading events" />
        ) : query.isError ? (
          <ErrorState message="Could not load events." onRetry={() => query.refetch()} />
        ) : query.data && query.data.items.length ? (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-left" data-testid="events-table">
                <thead>
                  <tr className="border-b border-surface-800">
                    <SortableHeader
                      label="Timestamp" field="timestamp" sort={sort} onSort={onSort}
                      defaultDirection="desc" ascLabel="oldest first" descLabel="newest first"
                    />
                    <SortableHeader
                      label="Severity" field="severity" sort={sort} onSort={onSort}
                      defaultDirection="desc"
                      ascLabel="least severe first" descLabel="most severe first"
                    />
                    <SortableHeader label="Type" field="event_type" sort={sort} onSort={onSort} />
                    <SortableHeader label="Source" field="src_ip" sort={sort} onSort={onSort} />
                    {/* Destination and Message are not sortable: neither is indexed
                        for ordering, and sorting free text helps nobody. */}
                    <PlainHeader label="Destination" />
                    <SortableHeader label="Account" field="username" sort={sort} onSort={onSort} />
                    <SortableHeader label="Outcome" field="outcome" sort={sort} onSort={onSort} />
                    <PlainHeader label="Message" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-surface-800">
                  {query.data.items.map((event) => (
                    <tr key={event.id} className="hover:bg-surface-850">
                      <td className="px-3 py-2 whitespace-nowrap">
                        <Link to={`/events/${event.id}`} className="hover:text-accent">
                          <Mono>{formatTimestamp(event.timestamp)}</Mono>
                        </Link>
                      </td>
                      <td className="px-3 py-2">
                        <SeverityBadge severity={event.severity} />
                      </td>
                      <td className="px-3 py-2 text-2xs text-ink-300 whitespace-nowrap">
                        {titleCase(event.event_type)}
                      </td>
                      <td className="px-3 py-2 whitespace-nowrap">
                        {event.src_ip ? (
                          <Link
                            to={`/investigate?ip=${encodeURIComponent(event.src_ip)}`}
                            className="hover:text-accent"
                          >
                            <Mono>
                              {event.src_ip}
                              {event.src_port ? `:${event.src_port}` : ''}
                            </Mono>
                          </Link>
                        ) : (
                          <span className="text-2xs text-ink-400">—</span>
                        )}
                      </td>
                      <td className="px-3 py-2 whitespace-nowrap">
                        <Mono className="text-ink-300">
                          {event.dst_ip ? `${event.dst_ip}${event.dst_port ? `:${event.dst_port}` : ''}` : '—'}
                        </Mono>
                      </td>
                      <td className="px-3 py-2 text-2xs text-ink-300">{event.username ?? '—'}</td>
                      <td className="px-3 py-2 text-2xs">
                        <span
                          className={
                            event.outcome === 'failure'
                              ? 'text-severity-high'
                              : event.outcome === 'blocked'
                                ? 'text-severity-medium'
                                : 'text-ink-300'
                          }
                        >
                          {event.outcome}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-2xs text-ink-300 max-w-xs">
                        {truncate(event.message, 60)}
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
          <EmptyState title="No events match these filters" />
        )}
      </Card>
    </div>
  )
}
