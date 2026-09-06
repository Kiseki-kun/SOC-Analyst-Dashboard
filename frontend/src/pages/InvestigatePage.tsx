import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import clsx from 'clsx'

import { PlainHeader, SortableHeader } from '@/components/SortableHeader'
import { useTableSort } from '@/hooks/useTableSort'
import {
  Button,
  Card,
  CardHeader,
  EmptyState,
  ErrorState,
  Input,
  LoadingBlock,
  Mono,
  Pill,
  SeverityBadge,
  StatusBadge,
} from '@/components/ui'
import { StatTile } from '@/components/StatTile'
import { useIpInvestigation } from '@/hooks/queries'
import { formatTimestamp, titleCase } from '@/lib/format'

const VERDICT_STYLE = {
  malicious: 'border-severity-critical/50 bg-severity-critical/10',
  suspicious: 'border-severity-medium/50 bg-severity-medium/10',
  benign: 'border-ok/40 bg-ok/10',
} as const

export default function InvestigatePage() {
  const [params, setParams] = useSearchParams()
  const ip = params.get('ip') ?? ''
  const [input, setInput] = useState(ip)

  const query = useIpInvestigation(ip || undefined)

  // Recent activity for an address arrives complete in one response, so it
  // sorts client-side. Chronological order in both directions is the whole
  // point of this table during an investigation.
  const recent = useTableSort(
    query.data?.recent_events ?? [],
    {
      timestamp: (event) => event.timestamp,
      event_type: (event) => event.event_type,
      username: (event) => event.username,
      outcome: (event) => event.outcome,
    },
    { by: 'timestamp', dir: 'desc' },
  )

  const submit = () => {
    const next = new URLSearchParams()
    if (input.trim()) next.set('ip', input.trim())
    setParams(next)
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-base font-semibold text-ink-100">IP investigation</h1>
        <p className="mt-0.5 text-2xs text-ink-400">
          Pivot on an address across events, alerts and incidents.
        </p>
      </div>

      <Card className="p-3 flex flex-wrap gap-2">
        <Input
          className="max-w-xs"
          value={input}
          onChange={(event) => setInput(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter') submit()
          }}
          placeholder="203.0.113.99"
          aria-label="IP address to investigate"
        />
        <Button variant="primary" onClick={submit}>
          Investigate
        </Button>
      </Card>

      {!ip ? (
        <Card>
          <EmptyState
            title="Enter an address to begin"
            hint="Source addresses throughout the console link here."
          />
        </Card>
      ) : query.isLoading ? (
        <LoadingBlock label={`Investigating ${ip}`} />
      ) : query.isError ? (
        <Card>
          <ErrorState message={`Could not investigate ${ip}. Check that it is a valid IP address.`} />
        </Card>
      ) : query.data ? (
        <>
          <div
            className={clsx(
              'rounded-lg border p-4',
              VERDICT_STYLE[query.data.reputation.verdict],
            )}
          >
            <div className="flex flex-wrap items-center gap-3">
              <Mono className="text-sm text-ink-100">{query.data.ip_address}</Mono>
              <span className="rounded border border-surface-600 bg-surface-900 px-2 py-0.5 text-2xs font-medium uppercase tracking-wide text-ink-100">
                {query.data.reputation.verdict}
              </span>
              <span className="text-2xs text-ink-300 tabular">
                Local risk score {query.data.reputation.score}/100
              </span>
              {query.data.reputation.on_watchlist ? <Pill>On watchlist</Pill> : null}
            </div>

            {/* The verdict is always shown with its reasoning. An opaque score
                cannot be argued with, and an analyst must be able to disagree. */}
            <ul className="mt-2.5 space-y-0.5">
              {query.data.reputation.basis.map((reason) => (
                <li key={reason} className="text-2xs text-ink-200">
                  · {reason}
                </li>
              ))}
            </ul>

            <p className="mt-2.5 text-2xs text-ink-400">
              This verdict is derived only from data inside this application. No external threat
              intelligence service is consulted, and the score has no meaning outside this project.
            </p>
          </div>

          <div className="grid gap-3 grid-cols-2 lg:grid-cols-4">
            <StatTile label="Total events" value={query.data.summary.total_events} />
            <StatTile
              label="Failed authentications"
              value={query.data.summary.failed_authentications}
              tone={query.data.summary.failed_authentications > 0 ? 'warning' : 'neutral'}
            />
            <StatTile
              label="Distinct ports contacted"
              value={query.data.summary.distinct_destination_ports}
            />
            <StatTile
              label="Distinct hosts contacted"
              value={query.data.summary.distinct_destination_hosts}
            />
          </div>

          <div className="grid gap-4 lg:grid-cols-3">
            <Card>
              <CardHeader title="Activity window" />
              <dl className="p-4 space-y-1.5 text-2xs">
                <div className="flex justify-between gap-3">
                  <dt className="text-ink-400">First seen</dt>
                  <dd className="text-ink-100 font-mono">
                    {formatTimestamp(query.data.summary.first_seen)}
                  </dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt className="text-ink-400">Last seen</dt>
                  <dd className="text-ink-100 font-mono">
                    {formatTimestamp(query.data.summary.last_seen)}
                  </dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt className="text-ink-400">Connections</dt>
                  <dd className="text-ink-100 tabular">
                    {query.data.summary.connection_count.toLocaleString()}
                  </dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt className="text-ink-400">Successful logins</dt>
                  <dd className="text-ink-100 tabular">
                    {query.data.summary.successful_authentications.toLocaleString()}
                  </dd>
                </div>
              </dl>
            </Card>

            <Card>
              <CardHeader title="Associated accounts" />
              <div className="p-4 flex flex-wrap gap-1.5">
                {query.data.associated_usernames.length ? (
                  query.data.associated_usernames.map((name) => <Pill key={name}>{name}</Pill>)
                ) : (
                  <p className="text-2xs text-ink-400">None observed.</p>
                )}
              </div>
            </Card>

            <Card>
              <CardHeader title="Ports contacted" />
              <div className="p-4 flex flex-wrap gap-1.5">
                {query.data.top_destination_ports.length ? (
                  query.data.top_destination_ports.map((port) => <Pill key={port}>{port}</Pill>)
                ) : (
                  <p className="text-2xs text-ink-400">None observed.</p>
                )}
              </div>
            </Card>
          </div>

          <Card>
            <CardHeader
              title="Related alerts"
              subtitle={
                query.data.related_incident_uids.length
                  ? `Also referenced by incident(s): ${query.data.related_incident_uids.join(', ')}`
                  : undefined
              }
            />
            {query.data.related_alerts.length ? (
              <ul className="divide-y divide-surface-800">
                {query.data.related_alerts.map((alert) => (
                  <li key={alert.id}>
                    <Link
                      to={`/alerts/${alert.id}`}
                      className="flex items-center gap-3 px-4 py-2.5 hover:bg-surface-850"
                    >
                      <SeverityBadge severity={alert.severity} />
                      <span className="min-w-0 flex-1 truncate text-xs text-ink-100">
                        {alert.title}
                      </span>
                      <StatusBadge status={alert.status} />
                    </Link>
                  </li>
                ))}
              </ul>
            ) : (
              <EmptyState title="No alerts reference this address" />
            )}
          </Card>

          <Card>
            <CardHeader title="Recent events" subtitle="Newest first" />
            {query.data.recent_events.length ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left" data-testid="ip-events-table">
                  <thead>
                    <tr className="border-b border-surface-800">
                      <SortableHeader
                        label="Time" field="timestamp" sort={recent.sort} onSort={recent.onSort}
                        defaultDirection="desc" ascLabel="oldest first" descLabel="newest first"
                      />
                      <SortableHeader
                        label="Type" field="event_type" sort={recent.sort} onSort={recent.onSort}
                      />
                      <SortableHeader
                        label="Account" field="username" sort={recent.sort} onSort={recent.onSort}
                      />
                      <SortableHeader
                        label="Outcome" field="outcome" sort={recent.sort} onSort={recent.onSort}
                      />
                      <PlainHeader label="Message" />
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-surface-800">
                    {recent.sorted.map((event) => (
                      <tr key={event.id} className="hover:bg-surface-850">
                        <td className="px-4 py-2 whitespace-nowrap">
                          <Link to={`/events/${event.id}`} className="hover:text-accent">
                            <Mono>{formatTimestamp(event.timestamp)}</Mono>
                          </Link>
                        </td>
                        <td className="px-4 py-2 text-2xs text-ink-300">
                          {titleCase(event.event_type)}
                        </td>
                        <td className="px-4 py-2 text-2xs text-ink-300">{event.username ?? '—'}</td>
                        <td className="px-4 py-2 text-2xs text-ink-300">{event.outcome}</td>
                        <td className="px-4 py-2 text-2xs text-ink-300">{event.message}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState title="No events recorded for this address" />
            )}
          </Card>
        </>
      ) : null}
    </div>
  )
}
