import { Link } from 'react-router-dom'

import { StatTile } from '@/components/StatTile'
import { AuthTrendChart, SeverityBars, VolumeArea } from '@/components/charts'
import {
  Card,
  CardHeader,
  EmptyState,
  ErrorState,
  LoadingBlock,
  Mono,
  SeverityBadge,
  StatusBadge,
} from '@/components/ui'
import { useAlerts, useAnalyticsOverview } from '@/hooks/queries'
import { formatRelative, truncate } from '@/lib/format'
import type { Severity } from '@/types/api'

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export default function DashboardPage() {
  const overview = useAnalyticsOverview(24, 7)
  const recentAlerts = useAlerts({ page_size: 8, sort_by: 'created_at', sort_dir: 'desc' })

  if (overview.isLoading) return <LoadingBlock label="Loading dashboard" />
  if (overview.isError || !overview.data) {
    return (
      <ErrorState
        message="Could not load dashboard data."
        onRetry={() => overview.refetch()}
      />
    )
  }

  const { summary, events_over_time, authentication_trend, top_source_ips } = overview.data

  const severityData = SEVERITY_ORDER.map((severity) => ({
    severity,
    count: summary.alerts_by_severity[severity] ?? 0,
  })).filter((entry) => entry.count > 0)

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-base font-semibold text-ink-100">Security Operations Overview</h1>
        <p className="mt-0.5 text-2xs text-ink-400">
          Live view of synthetic telemetry · updated {formatRelative(summary.generated_at)}
        </p>
      </div>

      <div className="grid gap-3 grid-cols-2 lg:grid-cols-4">
        <StatTile
          label="Open alerts"
          value={summary.open_alerts}
          hint={`${summary.unassigned_open_alerts} unassigned`}
          tone={summary.open_alerts > 0 ? 'warning' : 'neutral'}
          to="/alerts?status=new"
        />
        <StatTile
          label="Critical & high"
          value={summary.critical_high_open_alerts}
          hint="Open, needs triage"
          tone={summary.critical_high_open_alerts > 0 ? 'critical' : 'ok'}
          to="/alerts?severity=critical&severity=high"
        />
        <StatTile
          label="Open incidents"
          value={summary.open_incidents}
          hint="Not yet resolved"
          to="/incidents"
        />
        <StatTile
          label="Events / 24h"
          value={summary.events_last_24h}
          hint={`${summary.events_last_hour.toLocaleString()} in the last hour`}
          to="/events"
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader
            title="Event volume"
            subtitle="All sources, last 24 hours"
          />
          <div className="p-3">
            {events_over_time.length ? (
              <VolumeArea data={events_over_time} height={190} />
            ) : (
              <EmptyState title="No events in this window" hint="The generator may still be starting." />
            )}
          </div>
        </Card>

        <Card>
          <CardHeader title="Open alerts by severity" subtitle="Current backlog" />
          <div className="p-3">
            {severityData.length ? (
              <SeverityBars data={severityData} height={190} />
            ) : (
              <EmptyState title="No open alerts" hint="Nothing is waiting for triage." />
            )}
          </div>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader
            title="Authentication outcomes"
            subtitle={`${summary.auth_failures_last_24h.toLocaleString()} failures in the last 24 hours`}
          />
          <div className="p-3">
            {authentication_trend.length ? (
              <AuthTrendChart data={authentication_trend} height={200} />
            ) : (
              <EmptyState title="No authentication activity yet" />
            )}
          </div>
        </Card>

        <Card>
          <CardHeader title="Most active sources" subtitle="Last 24 hours" />
          <div className="divide-y divide-surface-800">
            {top_source_ips.length ? (
              top_source_ips.slice(0, 8).map((entry) => (
                <Link
                  key={entry.ip}
                  to={`/investigate?ip=${encodeURIComponent(entry.ip)}`}
                  className="flex items-center justify-between gap-2 px-4 py-2 hover:bg-surface-850"
                >
                  <Mono>{entry.ip}</Mono>
                  <span className="text-2xs text-ink-300 tabular">
                    {entry.event_count.toLocaleString()}
                    {entry.failure_count ? (
                      <span className="text-severity-high"> · {entry.failure_count} failed</span>
                    ) : null}
                  </span>
                </Link>
              ))
            ) : (
              <EmptyState title="No source activity recorded" />
            )}
          </div>
        </Card>
      </div>

      <Card>
        <CardHeader
          title="Latest alerts"
          actions={
            <Link to="/alerts" className="text-2xs text-accent hover:underline">
              View all
            </Link>
          }
        />
        {recentAlerts.isLoading ? (
          <LoadingBlock />
        ) : recentAlerts.data?.items.length ? (
          <ul className="divide-y divide-surface-800">
            {recentAlerts.data.items.map((alert) => (
              <li key={alert.id}>
                <Link
                  to={`/alerts/${alert.id}`}
                  className="flex items-center gap-3 px-4 py-2.5 hover:bg-surface-850"
                >
                  <SeverityBadge severity={alert.severity} />
                  <span className="min-w-0 flex-1 truncate text-xs text-ink-100">
                    {truncate(alert.title, 90)}
                  </span>
                  <StatusBadge status={alert.status} />
                  <span className="hidden sm:inline text-2xs text-ink-400 tabular w-20 text-right">
                    {formatRelative(alert.created_at)}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        ) : (
          <EmptyState
            title="No alerts yet"
            hint="Detections fire as the generator produces suspicious activity."
          />
        )}
      </Card>
    </div>
  )
}
