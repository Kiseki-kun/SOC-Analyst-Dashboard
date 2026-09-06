import { useState } from 'react'

import { RankedBars, SeverityBars, VolumeArea, AuthTrendChart, SERIES } from '@/components/charts'
import { StatTile } from '@/components/StatTile'
import { Card, CardHeader, EmptyState, ErrorState, LoadingBlock, Select } from '@/components/ui'
import { useAnalyticsOverview } from '@/hooks/queries'
import { formatDuration, titleCase } from '@/lib/format'
import type { Severity } from '@/types/api'

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export default function AnalyticsPage() {
  const [hours, setHours] = useState(24)
  const [days, setDays] = useState(7)
  const query = useAnalyticsOverview(hours, days)

  if (query.isLoading) return <LoadingBlock label="Loading analytics" />
  if (query.isError || !query.data) {
    return <ErrorState message="Could not load analytics." onRetry={() => query.refetch()} />
  }

  const data = query.data
  const metrics = data.response_metrics

  const severityData = SEVERITY_ORDER.map((severity) => ({
    severity,
    count: data.summary.alerts_by_severity[severity] ?? 0,
  })).filter((entry) => entry.count > 0)

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-base font-semibold text-ink-100">Analytics</h1>
          <p className="mt-0.5 text-2xs text-ink-400">
            Every figure is computed from stored events, alerts and incidents.
          </p>
        </div>
        {/* Filters in one row above the charts. */}
        <div className="flex gap-2">
          <Select
            value={hours}
            onChange={(event) => setHours(Number(event.target.value))}
            aria-label="Event window"
          >
            <option value={6}>Last 6 hours</option>
            <option value={24}>Last 24 hours</option>
            <option value={72}>Last 3 days</option>
            <option value={168}>Last 7 days</option>
          </Select>
          <Select
            value={days}
            onChange={(event) => setDays(Number(event.target.value))}
            aria-label="Alert window"
          >
            <option value={1}>Alerts: 1 day</option>
            <option value={7}>Alerts: 7 days</option>
            <option value={30}>Alerts: 30 days</option>
          </Select>
        </div>
      </div>

      <div className="grid gap-3 grid-cols-2 lg:grid-cols-4">
        <StatTile
          label="Mean time to acknowledge"
          value={formatDuration(metrics.mean_time_to_acknowledge_minutes)}
          hint={`${metrics.incidents_acknowledged} incident(s), ${metrics.window_days}d`}
        />
        <StatTile
          label="Mean time to contain"
          value={formatDuration(metrics.mean_time_to_contain_minutes)}
          hint="From opening to containment"
        />
        <StatTile
          label="Mean time to resolve"
          value={formatDuration(metrics.mean_time_to_resolve_minutes)}
          hint={`${metrics.incidents_resolved} resolved`}
        />
        <StatTile
          label="Events analysed"
          value={data.summary.total_events}
          hint="All time"
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title="Event volume" subtitle={`Last ${hours} hours`} />
          <div className="p-3">
            {data.events_over_time.length ? (
              <VolumeArea data={data.events_over_time} height={200} />
            ) : (
              <EmptyState title="No events in this window" />
            )}
          </div>
        </Card>

        <Card>
          <CardHeader title="Alert volume" subtitle={`Last ${hours} hours`} />
          <div className="p-3">
            {data.alerts_over_time.length ? (
              <VolumeArea data={data.alerts_over_time} color={SERIES[1]} height={200} />
            ) : (
              <EmptyState title="No alerts in this window" />
            )}
          </div>
        </Card>

        <Card>
          <CardHeader
            title="Authentication outcomes"
            subtitle="Solid = successful, dashed = failed"
          />
          <div className="p-3">
            {data.authentication_trend.length ? (
              <AuthTrendChart data={data.authentication_trend} height={200} />
            ) : (
              <EmptyState title="No authentication activity" />
            )}
          </div>
        </Card>

        <Card>
          <CardHeader title="Open alerts by severity" />
          <div className="p-3">
            {severityData.length ? (
              <SeverityBars data={severityData} height={200} />
            ) : (
              <EmptyState title="No open alerts" />
            )}
          </div>
        </Card>

        <Card>
          <CardHeader title="Most triggered detections" subtitle={`Last ${days} days`} />
          <div className="p-3">
            {data.top_detection_rules.length ? (
              <RankedBars
                data={data.top_detection_rules.map((entry) => ({
                  ...entry,
                  rule_key: titleCase(entry.rule_key),
                }))}
                labelKey="rule_key"
                valueKey="alert_count"
                height={220}
              />
            ) : (
              <EmptyState title="No detections have fired yet" />
            )}
          </div>
        </Card>

        <Card>
          <CardHeader title="Busiest source addresses" subtitle={`Last ${hours} hours`} />
          <div className="p-3">
            {data.top_source_ips.length ? (
              <RankedBars
                data={data.top_source_ips}
                labelKey="ip"
                valueKey="event_count"
                height={220}
                color={SERIES[2]}
              />
            ) : (
              <EmptyState title="No source activity" />
            )}
          </div>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader
            title="MITRE ATT&CK coverage"
            subtitle={`Techniques observed in the last ${days} days`}
          />
          {data.mitre_distribution.length ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-surface-800 text-2xs uppercase tracking-wide text-ink-400">
                    <th className="px-4 py-2 font-medium">Technique</th>
                    <th className="px-4 py-2 font-medium">Name</th>
                    <th className="px-4 py-2 font-medium">Tactic</th>
                    <th className="px-4 py-2 font-medium text-right">Alerts</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-surface-800">
                  {data.mitre_distribution.map((entry) => (
                    <tr key={entry.technique_id} className="hover:bg-surface-850">
                      <td className="px-4 py-2">
                        <a
                          href={`https://attack.mitre.org/techniques/${entry.technique_id.replace('.', '/')}/`}
                          target="_blank"
                          rel="noreferrer noopener"
                          className="font-mono text-2xs text-accent hover:underline"
                        >
                          {entry.technique_id}
                        </a>
                      </td>
                      <td className="px-4 py-2 text-2xs text-ink-100">{entry.technique_name}</td>
                      <td className="px-4 py-2 text-2xs text-ink-300">{entry.tactic}</td>
                      <td className="px-4 py-2 text-2xs text-ink-100 tabular text-right">
                        {entry.alert_count}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState title="No techniques observed yet" />
          )}
        </Card>

        <Card>
          <CardHeader title="Event mix" subtitle={`Last ${hours} hours`} />
          {data.event_type_distribution.length ? (
            <ul className="divide-y divide-surface-800">
              {data.event_type_distribution.map((entry) => {
                const total = data.event_type_distribution.reduce((sum, e) => sum + e.count, 0)
                const share = total ? Math.round((entry.count / total) * 100) : 0
                return (
                  <li key={entry.event_type} className="px-4 py-2">
                    <div className="flex items-center justify-between gap-3 text-2xs">
                      <span className="text-ink-100">{titleCase(entry.event_type)}</span>
                      <span className="text-ink-300 tabular">
                        {entry.count.toLocaleString()} · {share}%
                      </span>
                    </div>
                    <div className="mt-1 h-1 rounded bg-surface-800 overflow-hidden">
                      <div
                        className="h-full rounded bg-accent"
                        style={{ width: `${share}%` }}
                        aria-hidden
                      />
                    </div>
                  </li>
                )
              })}
            </ul>
          ) : (
            <EmptyState title="No events in this window" />
          )}
        </Card>
      </div>
    </div>
  )
}
