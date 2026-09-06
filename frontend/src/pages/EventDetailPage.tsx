import { Link, useParams } from 'react-router-dom'

import { Card, CardHeader, ErrorState, LoadingBlock, Mono, SeverityBadge } from '@/components/ui'
import { useEvent } from '@/hooks/queries'
import { formatNumber, formatTimestamp, titleCase } from '@/lib/format'

function Field({ label, value, link }: { label: string; value: unknown; link?: string }) {
  if (value === null || value === undefined || value === '') return null
  const text = String(value)
  return (
    <div className="flex justify-between gap-4 py-1 border-b border-surface-800/60 last:border-0">
      <dt className="text-2xs text-ink-400 shrink-0">{label}</dt>
      <dd className="text-2xs text-ink-100 font-mono text-right break-all">
        {link ? (
          <Link to={link} className="text-accent hover:underline">
            {text}
          </Link>
        ) : (
          text
        )}
      </dd>
    </div>
  )
}

export default function EventDetailPage() {
  const { eventId } = useParams<{ eventId: string }>()
  const query = useEvent(eventId)

  if (query.isLoading) return <LoadingBlock label="Loading event" />
  if (query.isError || !query.data) {
    return <ErrorState message="Could not load this event." onRetry={() => query.refetch()} />
  }

  const event = query.data

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <SeverityBadge severity={event.severity} />
            <Mono className="text-ink-400">{event.event_uid}</Mono>
          </div>
          <h1 className="mt-1.5 text-base font-semibold text-ink-100">
            {titleCase(event.event_type)} · {event.action}
          </h1>
          <p className="mt-0.5 text-2xs text-ink-400">{event.message}</p>
        </div>
        <Link to="/events" className="text-2xs text-accent hover:underline">
          ← Back to events
        </Link>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title="Normalized fields" subtitle="What the detection engine sees" />
          <dl className="p-4">
            <Field label="Timestamp" value={formatTimestamp(event.timestamp)} />
            <Field label="Ingested" value={formatTimestamp(event.ingested_at)} />
            <Field label="Source system" value={event.source} />
            <Field label="Event type" value={event.event_type} />
            <Field label="Action" value={event.action} />
            <Field label="Outcome" value={event.outcome} />
            <Field
              label="Source IP"
              value={event.src_ip}
              link={event.src_ip ? `/investigate?ip=${encodeURIComponent(event.src_ip)}` : undefined}
            />
            <Field label="Source port" value={event.src_port} />
            <Field
              label="Destination IP"
              value={event.dst_ip}
              link={event.dst_ip ? `/investigate?ip=${encodeURIComponent(event.dst_ip)}` : undefined}
            />
            <Field label="Destination port" value={event.dst_port} />
            <Field label="Protocol" value={event.protocol} />
            <Field label="Account" value={event.username} />
            <Field label="Host" value={event.hostname} />
            <Field label="Location" value={[event.city, event.country_code].filter(Boolean).join(', ')} />
            <Field label="Process" value={event.process_name} />
            <Field label="Command line" value={event.command_line} />
            <Field label="File path" value={event.file_path} />
            <Field label="File hash" value={event.file_hash} />
            <Field label="HTTP method" value={event.http_method} />
            <Field label="URL path" value={event.url_path} />
            <Field label="HTTP status" value={event.http_status} />
            <Field label="DNS query" value={event.dns_query} />
            <Field label="User agent" value={event.user_agent} />
            <Field label="Bytes sent" value={event.bytes_sent ? formatNumber(event.bytes_sent) : null} />
            <Field label="Bytes received" value={event.bytes_received ? formatNumber(event.bytes_received) : null} />
            <Field label="Analyzed" value={event.analyzed ? 'yes' : 'no'} />
          </dl>
        </Card>

        <Card>
          <CardHeader
            title="Raw source document"
            subtitle="Exactly what arrived, before normalization"
          />
          <div className="p-4">
            {/* Rendered as text inside <pre>. React escapes it, so a hostile
                payload in the raw document is displayed, never interpreted. */}
            <pre className="overflow-x-auto rounded bg-surface-950 p-3 text-2xs text-ink-200 font-mono">
              {JSON.stringify(event.raw, null, 2)}
            </pre>
          </div>
        </Card>
      </div>
    </div>
  )
}
