import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'

import { SortableHeader } from '@/components/SortableHeader'
import { useTableSort } from '@/hooks/useTableSort'
import {
  Button,
  Card,
  CardHeader,
  EmptyState,
  ErrorState,
  LoadingBlock,
  Modal,
  Mono,
  Pill,
  Select,
  SeverityBadge,
  Spinner,
  StatusBadge,
  Textarea,
} from '@/components/ui'
import { useToast } from '@/components/ui/toast'
import {
  useAddAlertNote,
  useAlert,
  useAssignAlert,
  useCreateIncident,
  useIncidents,
  useLinkAlertToIncident,
  useUpdateAlertStatus,
} from '@/hooks/queries'
import { ApiError } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { Permission, can } from '@/lib/permissions'
import { formatNumber, formatTimestamp, titleCase, truncate } from '@/lib/format'
import type { AlertStatus } from '@/types/api'

const TERMINAL: AlertStatus[] = ['resolved', 'false_positive']
const TRANSITIONS: AlertStatus[] = ['new', 'in_review', 'escalated', 'resolved', 'false_positive']

export default function AlertDetailPage() {
  const { alertId } = useParams<{ alertId: string }>()
  const navigate = useNavigate()
  const toast = useToast()
  const { user } = useAuth()

  const query = useAlert(alertId)
  const updateStatus = useUpdateAlertStatus(alertId ?? '')
  const assign = useAssignAlert(alertId ?? '')
  const addNote = useAddAlertNote(alertId ?? '')
  const createIncident = useCreateIncident()
  const linkIncident = useLinkAlertToIncident(alertId ?? '')
  // Open incidents an analyst might attach this alert to. Loaded only while
  // the escalation dialog is open.
  const openIncidents = useIncidents({
    status: ['open', 'investigating', 'contained'],
    page_size: 50,
    sort_by: 'created_at',
    sort_dir: 'desc',
  })

  const [note, setNote] = useState('')
  const [closing, setClosing] = useState<AlertStatus | null>(null)
  const [resolution, setResolution] = useState('')
  const [escalating, setEscalating] = useState(false)
  // 'new' creates an incident from this alert; 'existing' attaches it to one
  // that already exists. Forcing the first path produced duplicate incidents
  // for alerts that were obviously part of the same event.
  const [escalationMode, setEscalationMode] = useState<'new' | 'existing'>('new')
  const [targetIncidentId, setTargetIncidentId] = useState('')

  // Evidence events sort client-side: they arrive complete inside the alert
  // detail response, so a round trip to reorder a few dozen rows would be
  // slower and no more correct. Newest first by default, because triage starts
  // from "what just happened".
  const evidence = useTableSort(
    query.data?.events ?? [],
    {
      timestamp: (event) => event.timestamp,
      event_type: (event) => event.event_type,
      src_ip: (event) => event.src_ip,
      username: (event) => event.username,
      outcome: (event) => event.outcome,
    },
    { by: 'timestamp', dir: 'desc' },
  )

  if (query.isLoading) return <LoadingBlock label="Loading alert" />
  if (query.isError || !query.data) {
    return <ErrorState message="Could not load this alert." onRetry={() => query.refetch()} />
  }

  const alert = query.data
  const mayTriage = can(user, Permission.ALERT_TRIAGE)
  const mayNote = can(user, Permission.ALERT_NOTE_CREATE)
  const mayEscalate = can(user, Permission.INCIDENT_CREATE)

  const handleStatus = async (status: AlertStatus) => {
    if (TERMINAL.includes(status)) {
      setClosing(status)
      return
    }
    try {
      await updateStatus.mutateAsync({ status })
      toast.push(`Alert moved to ${titleCase(status)}.`, 'success')
    } catch (error) {
      toast.push(error instanceof ApiError ? error.message : 'Could not update status.', 'error')
    }
  }

  const confirmClose = async () => {
    if (!closing) return
    try {
      await updateStatus.mutateAsync({ status: closing, resolution_note: resolution })
      toast.push(`Alert marked ${titleCase(closing)}.`, 'success')
      setClosing(null)
      setResolution('')
    } catch (error) {
      toast.push(error instanceof ApiError ? error.message : 'Could not close alert.', 'error')
    }
  }

  const handleAttachToExisting = async () => {
    if (!targetIncidentId) return
    try {
      await linkIncident.mutateAsync(targetIncidentId)
      const incident = openIncidents.data?.items.find((i) => i.id === targetIncidentId)
      toast.push(`Attached to ${incident?.incident_uid ?? 'the incident'}.`, 'success')
      setEscalating(false)
      navigate(`/incidents/${targetIncidentId}`)
    } catch (error) {
      toast.push(
        error instanceof ApiError ? error.message : 'Could not attach the alert.',
        'error',
      )
    }
  }

  const handleEscalate = async () => {
    try {
      const incident = await createIncident.mutateAsync({
        title: alert.title,
        description: alert.description,
        severity: alert.severity,
        alert_ids: [alert.id],
      })
      toast.push(`Created ${incident.incident_uid}.`, 'success')
      navigate(`/incidents/${incident.id}`)
    } catch (error) {
      toast.push(
        error instanceof ApiError ? error.message : 'Could not create incident.',
        'error',
      )
    } finally {
      setEscalating(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <SeverityBadge severity={alert.severity} />
            <StatusBadge status={alert.status} />
            <Mono className="text-ink-400">{alert.alert_uid}</Mono>
          </div>
          <h1 className="mt-1.5 text-base font-semibold text-ink-100">{alert.title}</h1>
        </div>
        <Link to="/alerts" className="text-2xs text-accent hover:underline">
          ← Back to alerts
        </Link>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2 space-y-4">
          <Card>
            <CardHeader title="Why this fired" subtitle={`Rule: ${alert.rule_key}`} />
            <div className="p-4 space-y-3">
              <p className="text-xs leading-relaxed text-ink-200">{alert.description}</p>

              {Object.keys(alert.evidence).length > 0 ? (
                <div>
                  <h3 className="text-2xs uppercase tracking-wide text-ink-400 mb-1.5">
                    Supporting evidence
                  </h3>
                  <dl className="grid gap-x-6 gap-y-1 sm:grid-cols-2">
                    {Object.entries(alert.evidence).map(([key, value]) => (
                      <div key={key} className="flex justify-between gap-3 text-2xs">
                        <dt className="text-ink-400">{titleCase(key)}</dt>
                        <dd className="text-ink-100 text-right break-all">
                          {Array.isArray(value)
                            ? value.slice(0, 8).join(', ') + (value.length > 8 ? ` +${value.length - 8}` : '')
                            : String(value)}
                        </dd>
                      </div>
                    ))}
                  </dl>
                </div>
              ) : null}
            </div>
          </Card>

          <Card>
            <CardHeader
              title="Evidence events"
              subtitle={`${formatNumber(alert.events.length)} of ${formatNumber(alert.event_count)} linked events`}
            />
            {alert.events.length ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left" data-testid="evidence-table">
                  <caption className="sr-only">
                    Events that triggered this alert, sortable by column
                  </caption>
                  <thead>
                    <tr className="border-b border-surface-800">
                      <SortableHeader
                        label="Time"
                        field="timestamp"
                        sort={evidence.sort}
                        onSort={evidence.onSort}
                        defaultDirection="desc"
                        ascLabel="oldest first"
                        descLabel="newest first"
                      />
                      <SortableHeader
                        label="Type"
                        field="event_type"
                        sort={evidence.sort}
                        onSort={evidence.onSort}
                      />
                      <SortableHeader
                        label="Source"
                        field="src_ip"
                        sort={evidence.sort}
                        onSort={evidence.onSort}
                      />
                      <SortableHeader
                        label="Account"
                        field="username"
                        sort={evidence.sort}
                        onSort={evidence.onSort}
                      />
                      <SortableHeader
                        label="Outcome"
                        field="outcome"
                        sort={evidence.sort}
                        onSort={evidence.onSort}
                      />
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-surface-800">
                    {evidence.sorted.slice(0, 25).map((event) => (
                      <tr key={event.id} className="hover:bg-surface-850">
                        <td className="px-3 py-2">
                          <Link to={`/events/${event.id}`} className="hover:text-accent">
                            <Mono>{formatTimestamp(event.timestamp)}</Mono>
                          </Link>
                        </td>
                        <td className="px-3 py-2 text-2xs text-ink-300">
                          {titleCase(event.event_type)}
                        </td>
                        <td className="px-3 py-2">
                          <Mono>{event.src_ip ?? '—'}</Mono>
                        </td>
                        <td className="px-3 py-2 text-2xs text-ink-300">
                          {event.username ?? '—'}
                        </td>
                        <td className="px-3 py-2 text-2xs text-ink-300">{event.outcome}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {evidence.sorted.length > 25 ? (
                  <p className="px-4 py-2 text-2xs text-ink-400 border-t border-surface-800">
                    Showing the first 25 of {evidence.sorted.length} linked events in this
                    order. Change the sort to see the other end of the window.
                  </p>
                ) : null}
              </div>
            ) : (
              <EmptyState title="No linked events" />
            )}
          </Card>

          <Card>
            <CardHeader title="Investigation notes" />
            <div className="p-4 space-y-3">
              {alert.notes.length ? (
                <ul className="space-y-2.5">
                  {alert.notes.map((entry) => (
                    <li key={entry.id} className="rounded border border-surface-800 bg-surface-850 p-2.5">
                      <p className="text-2xs text-ink-400">
                        {entry.author_email} · {formatTimestamp(entry.created_at)}
                      </p>
                      <p className="mt-1 text-xs text-ink-100 whitespace-pre-wrap">{entry.body}</p>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-2xs text-ink-400">No notes recorded yet.</p>
              )}

              {mayNote ? (
                <div className="space-y-2">
                  <Textarea
                    rows={3}
                    value={note}
                    onChange={(event) => setNote(event.target.value)}
                    placeholder="Record what you checked and what you concluded…"
                    aria-label="New investigation note"
                  />
                  <Button
                    variant="primary"
                    size="sm"
                    disabled={!note.trim() || addNote.isPending}
                    onClick={async () => {
                      try {
                        await addNote.mutateAsync(note)
                        setNote('')
                        toast.push('Note added.', 'success')
                      } catch (error) {
                        toast.push(
                          error instanceof ApiError ? error.message : 'Could not add note.',
                          'error',
                        )
                      }
                    }}
                  >
                    Add note
                  </Button>
                </div>
              ) : null}
            </div>
          </Card>
        </div>

        <div className="space-y-4">
          <Card>
            <CardHeader title="Triage" />
            <div className="p-4 space-y-3">
              {mayTriage ? (
                <div>
                  <p className="text-2xs text-ink-400 mb-1.5">Set status</p>
                  <div className="flex flex-wrap gap-1.5">
                    {TRANSITIONS.filter((value) => value !== alert.status).map((value) => (
                      <Button
                        key={value}
                        size="sm"
                        variant={TERMINAL.includes(value) ? 'secondary' : 'primary'}
                        disabled={updateStatus.isPending}
                        onClick={() => handleStatus(value)}
                      >
                        {titleCase(value)}
                      </Button>
                    ))}
                  </div>
                </div>
              ) : (
                <p className="text-2xs text-ink-400">
                  Your role can view this alert but not change its status.
                </p>
              )}

              {mayTriage ? (
                <div className="pt-2 border-t border-surface-800">
                  <p className="text-2xs text-ink-400 mb-1.5">Assignment</p>
                  <p className="text-xs text-ink-100 mb-1.5">
                    {alert.assigned_to?.email ?? 'Unassigned'}
                  </p>
                  <div className="flex gap-1.5">
                    <Button
                      size="sm"
                      disabled={assign.isPending || alert.assigned_to?.id === user?.id}
                      onClick={async () => {
                        await assign.mutateAsync(user?.id ?? null)
                        toast.push('Assigned to you.', 'success')
                      }}
                    >
                      Assign to me
                    </Button>
                    {alert.assigned_to ? (
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={async () => {
                          await assign.mutateAsync(null)
                          toast.push('Assignment cleared.', 'success')
                        }}
                      >
                        Unassign
                      </Button>
                    ) : null}
                  </div>
                </div>
              ) : null}

              {mayEscalate && !alert.incident_id ? (
                <div className="pt-2 border-t border-surface-800">
                  <Button variant="primary" size="sm" onClick={() => setEscalating(true)}>
                    Escalate to incident
                  </Button>
                </div>
              ) : null}

              {alert.incident_id ? (
                <div className="pt-2 border-t border-surface-800">
                  <p className="text-2xs text-ink-400 mb-1">Linked incident</p>
                  <Link
                    to={`/incidents/${alert.incident_id}`}
                    className="text-xs text-accent hover:underline"
                  >
                    Open incident →
                  </Link>
                </div>
              ) : null}
            </div>
          </Card>

          <Card>
            <CardHeader
              title="Pivot"
              subtitle="Carries this alert's context into the event explorer"
            />
            <div className="p-4 space-y-1.5">
              {alert.src_ip ? (
                <Link
                  to={`/events?src_ip=${encodeURIComponent(alert.src_ip)}&sort_by=timestamp&sort_dir=desc`}
                  className="block text-2xs text-accent hover:underline"
                >
                  All events from {alert.src_ip} →
                </Link>
              ) : null}
              {alert.username ? (
                <Link
                  to={`/events?username=${encodeURIComponent(alert.username)}&sort_by=timestamp&sort_dir=desc`}
                  className="block text-2xs text-accent hover:underline"
                >
                  All events for account “{alert.username}” →
                </Link>
              ) : null}
              {alert.src_ip ? (
                <Link
                  to={`/investigate?ip=${encodeURIComponent(alert.src_ip)}`}
                  className="block text-2xs text-accent hover:underline"
                >
                  Investigate {alert.src_ip} →
                </Link>
              ) : null}
              {!alert.src_ip && !alert.username ? (
                <p className="text-2xs text-ink-400">
                  This alert has no address or account to pivot on.
                </p>
              ) : null}
            </div>
          </Card>

          <Card>
            <CardHeader title="Attributes" />
            <dl className="p-4 space-y-1.5 text-2xs">
              {[
                ['Source address', alert.src_ip],
                ['Destination', alert.dst_ip],
                ['Account', alert.username],
                ['Host', alert.hostname],
                ['Confidence', `${alert.confidence}%`],
                ['First seen', formatTimestamp(alert.first_seen)],
                ['Last seen', formatTimestamp(alert.last_seen)],
              ].map(([label, value]) => (
                <div key={String(label)} className="flex justify-between gap-3">
                  <dt className="text-ink-400">{label}</dt>
                  <dd className="text-ink-100 font-mono text-right break-all">
                    {value || '—'}
                  </dd>
                </div>
              ))}
            </dl>
          </Card>

          {alert.mitre_technique_id ? (
            <Card>
              <CardHeader title="MITRE ATT&CK" />
              <div className="p-4 space-y-2">
                <Pill>{alert.mitre_technique_id}</Pill>
                <p className="text-xs text-ink-100">{alert.mitre_technique_name}</p>
                <p className="text-2xs text-ink-400">Tactic: {alert.mitre_tactic}</p>
                <a
                  href={`https://attack.mitre.org/techniques/${alert.mitre_technique_id.replace('.', '/')}/`}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="inline-block text-2xs text-accent hover:underline"
                >
                  View on attack.mitre.org →
                </a>
              </div>
            </Card>
          ) : null}

          {alert.resolution_note ? (
            <Card>
              <CardHeader title="Resolution" />
              <p className="p-4 text-xs text-ink-200 whitespace-pre-wrap">
                {alert.resolution_note}
              </p>
            </Card>
          ) : null}
        </div>
      </div>

      <Modal
        open={closing !== null}
        title={`Mark alert ${closing ? titleCase(closing) : ''}`}
        onClose={() => setClosing(null)}
      >
        <div className="space-y-3">
          <p className="text-xs text-ink-300">
            A resolution note is required. The next analyst who sees this address will read it
            before re-investigating.
          </p>
          <Textarea
            rows={4}
            value={resolution}
            onChange={(event) => setResolution(event.target.value)}
            placeholder="What did you determine, and how?"
            aria-label="Resolution note"
          />
          <div className="flex justify-end gap-2">
            <Button onClick={() => setClosing(null)}>Cancel</Button>
            <Button
              variant="primary"
              disabled={!resolution.trim() || updateStatus.isPending}
              onClick={confirmClose}
            >
              Confirm
            </Button>
          </div>
        </div>
      </Modal>

      <Modal open={escalating} title="Escalate to incident" onClose={() => setEscalating(false)}>
        <div className="space-y-4">
          <fieldset className="space-y-2">
            <legend className="text-2xs text-ink-300 mb-1">How would you like to escalate?</legend>
            <label className="flex items-start gap-2 cursor-pointer">
              <input
                type="radio"
                name="escalation-mode"
                value="new"
                checked={escalationMode === 'new'}
                onChange={() => setEscalationMode('new')}
                className="mt-0.5"
              />
              <span className="text-xs text-ink-100">
                Open a new incident
                <span className="block text-2xs text-ink-400">
                  Titled “{truncate(alert.title, 60)}” at {alert.severity} severity.
                </span>
              </span>
            </label>
            <label className="flex items-start gap-2 cursor-pointer">
              <input
                type="radio"
                name="escalation-mode"
                value="existing"
                checked={escalationMode === 'existing'}
                onChange={() => setEscalationMode('existing')}
                className="mt-0.5"
              />
              <span className="text-xs text-ink-100">
                Attach to an existing incident
                <span className="block text-2xs text-ink-400">
                  Use this when the alert is part of something already being worked.
                </span>
              </span>
            </label>
          </fieldset>

          {escalationMode === 'existing' ? (
            <div>
              <label htmlFor="target-incident" className="block text-2xs text-ink-300 mb-1">
                Open incident
              </label>
              {openIncidents.isLoading ? (
                <Spinner label="Loading incidents" />
              ) : openIncidents.data?.items.length ? (
                <Select
                  id="target-incident"
                  className="w-full"
                  value={targetIncidentId}
                  onChange={(event) => setTargetIncidentId(event.target.value)}
                >
                  <option value="">Select an incident…</option>
                  {openIncidents.data.items.map((incident) => (
                    <option key={incident.id} value={incident.id}>
                      {incident.incident_uid} · {truncate(incident.title, 50)} ({incident.severity})
                    </option>
                  ))}
                </Select>
              ) : (
                <p className="text-2xs text-ink-400">
                  No open incidents. Open a new one instead.
                </p>
              )}
            </div>
          ) : null}

          <div className="flex justify-end gap-2">
            <Button onClick={() => setEscalating(false)}>Cancel</Button>
            {escalationMode === 'new' ? (
              <Button
                variant="primary"
                disabled={createIncident.isPending}
                onClick={handleEscalate}
              >
                Create incident
              </Button>
            ) : (
              <Button
                variant="primary"
                disabled={!targetIncidentId || linkIncident.isPending}
                onClick={handleAttachToExisting}
              >
                Attach to incident
              </Button>
            )}
          </div>
        </div>
      </Modal>
    </div>
  )
}
