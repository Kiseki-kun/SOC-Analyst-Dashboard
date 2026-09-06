import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'

import {
  Button,
  Card,
  CardHeader,
  EmptyState,
  ErrorState,
  Input,
  LoadingBlock,
  Modal,
  Mono,
  Select,
  SeverityBadge,
  StatusBadge,
  Textarea,
} from '@/components/ui'
import { useToast } from '@/components/ui/toast'
import {
  useAddIncidentNote,
  useIncident,
  useSimulateResponse,
  useUpdateIncident,
} from '@/hooks/queries'
import { ApiError } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { Permission, can } from '@/lib/permissions'
import { formatTimestamp, titleCase } from '@/lib/format'
import type { IncidentStatus, ResponseActionType } from '@/types/api'

const STATUSES: IncidentStatus[] = ['open', 'investigating', 'contained', 'resolved', 'closed']
const TERMINAL: IncidentStatus[] = ['resolved', 'closed']

// The wording is deliberate. Each label says what the action WOULD do in a real
// platform, and the panel states plainly that nothing outside this database is
// touched. A portfolio project that implied it could isolate a host would be
// making a claim it cannot back.
const RESPONSE_ACTIONS: { value: ResponseActionType; label: string; effect: string }[] = [
  { value: 'simulated_ip_block', label: 'Block source address', effect: 'would push a deny rule to the perimeter firewall' },
  { value: 'simulated_account_disable', label: 'Disable account', effect: 'would disable the account in the directory' },
  { value: 'simulated_host_isolation', label: 'Isolate host', effect: 'would quarantine the host via the endpoint agent' },
  { value: 'simulated_credential_reset', label: 'Force credential reset', effect: 'would reset credentials and revoke sessions' },
  { value: 'add_ioc_to_watchlist', label: 'Add indicator to watchlist', effect: 'adds the indicator locally — this one does take effect, inside this application' },
]

export default function IncidentDetailPage() {
  const { incidentId } = useParams<{ incidentId: string }>()
  const toast = useToast()
  const { user } = useAuth()

  const query = useIncident(incidentId)
  const update = useUpdateIncident(incidentId ?? '')
  const addNote = useAddIncidentNote(incidentId ?? '')
  const simulate = useSimulateResponse(incidentId ?? '')

  const [note, setNote] = useState('')
  const [closing, setClosing] = useState<IncidentStatus | null>(null)
  const [summary, setSummary] = useState('')
  const [actionOpen, setActionOpen] = useState(false)
  const [actionType, setActionType] = useState<ResponseActionType>('simulated_ip_block')
  const [target, setTarget] = useState('')
  const [actionNote, setActionNote] = useState('')

  if (query.isLoading) return <LoadingBlock label="Loading incident" />
  if (query.isError || !query.data) {
    return <ErrorState message="Could not load this incident." onRetry={() => query.refetch()} />
  }

  const incident = query.data
  const mayUpdate = can(user, Permission.INCIDENT_UPDATE)
  const mayClose = can(user, Permission.INCIDENT_CLOSE)
  const mayRespond = can(user, Permission.RESPONSE_ACTION_EXECUTE)

  const changeStatus = async (status: IncidentStatus) => {
    if (TERMINAL.includes(status)) {
      setSummary(incident.resolution_summary ?? '')
      setClosing(status)
      return
    }
    try {
      await update.mutateAsync({ status })
      toast.push(`Incident moved to ${titleCase(status)}.`, 'success')
    } catch (error) {
      toast.push(error instanceof ApiError ? error.message : 'Could not update.', 'error')
    }
  }

  const confirmClose = async () => {
    if (!closing) return
    try {
      await update.mutateAsync({ status: closing, resolution_summary: summary })
      toast.push(`Incident ${titleCase(closing)}.`, 'success')
      setClosing(null)
    } catch (error) {
      toast.push(error instanceof ApiError ? error.message : 'Could not update.', 'error')
    }
  }

  const runAction = async () => {
    try {
      await simulate.mutateAsync({ action_type: actionType, target, note: actionNote })
      toast.push('Simulated action recorded.', 'success')
      setActionOpen(false)
      setTarget('')
      setActionNote('')
    } catch (error) {
      toast.push(error instanceof ApiError ? error.message : 'Could not record action.', 'error')
    }
  }

  const selectedAction = RESPONSE_ACTIONS.find((entry) => entry.value === actionType)

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <Mono className="text-accent">{incident.incident_uid}</Mono>
            <SeverityBadge severity={incident.severity} />
            <StatusBadge status={incident.status} />
          </div>
          <h1 className="mt-1.5 text-base font-semibold text-ink-100">{incident.title}</h1>
        </div>
        <Link to="/incidents" className="text-2xs text-accent hover:underline">
          ← Back to incidents
        </Link>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2 space-y-4">
          {incident.description ? (
            <Card>
              <CardHeader title="Description" />
              <p className="p-4 text-xs leading-relaxed text-ink-200 whitespace-pre-wrap">
                {incident.description}
              </p>
            </Card>
          ) : null}

          <Card>
            <CardHeader title="Timeline" subtitle="What happened, in order" />
            {incident.timeline_entries.length ? (
              <ol className="p-4 space-y-3">
                {incident.timeline_entries.map((entry) => (
                  <li key={entry.id} className="flex gap-3">
                    <div className="flex flex-col items-center pt-1">
                      <span
                        aria-hidden
                        className={`h-2 w-2 rounded-full ${
                          entry.entry_type === 'response_action'
                            ? 'bg-severity-high'
                            : entry.entry_type === 'status_changed'
                              ? 'bg-accent'
                              : 'bg-surface-600'
                        }`}
                      />
                      <span aria-hidden className="mt-1 w-px flex-1 bg-surface-700" />
                    </div>
                    <div className="pb-1 min-w-0">
                      <p className="text-xs text-ink-100">{entry.summary}</p>
                      <p className="text-2xs text-ink-400 mt-0.5">
                        {formatTimestamp(entry.occurred_at)}
                        {entry.actor_email ? ` · ${entry.actor_email}` : ''}
                      </p>
                    </div>
                  </li>
                ))}
              </ol>
            ) : (
              <EmptyState title="No timeline entries yet" />
            )}
          </Card>

          <Card>
            <CardHeader
              title="Attached alerts"
              subtitle={`${incident.alerts.length} alert(s)`}
            />
            {incident.alerts.length ? (
              <ul className="divide-y divide-surface-800">
                {incident.alerts.map((alert) => (
                  <li key={alert.id}>
                    <Link
                      to={`/alerts/${alert.id}`}
                      className="flex items-center gap-3 px-4 py-2.5 hover:bg-surface-850"
                    >
                      <SeverityBadge severity={alert.severity} />
                      <span className="min-w-0 flex-1 truncate text-xs text-ink-100">
                        {alert.title}
                      </span>
                      <Mono className="text-ink-400">{alert.mitre_technique_id ?? ''}</Mono>
                    </Link>
                  </li>
                ))}
              </ul>
            ) : (
              <EmptyState title="No alerts attached" />
            )}
          </Card>

          <Card>
            <CardHeader
              title="Simulated response actions"
              subtitle="Recorded intent — nothing outside this database is changed"
              actions={
                mayRespond ? (
                  <Button size="sm" variant="primary" onClick={() => setActionOpen(true)}>
                    Record action
                  </Button>
                ) : null
              }
            />
            {incident.response_actions.length ? (
              <ul className="divide-y divide-surface-800">
                {incident.response_actions.map((action) => (
                  <li key={action.id} className="px-4 py-2.5">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="rounded border border-severity-high/40 bg-severity-high/10 px-1.5 py-0.5 text-2xs font-medium text-ink-100">
                        SIMULATED
                      </span>
                      <span className="text-xs text-ink-100">
                        {titleCase(action.action_type.replace('simulated_', ''))}
                      </span>
                      <Mono>{action.target}</Mono>
                    </div>
                    <p className="mt-1 text-2xs text-ink-400">
                      {action.performed_by_email} · {formatTimestamp(action.created_at)}
                    </p>
                    {action.note ? (
                      <p className="mt-1 text-2xs text-ink-300">{action.note}</p>
                    ) : null}
                  </li>
                ))}
              </ul>
            ) : (
              <EmptyState
                title="No response actions recorded"
                hint={mayRespond ? undefined : 'Your role cannot record response actions.'}
              />
            )}
          </Card>

          <Card>
            <CardHeader title="Investigation notes" />
            <div className="p-4 space-y-3">
              {incident.notes.length ? (
                <ul className="space-y-2.5">
                  {incident.notes.map((entry) => (
                    <li
                      key={entry.id}
                      className="rounded border border-surface-800 bg-surface-850 p-2.5"
                    >
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

              {can(user, Permission.INCIDENT_NOTE_CREATE) ? (
                <div className="space-y-2">
                  <Textarea
                    rows={3}
                    value={note}
                    onChange={(event) => setNote(event.target.value)}
                    placeholder="Add an investigation note…"
                    aria-label="New incident note"
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
            <CardHeader title="Status" />
            <div className="p-4 space-y-2">
              {mayUpdate ? (
                <div className="flex flex-wrap gap-1.5">
                  {STATUSES.filter((value) => value !== incident.status).map((value) => {
                    const blocked = TERMINAL.includes(value) && !mayClose
                    return (
                      <Button
                        key={value}
                        size="sm"
                        variant={TERMINAL.includes(value) ? 'secondary' : 'primary'}
                        disabled={update.isPending || blocked}
                        title={blocked ? 'Only responders may resolve or close incidents' : undefined}
                        onClick={() => changeStatus(value)}
                      >
                        {titleCase(value)}
                      </Button>
                    )
                  })}
                </div>
              ) : (
                <p className="text-2xs text-ink-400">
                  Your role can view this incident but not change it.
                </p>
              )}
            </div>
          </Card>

          <Card>
            <CardHeader title="Details" />
            <dl className="p-4 space-y-1.5 text-2xs">
              {[
                ['Owner', incident.assigned_to?.email ?? 'Unassigned'],
                ['Opened by', incident.created_by?.email ?? '—'],
                ['Opened', formatTimestamp(incident.created_at)],
                ['Acknowledged', formatTimestamp(incident.acknowledged_at)],
                ['Contained', formatTimestamp(incident.contained_at)],
                ['Resolved', formatTimestamp(incident.resolved_at)],
                ['Closed', formatTimestamp(incident.closed_at)],
              ].map(([label, value]) => (
                <div key={String(label)} className="flex justify-between gap-3">
                  <dt className="text-ink-400">{label}</dt>
                  <dd className="text-ink-100 text-right break-all">{value}</dd>
                </div>
              ))}
            </dl>
          </Card>

          {incident.resolution_summary ? (
            <Card>
              <CardHeader title="Resolution" />
              <p className="p-4 text-xs text-ink-200 whitespace-pre-wrap">
                {incident.resolution_summary}
              </p>
            </Card>
          ) : null}
        </div>
      </div>

      <Modal
        open={closing !== null}
        title={`${closing ? titleCase(closing) : ''} incident`}
        onClose={() => setClosing(null)}
      >
        <div className="space-y-3">
          <p className="text-xs text-ink-300">
            A resolution summary is required. It is what someone reading this incident in six
            months will rely on.
          </p>
          <Textarea
            rows={4}
            value={summary}
            onChange={(event) => setSummary(event.target.value)}
            aria-label="Resolution summary"
          />
          <div className="flex justify-end gap-2">
            <Button onClick={() => setClosing(null)}>Cancel</Button>
            <Button variant="primary" disabled={!summary.trim() || update.isPending} onClick={confirmClose}>
              Confirm
            </Button>
          </div>
        </div>
      </Modal>

      <Modal open={actionOpen} title="Record a simulated response" onClose={() => setActionOpen(false)}>
        <div className="space-y-3">
          <div className="rounded border border-severity-medium/40 bg-severity-medium/10 p-2.5">
            <p className="text-2xs text-ink-100">
              This records an intent in this application only. No firewall, directory, endpoint or
              external system is contacted — this project has no client for any of them.
            </p>
          </div>

          <div>
            <label htmlFor="action-type" className="block text-2xs text-ink-300 mb-1">
              Action
            </label>
            <Select
              id="action-type"
              value={actionType}
              onChange={(event) => setActionType(event.target.value as ResponseActionType)}
              className="w-full"
            >
              {RESPONSE_ACTIONS.map((entry) => (
                <option key={entry.value} value={entry.value}>
                  {entry.label}
                </option>
              ))}
            </Select>
            {selectedAction ? (
              <p className="mt-1 text-2xs text-ink-400">In a real platform this {selectedAction.effect}.</p>
            ) : null}
          </div>

          <div>
            <label htmlFor="action-target" className="block text-2xs text-ink-300 mb-1">
              Target
            </label>
            <Input
              id="action-target"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              placeholder="203.0.113.99, WKS-004, j.doe…"
            />
          </div>

          <div>
            <label htmlFor="action-note" className="block text-2xs text-ink-300 mb-1">
              Note (optional)
            </label>
            <Textarea
              id="action-note"
              rows={3}
              value={actionNote}
              onChange={(event) => setActionNote(event.target.value)}
            />
          </div>

          <div className="flex justify-end gap-2">
            <Button onClick={() => setActionOpen(false)}>Cancel</Button>
            <Button variant="primary" disabled={!target.trim() || simulate.isPending} onClick={runAction}>
              Record simulated action
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
