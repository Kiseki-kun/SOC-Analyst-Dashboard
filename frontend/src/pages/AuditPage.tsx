import { useSearchParams } from 'react-router-dom'

import {
  Card,
  EmptyState,
  ErrorState,
  LoadingBlock,
  Mono,
  Pagination,
  Select,
} from '@/components/ui'
import { useAuditActions, useAuditLog } from '@/hooks/queries'
import { formatTimestamp, titleCase } from '@/lib/format'

export default function AuditPage() {
  const [params, setParams] = useSearchParams()
  const page = Number(params.get('page') ?? 1)
  const action = params.get('action') ?? ''
  const success = params.get('success') ?? ''

  const actions = useAuditActions()
  const query = useAuditLog({
    page,
    page_size: 50,
    action: action || undefined,
    success: success === '' ? undefined : success === 'true',
  })

  const update = (key: string, value: string | null) => {
    const next = new URLSearchParams(params)
    next.delete('page')
    if (!value) next.delete(key)
    else next.set(key, value)
    setParams(next)
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-base font-semibold text-ink-100">Audit log</h1>
        <p className="mt-0.5 text-2xs text-ink-400">
          Append-only. The API exposes no way to edit or delete an entry.
        </p>
      </div>

      <Card className="p-3 flex flex-wrap gap-2">
        <Select
          value={action}
          onChange={(event) => update('action', event.target.value || null)}
          aria-label="Action filter"
        >
          <option value="">All actions</option>
          {actions.data?.map((value) => (
            <option key={value} value={value}>
              {titleCase(value)}
            </option>
          ))}
        </Select>
        <Select
          value={success}
          onChange={(event) => update('success', event.target.value || null)}
          aria-label="Outcome filter"
        >
          <option value="">Any outcome</option>
          <option value="true">Succeeded</option>
          <option value="false">Failed / denied</option>
        </Select>
      </Card>

      <Card>
        {query.isLoading ? (
          <LoadingBlock label="Loading audit log" />
        ) : query.isError ? (
          <ErrorState message="Could not load the audit log." onRetry={() => query.refetch()} />
        ) : query.data?.items.length ? (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-surface-800 text-2xs uppercase tracking-wide text-ink-400">
                    <th className="px-4 py-2 font-medium">Timestamp</th>
                    <th className="px-4 py-2 font-medium">Actor</th>
                    <th className="px-4 py-2 font-medium">Action</th>
                    <th className="px-4 py-2 font-medium">Resource</th>
                    <th className="px-4 py-2 font-medium">Source</th>
                    <th className="px-4 py-2 font-medium">Detail</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-surface-800">
                  {query.data.items.map((entry) => (
                    <tr key={entry.id} className="hover:bg-surface-850">
                      <td className="px-4 py-2 whitespace-nowrap">
                        <Mono>{formatTimestamp(entry.timestamp)}</Mono>
                      </td>
                      <td className="px-4 py-2 text-2xs text-ink-200">
                        {entry.actor_email ?? <span className="text-ink-400">anonymous</span>}
                        {entry.actor_role ? (
                          <span className="text-ink-400"> · {entry.actor_role}</span>
                        ) : null}
                      </td>
                      <td className="px-4 py-2 text-2xs">
                        <span className={entry.success ? 'text-ink-100' : 'text-severity-high'}>
                          {titleCase(entry.action)}
                        </span>
                      </td>
                      <td className="px-4 py-2 text-2xs text-ink-300">
                        {entry.resource_type ?? '—'}
                      </td>
                      <td className="px-4 py-2">
                        <Mono className="text-ink-400">{entry.ip_address ?? '—'}</Mono>
                      </td>
                      <td className="px-4 py-2 text-2xs text-ink-400 font-mono max-w-sm break-all">
                        {Object.keys(entry.details).length
                          ? Object.entries(entry.details)
                              .map(([key, value]) => `${key}=${String(value)}`)
                              .join(' ')
                          : '—'}
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
          <EmptyState title="No audit entries match these filters" />
        )}
      </Card>
    </div>
  )
}
