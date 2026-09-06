import clsx from 'clsx'
import { Link } from 'react-router-dom'
import type { ReactNode } from 'react'

import { formatNumber } from '@/lib/format'

/**
 * A single headline number.
 *
 * Not a chart: when the data's job is "one figure right now", a chart adds
 * chrome without adding information. The value is the largest thing in the
 * tile, the label sits above it, and any qualifier goes below in muted ink.
 */
export function StatTile({
  label,
  value,
  hint,
  tone = 'neutral',
  to,
}: {
  label: string
  value: number | string | null
  hint?: ReactNode
  tone?: 'neutral' | 'warning' | 'critical' | 'ok'
  to?: string
}) {
  const body = (
    <>
      <p className="text-2xs uppercase tracking-wide text-ink-400">{label}</p>
      <p
        className={clsx(
          'mt-1.5 text-2xl font-semibold tabular',
          tone === 'neutral' && 'text-ink-100',
          tone === 'ok' && 'text-ok',
          tone === 'warning' && 'text-severity-medium',
          tone === 'critical' && 'text-severity-critical',
        )}
      >
        {typeof value === 'number' ? formatNumber(value) : (value ?? '—')}
      </p>
      {hint ? <p className="mt-1 text-2xs text-ink-400">{hint}</p> : null}
    </>
  )

  if (to) {
    return (
      <Link
        to={to}
        className="card p-4 block transition-colors hover:border-surface-600 focus-visible:border-accent"
      >
        {body}
      </Link>
    )
  }
  return <div className="card p-4">{body}</div>
}
