import clsx from 'clsx'
import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes } from 'react'

import type { AlertStatus, IncidentStatus, Severity } from '@/types/api'
import { titleCase } from '@/lib/format'

/* -------------------------------------------------------------- primitives */

export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return <section className={clsx('card', className)}>{children}</section>
}

export function CardHeader({
  title,
  subtitle,
  actions,
}: {
  title: ReactNode
  subtitle?: ReactNode
  actions?: ReactNode
}) {
  return (
    <header className="card-header">
      <div className="min-w-0">
        <h2 className="text-sm font-semibold text-ink-100 truncate">{title}</h2>
        {subtitle ? <p className="text-2xs text-ink-300 mt-0.5">{subtitle}</p> : null}
      </div>
      {actions ? <div className="flex items-center gap-2 shrink-0">{actions}</div> : null}
    </header>
  )
}

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: 'sm' | 'md'
}

export function Button({
  variant = 'secondary',
  size = 'md',
  className,
  children,
  ...rest
}: ButtonProps) {
  return (
    <button
      className={clsx(
        'inline-flex items-center justify-center gap-1.5 rounded font-medium transition-colors',
        'disabled:opacity-50 disabled:cursor-not-allowed',
        size === 'sm' ? 'px-2.5 py-1 text-2xs' : 'px-3 py-1.5 text-xs',
        variant === 'primary' && 'bg-accent text-white hover:bg-accent-muted',
        variant === 'secondary' &&
          'bg-surface-800 text-ink-100 border border-surface-700 hover:bg-surface-700',
        variant === 'ghost' && 'text-ink-300 hover:text-ink-100 hover:bg-surface-800',
        variant === 'danger' && 'bg-danger text-white hover:opacity-90',
        className,
      )}
      {...rest}
    >
      {children}
    </button>
  )
}

export function Input({ className, ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={clsx(
        'w-full bg-surface-850 border border-surface-700 rounded px-2.5 py-1.5 text-xs',
        'text-ink-100 placeholder:text-ink-400',
        'focus:border-accent focus:outline-none',
        className,
      )}
      {...rest}
    />
  )
}

export function Select({ className, children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={clsx(
        'bg-surface-850 border border-surface-700 rounded px-2 py-1.5 text-xs text-ink-100',
        'focus:border-accent focus:outline-none',
        className,
      )}
      {...rest}
    >
      {children}
    </select>
  )
}

export function Textarea({
  className,
  ...rest
}: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      className={clsx(
        'w-full bg-surface-850 border border-surface-700 rounded px-2.5 py-2 text-xs',
        'text-ink-100 placeholder:text-ink-400 focus:border-accent focus:outline-none',
        className,
      )}
      {...rest}
    />
  )
}

/* ------------------------------------------------------------------ badges */

// Severity is a STATUS scale. The colour never carries the meaning on its own:
// every chip renders a coloured dot beside the severity's own name, because
// `critical` measures 3.91:1 on this surface — fine for a mark, below the 4.5:1
// small-text threshold. The label text stays in high-contrast ink.
const SEVERITY_DOT: Record<Severity, string> = {
  critical: 'bg-severity-critical',
  high: 'bg-severity-high',
  medium: 'bg-severity-medium',
  low: 'bg-severity-low',
  info: 'bg-severity-info',
}

const SEVERITY_TINT: Record<Severity, string> = {
  critical: 'border-severity-critical/40 bg-severity-critical/10',
  high: 'border-severity-high/40 bg-severity-high/10',
  medium: 'border-severity-medium/40 bg-severity-medium/10',
  low: 'border-severity-low/40 bg-severity-low/10',
  info: 'border-severity-info/40 bg-severity-info/10',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5',
        'text-2xs font-medium uppercase tracking-wide text-ink-100',
        SEVERITY_TINT[severity],
      )}
    >
      <span aria-hidden className={clsx('h-1.5 w-1.5 rounded-full', SEVERITY_DOT[severity])} />
      {severity}
    </span>
  )
}

const ALERT_STATUS_STYLE: Record<AlertStatus, string> = {
  new: 'border-accent/40 bg-accent/10',
  in_review: 'border-severity-medium/40 bg-severity-medium/10',
  escalated: 'border-severity-critical/40 bg-severity-critical/10',
  resolved: 'border-ok/40 bg-ok/10',
  false_positive: 'border-surface-600 bg-surface-800',
}

const INCIDENT_STATUS_STYLE: Record<IncidentStatus, string> = {
  open: 'border-accent/40 bg-accent/10',
  investigating: 'border-severity-medium/40 bg-severity-medium/10',
  contained: 'border-severity-high/40 bg-severity-high/10',
  resolved: 'border-ok/40 bg-ok/10',
  closed: 'border-surface-600 bg-surface-800',
}

export function StatusBadge({ status }: { status: AlertStatus | IncidentStatus }) {
  const style =
    (ALERT_STATUS_STYLE as Record<string, string>)[status] ??
    (INCIDENT_STATUS_STYLE as Record<string, string>)[status] ??
    'border-surface-600 bg-surface-800'
  return (
    <span
      className={clsx(
        'inline-flex items-center rounded border px-1.5 py-0.5 text-2xs font-medium text-ink-100',
        style,
      )}
    >
      {titleCase(status)}
    </span>
  )
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={clsx('font-mono text-2xs text-ink-200', className)}>{children}</span>
}

export function Pill({ children }: { children: ReactNode }) {
  return (
    <span className="inline-flex items-center rounded bg-surface-800 border border-surface-700 px-1.5 py-0.5 text-2xs text-ink-200">
      {children}
    </span>
  )
}

/* ------------------------------------------------------------------ states */

export function Spinner({ label = 'Loading' }: { label?: string }) {
  return (
    <div role="status" className="flex items-center gap-2 text-xs text-ink-300">
      <span
        aria-hidden
        className="h-3.5 w-3.5 rounded-full border-2 border-surface-600 border-t-accent animate-spin"
      />
      {label}…
    </div>
  )
}

export function LoadingBlock({ label }: { label?: string }) {
  return (
    <div className="flex items-center justify-center py-12">
      <Spinner label={label} />
    </div>
  )
}

export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="py-12 text-center">
      <p className="text-sm text-ink-200">{title}</p>
      {hint ? <p className="mt-1 text-xs text-ink-400">{hint}</p> : null}
    </div>
  )
}

export function ErrorState({
  message,
  correlationId,
  onRetry,
}: {
  message: string
  correlationId?: string | null
  onRetry?: () => void
}) {
  return (
    <div className="py-10 text-center">
      <p className="text-sm text-severity-high">{message}</p>
      {correlationId ? (
        // Surfaced so a user can quote it in a bug report and it can be found
        // in the server logs, where the actual diagnostic detail lives.
        <p className="mt-1 text-2xs text-ink-400 font-mono">Reference: {correlationId}</p>
      ) : null}
      {onRetry ? (
        <Button className="mt-3" onClick={onRetry}>
          Try again
        </Button>
      ) : null}
    </div>
  )
}

/* -------------------------------------------------------------- pagination */

export function Pagination({
  page,
  pages,
  total,
  pageSize,
  onChange,
}: {
  page: number
  pages: number
  total: number
  pageSize: number
  onChange: (page: number) => void
}) {
  if (total === 0) return null
  const first = (page - 1) * pageSize + 1
  const last = Math.min(page * pageSize, total)
  return (
    <div className="flex items-center justify-between gap-3 px-4 py-2.5 border-t border-surface-800">
      <p className="text-2xs text-ink-300 tabular">
        {first.toLocaleString()}–{last.toLocaleString()} of {total.toLocaleString()}
      </p>
      <div className="flex items-center gap-1.5">
        <Button size="sm" disabled={page <= 1} onClick={() => onChange(page - 1)}>
          Previous
        </Button>
        <span className="text-2xs text-ink-300 tabular px-1">
          {page} / {Math.max(pages, 1)}
        </span>
        <Button size="sm" disabled={page >= pages} onClick={() => onChange(page + 1)}>
          Next
        </Button>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ modal */

export function Modal({
  open,
  title,
  children,
  onClose,
}: {
  open: boolean
  title: string
  children: ReactNode
  onClose: () => void
}) {
  if (!open) return null
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      onClick={onClose}
    >
      <div
        className="w-full max-w-lg card max-h-[85vh] overflow-y-auto"
        onClick={(event) => event.stopPropagation()}
      >
        <CardHeader
          title={title}
          actions={
            <Button size="sm" variant="ghost" onClick={onClose} aria-label="Close dialog">
              Close
            </Button>
          }
        />
        <div className="p-4">{children}</div>
      </div>
    </div>
  )
}
