import { format, formatDistanceToNowStrict, parseISO } from 'date-fns'

export function formatTimestamp(value: string | null | undefined): string {
  if (!value) return '—'
  try {
    return format(parseISO(value), 'yyyy-MM-dd HH:mm:ss')
  } catch {
    return '—'
  }
}

export function formatShortTime(value: string | null | undefined): string {
  if (!value) return '—'
  try {
    return format(parseISO(value), 'HH:mm')
  } catch {
    return '—'
  }
}

export function formatRelative(value: string | null | undefined): string {
  if (!value) return '—'
  try {
    return `${formatDistanceToNowStrict(parseISO(value))} ago`
  } catch {
    return '—'
  }
}

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined) return '—'
  return value.toLocaleString()
}

/** Minutes as a human duration. Null means "not measured", never "zero". */
export function formatDuration(minutes: number | null | undefined): string {
  if (minutes === null || minutes === undefined) return 'Not yet measured'
  if (minutes < 1) return '< 1 min'
  if (minutes < 60) return `${Math.round(minutes)} min`
  const hours = minutes / 60
  if (hours < 24) return `${hours.toFixed(1)} h`
  return `${(hours / 24).toFixed(1)} d`
}

export function titleCase(value: string): string {
  return value
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase())
}

export function truncate(value: string, max = 80): string {
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`
}
