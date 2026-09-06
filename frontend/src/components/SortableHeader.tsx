import clsx from 'clsx'

export type SortDirection = 'asc' | 'desc'

export interface SortState {
  by: string
  dir: SortDirection
}

/**
 * An accessible sortable column header.
 *
 * Three things make this usable rather than merely clickable:
 *
 * - The `<th>` carries `aria-sort`, which is how assistive technology reports
 *   which column a table is ordered by. The arrow alone conveys nothing to a
 *   screen reader.
 * - The control is a real `<button>`, so Enter and Space work without any
 *   keyboard handling of our own, and it lands in the tab order naturally.
 * - The accessible name states the current order *and* what activating will do,
 *   because "Timestamp, sorted" leaves the user guessing which way.
 */
export function SortableHeader({
  label,
  field,
  sort,
  onSort,
  defaultDirection = 'asc',
  align = 'left',
  className,
  ascLabel,
  descLabel,
}: {
  label: string
  field: string
  sort: SortState
  onSort: (field: string, direction: SortDirection) => void
  /** Direction applied the first time this column is chosen. */
  defaultDirection?: SortDirection
  align?: 'left' | 'right'
  className?: string
  /** Domain wording, e.g. "oldest first" instead of "ascending". */
  ascLabel?: string
  descLabel?: string
}) {
  const isActive = sort.by === field
  const direction: SortDirection = isActive ? sort.dir : defaultDirection
  const nextDirection: SortDirection = isActive
    ? direction === 'asc'
      ? 'desc'
      : 'asc'
    : defaultDirection

  const ascText = ascLabel ?? 'ascending'
  const descText = descLabel ?? 'descending'
  const currentText = direction === 'asc' ? ascText : descText
  const nextText = nextDirection === 'asc' ? ascText : descText

  const accessibleName = isActive
    ? `${label}, sorted ${currentText}. Activate to sort ${nextText}.`
    : `${label}, not sorted. Activate to sort ${nextText}.`

  return (
    <th
      scope="col"
      // The programmatic signal. Without it the sort state is visual only.
      aria-sort={isActive ? (direction === 'asc' ? 'ascending' : 'descending') : 'none'}
      className={clsx('px-3 py-2 font-medium', className)}
    >
      <button
        type="button"
        onClick={() => onSort(field, nextDirection)}
        aria-label={accessibleName}
        title={accessibleName}
        className={clsx(
          'group inline-flex items-center gap-1 rounded px-1 -mx-1 py-0.5',
          'text-2xs uppercase tracking-wide transition-colors',
          'hover:text-ink-100 focus-visible:outline-none focus-visible:ring-2',
          'focus-visible:ring-accent focus-visible:ring-offset-1 focus-visible:ring-offset-surface-900',
          isActive ? 'text-ink-100' : 'text-ink-400',
          align === 'right' && 'flex-row-reverse',
        )}
      >
        <span>{label}</span>
        <span
          aria-hidden
          className={clsx(
            'text-[0.6rem] leading-none transition-opacity',
            isActive ? 'opacity-100' : 'opacity-0 group-hover:opacity-40',
          )}
          data-testid={`sort-indicator-${field}`}
        >
          {direction === 'asc' ? '▲' : '▼'}
        </span>
      </button>
    </th>
  )
}

/** A plain, non-sortable header, so header rows stay visually consistent. */
export function PlainHeader({
  label,
  className,
}: {
  label: string
  className?: string
}) {
  return (
    <th
      scope="col"
      className={clsx(
        'px-3 py-2 font-medium text-2xs uppercase tracking-wide text-ink-400',
        className,
      )}
    >
      {label}
    </th>
  )
}
