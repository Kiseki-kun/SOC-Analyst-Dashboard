import { useMemo, useState } from 'react'

import type { SortDirection, SortState } from '@/components/SortableHeader'

/** Value a row contributes to a comparison. Null sorts last in both directions. */
export type SortValue = string | number | null | undefined

export type SortAccessors<T> = Record<string, (row: T) => SortValue>

function isMissing(value: SortValue): boolean {
  return value === null || value === undefined || value === ''
}

function comparePresent(a: SortValue, b: SortValue): number {
  if (typeof a === 'number' && typeof b === 'number') return a - b
  return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' })
}

/**
 * Client-side sorting for tables whose rows are already fully loaded.
 *
 * Used for an alert's evidence events and an address's recent activity: both
 * arrive complete inside a single detail response, so paging them back to the
 * server to reorder a few dozen rows would be slower and no more correct.
 *
 * Tables backed by a paginated endpoint sort server-side instead, through the
 * existing allow-listed `sort_by`/`sort_dir` parameters — reordering only the
 * current page would silently lie about what the ordering means.
 */
export function useTableSort<T>(
  rows: readonly T[],
  accessors: SortAccessors<T>,
  initial: SortState,
) {
  const [sort, setSort] = useState<SortState>(initial)

  const sorted = useMemo(() => {
    const accessor = accessors[sort.by]
    if (!accessor) return [...rows]
    // Array.prototype.sort is stable in every engine this targets, so rows
    // with equal keys keep their original relative order.
    const copy = [...rows]
    copy.sort((left, right) => {
      const a = accessor(left)
      const b = accessor(right)

      // Missing values sort last in BOTH directions. This is handled before the
      // direction flip on purpose: negating the whole comparison would send
      // them to the top when sorting descending, burying them above the rows
      // the analyst actually asked to see. An absent value is unknown, not
      // "smallest".
      const aMissing = isMissing(a)
      const bMissing = isMissing(b)
      if (aMissing && bMissing) return 0
      if (aMissing) return 1
      if (bMissing) return -1

      const result = comparePresent(a, b)
      return sort.dir === 'asc' ? result : -result
    })
    return copy
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, sort.by, sort.dir])

  const onSort = (field: string, direction: SortDirection) => setSort({ by: field, dir: direction })

  return { sorted, sort, onSort }
}
