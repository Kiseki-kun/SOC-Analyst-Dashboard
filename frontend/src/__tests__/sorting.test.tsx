import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { useState } from 'react'

import { PlainHeader, SortableHeader } from '@/components/SortableHeader'
import type { SortState } from '@/components/SortableHeader'
import { useTableSort } from '@/hooks/useTableSort'

/* ------------------------------------------------------------------ helpers */

interface Row {
  id: string
  timestamp: string
  username: string | null
  severity: string
  count: number
}

const ROWS: Row[] = [
  { id: 'b', timestamp: '2026-09-03T10:30:00Z', username: 'bravo', severity: 'high', count: 5 },
  { id: 'a', timestamp: '2026-09-03T09:00:00Z', username: 'alpha', severity: 'critical', count: 12 },
  { id: 'd', timestamp: '2026-09-03T12:00:00Z', username: null, severity: 'low', count: 1 },
  { id: 'c', timestamp: '2026-09-03T11:15:00Z', username: 'charlie', severity: 'medium', count: 9 },
]

const ACCESSORS = {
  timestamp: (r: Row) => r.timestamp,
  username: (r: Row) => r.username,
  count: (r: Row) => r.count,
}

/** A table wired exactly as the evidence tables are. */
function EvidenceTable({ rows = ROWS }: { rows?: Row[] }) {
  const { sorted, sort, onSort } = useTableSort(rows, ACCESSORS, {
    by: 'timestamp',
    dir: 'desc',
  })
  return (
    <table>
      <caption>Evidence</caption>
      <thead>
        <tr>
          <SortableHeader
            label="Time"
            field="timestamp"
            sort={sort}
            onSort={onSort}
            defaultDirection="desc"
            ascLabel="oldest first"
            descLabel="newest first"
          />
          <SortableHeader label="Account" field="username" sort={sort} onSort={onSort} />
          <SortableHeader label="Count" field="count" sort={sort} onSort={onSort} />
          <PlainHeader label="Message" />
        </tr>
      </thead>
      <tbody>
        {sorted.map((row) => (
          <tr key={row.id}>
            <td>{row.timestamp}</td>
            <td>{row.username ?? '—'}</td>
            <td>{row.count}</td>
            <td>message</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

/** Strict indexing is on, so array access is narrowed explicitly. */
function tableBody(): HTMLElement {
  const groups = screen.getAllByRole('rowgroup')
  const body = groups[1] ?? groups[0]
  if (!body) throw new Error('no table body rendered')
  return body
}

function cellTexts(columnIndex: number): string[] {
  return within(tableBody())
    .getAllByRole('row')
    .map((row) => {
      const cell = within(row).getAllByRole('cell')[columnIndex]
      return cell?.textContent ?? ''
    })
}

function rowOrder(): string[] {
  return cellTexts(0)
}

/* ------------------------------------------------------- timestamp sorting */

describe('evidence table timestamp sorting', () => {
  it('defaults to newest first', () => {
    render(<EvidenceTable />)
    expect(rowOrder()).toEqual([
      '2026-09-03T12:00:00Z',
      '2026-09-03T11:15:00Z',
      '2026-09-03T10:30:00Z',
      '2026-09-03T09:00:00Z',
    ])
  })

  it('switches to oldest first when the header is activated', async () => {
    const user = userEvent.setup()
    render(<EvidenceTable />)
    await user.click(screen.getByRole('button', { name: /Time/ }))
    expect(rowOrder()).toEqual([
      '2026-09-03T09:00:00Z',
      '2026-09-03T10:30:00Z',
      '2026-09-03T11:15:00Z',
      '2026-09-03T12:00:00Z',
    ])
  })

  it('toggles back to newest first on a second activation', async () => {
    const user = userEvent.setup()
    render(<EvidenceTable />)
    const header = screen.getByRole('button', { name: /Time/ })
    await user.click(header)
    await user.click(screen.getByRole('button', { name: /Time/ }))
    expect(rowOrder()[0]).toBe('2026-09-03T12:00:00Z')
  })

  it('is reachable and operable by keyboard alone', async () => {
    const user = userEvent.setup()
    render(<EvidenceTable />)
    await user.tab()
    expect(screen.getByRole('button', { name: /Time/ })).toHaveFocus()
    await user.keyboard('{Enter}')
    expect(rowOrder()[0]).toBe('2026-09-03T09:00:00Z')
    await user.keyboard(' ')
    expect(rowOrder()[0]).toBe('2026-09-03T12:00:00Z')
  })
})

/* ------------------------------------------------------ sort-state signals */

describe('sort direction is announced, not just drawn', () => {
  it('marks the active column with aria-sort and the others with none', async () => {
    const user = userEvent.setup()
    render(<EvidenceTable />)

    const timeHeader = screen.getByRole('columnheader', { name: /Time/ })
    const accountHeader = screen.getByRole('columnheader', { name: /Account/ })
    expect(timeHeader).toHaveAttribute('aria-sort', 'descending')
    expect(accountHeader).toHaveAttribute('aria-sort', 'none')

    await user.click(screen.getByRole('button', { name: /Time/ }))
    expect(screen.getByRole('columnheader', { name: /Time/ })).toHaveAttribute(
      'aria-sort',
      'ascending',
    )
  })

  it('moves aria-sort to the newly chosen column', async () => {
    const user = userEvent.setup()
    render(<EvidenceTable />)
    await user.click(screen.getByRole('button', { name: /Account/ }))
    expect(screen.getByRole('columnheader', { name: /Account/ })).toHaveAttribute(
      'aria-sort',
      'ascending',
    )
    expect(screen.getByRole('columnheader', { name: /Time/ })).toHaveAttribute(
      'aria-sort',
      'none',
    )
  })

  it('names the current order and the effect of activating', () => {
    render(<EvidenceTable />)
    expect(
      screen.getByRole('button', { name: /Time, sorted newest first\. Activate to sort oldest first\./ }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /Account, not sorted\. Activate to sort ascending\./ }),
    ).toBeInTheDocument()
  })

  it('shows a direction indicator only on the active column', async () => {
    const user = userEvent.setup()
    render(<EvidenceTable />)
    expect(screen.getByTestId('sort-indicator-timestamp')).toHaveTextContent('▼')
    await user.click(screen.getByRole('button', { name: /Time/ }))
    expect(screen.getByTestId('sort-indicator-timestamp')).toHaveTextContent('▲')
  })

  it('does not make a non-sortable column look sortable', () => {
    render(<EvidenceTable />)
    const message = screen.getByRole('columnheader', { name: 'Message' })
    expect(message).not.toHaveAttribute('aria-sort')
    expect(within(message).queryByRole('button')).toBeNull()
  })
})

/* ---------------------------------------------------------- sorting values */

describe('sort comparison rules', () => {
  it('sorts numbers numerically, not lexically', async () => {
    const user = userEvent.setup()
    render(<EvidenceTable />)
    await user.click(screen.getByRole('button', { name: /Count/ }))
    expect(cellTexts(2).map(Number)).toEqual([1, 5, 9, 12])
  })

  it('places missing values last in both directions', async () => {
    const user = userEvent.setup()
    render(<EvidenceTable />)
    const accountAt = () => cellTexts(1)
    await user.click(screen.getByRole('button', { name: /Account/ }))
    expect(accountAt()[3]).toBe('—')
    await user.click(screen.getByRole('button', { name: /Account/ }))
    // Still last: an absent value is unknown, not "smallest".
    expect(accountAt()[3]).toBe('—')
  })

  it('does not mutate the array it was given', () => {
    const original = [...ROWS]
    render(<EvidenceTable rows={original} />)
    expect(original.map((r) => r.id)).toEqual(['b', 'a', 'd', 'c'])
  })

  it('renders every row, so counts are never changed by sorting', async () => {
    const user = userEvent.setup()
    render(<EvidenceTable />)
    expect(rowOrder()).toHaveLength(4)
    await user.click(screen.getByRole('button', { name: /Time/ }))
    expect(rowOrder()).toHaveLength(4)
  })

  it('handles an empty table without error', () => {
    render(<EvidenceTable rows={[]} />)
    expect(screen.getByRole('columnheader', { name: /Time/ })).toBeInTheDocument()
  })
})

/* --------------------------------------- server-side pattern: filter safety */

/**
 * The paginated tables put sort state in the URL. The behaviour that matters is
 * that choosing a sort changes ONLY the sort keys and the page - never a filter.
 */
function urlSortReducer(current: string, field: string, dir: 'asc' | 'desc'): string {
  const next = new URLSearchParams(current)
  next.set('sort_by', field)
  next.set('sort_dir', dir)
  next.delete('page')
  return next.toString()
}

describe('URL-backed sorting preserves investigation context', () => {
  it('keeps every existing filter when the sort changes', () => {
    const before = 'severity=critical&severity=high&outcome=failure&search=admin&page=3'
    const after = new URLSearchParams(urlSortReducer(before, 'timestamp', 'asc'))
    expect(after.getAll('severity')).toEqual(['critical', 'high'])
    expect(after.get('outcome')).toBe('failure')
    expect(after.get('search')).toBe('admin')
  })

  it('applies the requested sort', () => {
    const after = new URLSearchParams(urlSortReducer('severity=high', 'timestamp', 'asc'))
    expect(after.get('sort_by')).toBe('timestamp')
    expect(after.get('sort_dir')).toBe('asc')
  })

  it('returns to page 1, because page 7 of a re-sorted list is meaningless', () => {
    const after = new URLSearchParams(urlSortReducer('page=7&severity=high', 'severity', 'desc'))
    expect(after.get('page')).toBeNull()
    expect(after.get('severity')).toBe('high')
  })

  it('replaces the previous sort rather than accumulating keys', () => {
    const once = urlSortReducer('', 'timestamp', 'desc')
    const twice = new URLSearchParams(urlSortReducer(once, 'severity', 'asc'))
    expect(twice.getAll('sort_by')).toEqual(['severity'])
    expect(twice.getAll('sort_dir')).toEqual(['asc'])
  })
})

/* ------------------------------------------------------------ controlled use */

describe('SortableHeader as a controlled component', () => {
  it('reports the field and the next direction to its caller', async () => {
    const user = userEvent.setup()
    const onSort = vi.fn()
    const sort: SortState = { by: 'timestamp', dir: 'desc' }
    render(
      <table>
        <thead>
          <tr>
            <SortableHeader label="Time" field="timestamp" sort={sort} onSort={onSort} />
          </tr>
        </thead>
      </table>,
    )
    await user.click(screen.getByRole('button', { name: /Time/ }))
    expect(onSort).toHaveBeenCalledWith('timestamp', 'asc')
  })

  it('uses the declared default direction for an inactive column', async () => {
    const user = userEvent.setup()
    const onSort = vi.fn()
    render(
      <table>
        <thead>
          <tr>
            <SortableHeader
              label="Time"
              field="timestamp"
              sort={{ by: 'severity', dir: 'asc' }}
              onSort={onSort}
              defaultDirection="desc"
            />
          </tr>
        </thead>
      </table>,
    )
    await user.click(screen.getByRole('button', { name: /Time/ }))
    expect(onSort).toHaveBeenCalledWith('timestamp', 'desc')
  })
})

/* --------------------------------------------- sorting alongside filtering */

function FilterableTable() {
  const [onlyFailures, setOnlyFailures] = useState(false)
  const rows = onlyFailures ? ROWS.filter((r) => r.count > 4) : ROWS
  const { sorted, sort, onSort } = useTableSort(rows, ACCESSORS, { by: 'timestamp', dir: 'desc' })
  return (
    <>
      <button onClick={() => setOnlyFailures((v) => !v)}>Toggle filter</button>
      <table>
        <thead>
          <tr>
            <SortableHeader label="Time" field="timestamp" sort={sort} onSort={onSort} />
          </tr>
        </thead>
        <tbody>
          {sorted.map((r) => (
            <tr key={r.id}>
              <td>{r.timestamp}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  )
}

describe('client-side sorting and filtering together', () => {
  it('keeps the chosen sort when the filter changes', async () => {
    const user = userEvent.setup()
    render(<FilterableTable />)
    await user.click(screen.getByRole('button', { name: /Time/ }))       // oldest first
    await user.click(screen.getByRole('button', { name: 'Toggle filter' }))
    const stamps = within(tableBody()).getAllByRole('row').map((r) => r.textContent)
    expect(stamps).toEqual(['2026-09-03T09:00:00Z', '2026-09-03T10:30:00Z', '2026-09-03T11:15:00Z'])
    expect(screen.getByRole('columnheader', { name: /Time/ })).toHaveAttribute(
      'aria-sort',
      'ascending',
    )
  })

  it('sorts only what the filter left behind', async () => {
    const user = userEvent.setup()
    render(<FilterableTable />)
    await user.click(screen.getByRole('button', { name: 'Toggle filter' }))
    expect(within(tableBody()).getAllByRole('row')).toHaveLength(3)
  })
})
