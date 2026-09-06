import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { SeverityBadge, StatusBadge, EmptyState, ErrorState } from '@/components/ui'
import { StatTile } from '@/components/StatTile'

describe('SeverityBadge', () => {
  it('renders the severity as text, not colour alone', () => {
    // The accessibility requirement: `critical` measures 3.91:1 on this
    // surface, so the meaning must never rest on the hue.
    render(<SeverityBadge severity="critical" />)
    expect(screen.getByText('critical')).toBeInTheDocument()
  })

  it('renders every severity level', () => {
    const levels = ['critical', 'high', 'medium', 'low', 'info'] as const
    for (const level of levels) {
      const { unmount } = render(<SeverityBadge severity={level} />)
      expect(screen.getByText(level)).toBeInTheDocument()
      unmount()
    }
  })
})

describe('StatusBadge', () => {
  it('humanises an underscored status', () => {
    render(<StatusBadge status="false_positive" />)
    expect(screen.getByText('False Positive')).toBeInTheDocument()
  })
})

describe('StatTile', () => {
  it('renders a numeric value with thousands separators', () => {
    render(<StatTile label="Events" value={12345} />)
    expect(screen.getByText('12,345')).toBeInTheDocument()
  })

  it('renders an em dash rather than "null" for a missing value', () => {
    render(<StatTile label="Events" value={null} />)
    expect(screen.getByText('—')).toBeInTheDocument()
  })

  it('passes through a pre-formatted string such as "Not yet measured"', () => {
    render(<StatTile label="MTTR" value="Not yet measured" />)
    expect(screen.getByText('Not yet measured')).toBeInTheDocument()
  })
})

describe('state components', () => {
  it('empty state shows a title and a hint', () => {
    render(<EmptyState title="Nothing here" hint="Try widening the filter" />)
    expect(screen.getByText('Nothing here')).toBeInTheDocument()
    expect(screen.getByText('Try widening the filter')).toBeInTheDocument()
  })

  it('error state surfaces the correlation id for support', () => {
    render(<ErrorState message="It broke" correlationId="xyz789" />)
    expect(screen.getByText('It broke')).toBeInTheDocument()
    expect(screen.getByText(/xyz789/)).toBeInTheDocument()
  })
})
