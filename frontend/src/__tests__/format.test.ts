import { describe, expect, it } from 'vitest'

import { formatDuration, formatNumber, formatTimestamp, titleCase, truncate } from '@/lib/format'

describe('formatDuration', () => {
  it('never reports an unmeasured metric as zero', () => {
    // The backend returns null when no incident has reached that stage.
    // Rendering "0 min" would be a fabricated statistic.
    expect(formatDuration(null)).toBe('Not yet measured')
    expect(formatDuration(undefined)).toBe('Not yet measured')
  })

  it('renders minutes, hours and days', () => {
    expect(formatDuration(0.4)).toBe('< 1 min')
    expect(formatDuration(45)).toBe('45 min')
    expect(formatDuration(150)).toBe('2.5 h')
    expect(formatDuration(2880)).toBe('2.0 d')
  })
})

describe('formatting helpers', () => {
  it('renders an em dash for absent values rather than "null"', () => {
    expect(formatNumber(null)).toBe('—')
    expect(formatTimestamp(null)).toBe('—')
    expect(formatTimestamp('not-a-date')).toBe('—')
  })

  it('humanises identifiers', () => {
    expect(titleCase('brute_force_authentication')).toBe('Brute Force Authentication')
  })

  it('truncates with an ellipsis', () => {
    expect(truncate('abcdefghij', 5)).toBe('abcd…')
    expect(truncate('abc', 5)).toBe('abc')
  })
})
