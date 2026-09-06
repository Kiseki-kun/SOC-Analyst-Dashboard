import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError, getAccessToken, qs, request, setAccessToken } from '@/lib/api'

describe('query string builder', () => {
  it('drops empty values so filters do not send blanks', () => {
    expect(qs({ a: 1, b: '', c: null, d: undefined })).toBe('?a=1')
  })

  it('repeats a key for array values, matching the API contract', () => {
    expect(qs({ severity: ['critical', 'high'] })).toBe('?severity=critical&severity=high')
  })

  it('returns an empty string when nothing survives', () => {
    expect(qs({ a: null })).toBe('')
  })

  it('encodes characters that would otherwise break the URL', () => {
    expect(qs({ search: "' OR 1=1" })).toContain('search=')
    expect(qs({ search: "' OR 1=1" })).not.toContain(' OR ')
  })
})

describe('request', () => {
  const fetchMock = vi.fn()

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    setAccessToken(null)
  })
  afterEach(() => vi.unstubAllGlobals())

  const jsonResponse = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    })

  it('attaches the bearer token when one is held', async () => {
    setAccessToken('token-123')
    fetchMock.mockResolvedValueOnce(jsonResponse({ ok: true }))
    await request('/thing')
    // noUncheckedIndexedAccess is on, so the call record is narrowed rather
    // than asserted away with `!`.
    const call = fetchMock.mock.calls[0]
    expect(call).toBeDefined()
    expect(call?.[1]?.headers?.Authorization).toBe('Bearer token-123')
  })

  it('always sends credentials so the refresh cookie travels', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({}))
    await request('/thing')
    expect(fetchMock.mock.calls[0]?.[1]?.credentials).toBe('include')
  })

  it('refreshes once on 401 and replays the original request', async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ detail: 'Not authenticated.' }, 401))
      .mockResolvedValueOnce(jsonResponse({ access_token: 'fresh' }))
      .mockResolvedValueOnce(jsonResponse({ value: 42 }))

    const result = await request<{ value: number }>('/thing')
    expect(result.value).toBe(42)
    expect(getAccessToken()).toBe('fresh')
    expect(fetchMock).toHaveBeenCalledTimes(3)
  })

  it('gives up and clears the token when the refresh also fails', async () => {
    setAccessToken('stale')
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ detail: 'Not authenticated.' }, 401))
      .mockResolvedValueOnce(jsonResponse({ detail: 'no' }, 401))

    await expect(request('/thing')).rejects.toBeInstanceOf(ApiError)
    expect(getAccessToken()).toBeNull()
  })

  it('does not attempt a refresh loop on the refresh call itself', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ detail: 'no' }, 401))
    await expect(request('/auth/refresh', { method: 'POST', skipRefresh: true })).rejects.toThrow()
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('surfaces the correlation id so a user can quote it', async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ detail: 'Boom', correlation_id: 'abc123' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    await expect(request('/thing')).rejects.toMatchObject({
      status: 500,
      correlationId: 'abc123',
    })
  })

  it('does not choke on a non-JSON error body', async () => {
    fetchMock.mockResolvedValueOnce(new Response('<html>gateway error</html>', { status: 502 }))
    await expect(request('/thing')).rejects.toBeInstanceOf(ApiError)
  })
})
