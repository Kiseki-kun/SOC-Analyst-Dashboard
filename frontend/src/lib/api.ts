/**
 * API client.
 *
 * Two decisions worth understanding:
 *
 * 1. The access token lives in a module variable, not localStorage. A token in
 *    localStorage is readable by any script on the page, so a single XSS gives
 *    an attacker a bearer credential they can use from anywhere. Holding it in
 *    memory means it dies with the tab.
 *
 * 2. The refresh token is never touched by this code at all. It is an httpOnly
 *    cookie the browser attaches to /auth/refresh automatically. JavaScript
 *    cannot read it, which is the entire point.
 */

const BASE_URL: string =
  (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? 'http://localhost:58000/api/v1'

let accessToken: string | null = null
let onUnauthenticated: (() => void) | null = null

export function setAccessToken(token: string | null): void {
  accessToken = token
}

export function getAccessToken(): string | null {
  return accessToken
}

export function setUnauthenticatedHandler(handler: (() => void) | null): void {
  onUnauthenticated = handler
}

export class ApiError extends Error {
  readonly status: number
  readonly correlationId: string | null
  readonly fieldErrors: { field: string; message: string }[]

  constructor(
    status: number,
    message: string,
    correlationId: string | null = null,
    fieldErrors: { field: string; message: string }[] = [],
  ) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.correlationId = correlationId
    this.fieldErrors = fieldErrors
  }
}

interface RequestOptions {
  method?: string
  body?: unknown
  // Set for the refresh call itself, so a failed refresh cannot recurse.
  skipRefresh?: boolean
  signal?: AbortSignal
}

async function parseError(response: Response): Promise<ApiError> {
  let detail = response.statusText || 'Request failed'
  let correlationId: string | null = response.headers.get('X-Correlation-ID')
  let fieldErrors: { field: string; message: string }[] = []
  try {
    const body = await response.json()
    if (typeof body?.detail === 'string') detail = body.detail
    if (typeof body?.correlation_id === 'string') correlationId = body.correlation_id
    if (Array.isArray(body?.errors)) fieldErrors = body.errors
  } catch {
    // A non-JSON error body (a proxy error page, say) is not worth surfacing
    // verbatim; the status line is more useful than raw HTML.
  }
  return new ApiError(response.status, detail, correlationId, fieldErrors)
}

let refreshInFlight: Promise<boolean> | null = null

async function attemptRefresh(): Promise<boolean> {
  // Collapse concurrent refreshes. Without this, six queries firing on page
  // load would each trigger their own refresh and rotate the cookie six times,
  // with all but one of the resulting tokens immediately stale.
  if (refreshInFlight) return refreshInFlight

  refreshInFlight = (async () => {
    try {
      const response = await fetch(`${BASE_URL}/auth/refresh`, {
        method: 'POST',
        credentials: 'include',
      })
      if (!response.ok) return false
      const data = await response.json()
      accessToken = data.access_token
      return true
    } catch {
      return false
    } finally {
      // Cleared synchronously. Callers already hold a reference to this
      // promise, so resetting the variable cannot affect them — whereas
      // clearing it on a timer left a window in which a LATER request reused
      // an already-settled result, including a failed refresh reported as a
      // success.
      refreshInFlight = null
    }
  })()

  return refreshInFlight
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = 'GET', body, skipRefresh = false, signal } = options

  const send = async (): Promise<Response> => {
    const headers: Record<string, string> = {}
    if (body !== undefined) headers['Content-Type'] = 'application/json'
    if (accessToken) headers.Authorization = `Bearer ${accessToken}`

    return fetch(`${BASE_URL}${path}`, {
      method,
      headers,
      // Required so the refresh cookie is sent and stored cross-origin
      // (the SPA and API are on different ports).
      credentials: 'include',
      body: body === undefined ? undefined : JSON.stringify(body),
      signal,
    })
  }

  let response = await send()

  if (response.status === 401 && !skipRefresh) {
    // The access token is short-lived by design, so a 401 is expected during
    // an ordinary session. Refresh once, then replay the original request.
    const refreshed = await attemptRefresh()
    if (refreshed) {
      response = await send()
    } else {
      accessToken = null
      onUnauthenticated?.()
      throw await parseError(response)
    }
  }

  if (!response.ok) throw await parseError(response)
  if (response.status === 204) return undefined as T

  const text = await response.text()
  return (text ? JSON.parse(text) : undefined) as T
}

/** Build a query string, dropping empty values and expanding arrays. */
export function qs(params: Record<string, unknown>): string {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue
    if (Array.isArray(value)) {
      for (const item of value) {
        if (item !== undefined && item !== null && item !== '') search.append(key, String(item))
      }
    } else {
      search.append(key, String(value))
    }
  }
  const encoded = search.toString()
  return encoded ? `?${encoded}` : ''
}
