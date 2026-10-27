const BASE = '/api'

export function getCsrfToken(): string {
  const match = document.cookie.match(/(?:^|;\s*)universal_csrf=([^;]+)/)
  return match ? decodeURIComponent(match[1]) : ''
}

interface ValidationIssue {
  loc?: (string | number)[]
  msg?: string
}

/**
 * Turn an API error body into one readable sentence. FastAPI sends `detail` as
 * a string for HTTPException, but as an ARRAY of {loc, msg} for request
 * validation (422) — passing that to `new Error()` printed "[object Object]".
 * Every error path in the app (the `api` client and raw fetch uploads) goes
 * through this, so the user always sees e.g. "password: String should have at
 * least 12 characters".
 */
export function apiErrorMessage(body: unknown, status: number): string {
  const detail = (body as { detail?: unknown } | null)?.detail
  if (typeof detail === 'string' && detail.trim()) return detail
  if (Array.isArray(detail) && detail.length > 0) {
    return detail
      .map((d: ValidationIssue | string) => {
        if (typeof d === 'string') return d
        const field = (d.loc ?? []).filter(p => p !== 'body' && p !== 'query' && p !== 'path').join('.')
        const msg = d.msg ?? 'invalid value'
        return field ? `${field}: ${msg}` : msg
      })
      .join('; ')
  }
  if (detail && typeof detail === 'object') {
    const msg = (detail as { message?: unknown }).message
    if (typeof msg === 'string') return msg
  }
  if (status === 401) return 'Your session has ended — sign in again.'
  if (status === 403) return 'You do not have permission to do that.'
  if (status === 413) return 'The file is too large.'
  return `Request failed (HTTP ${status})`
}

/** Error for a failed `fetch` Response (reads the JSON body if there is one). */
export async function responseError(res: Response): Promise<Error & { status: number }> {
  const body = await res.json().catch(() => ({}))
  return Object.assign(new Error(apiErrorMessage(body, res.status)), { status: res.status })
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }

  const method = options?.method ?? 'GET'
  if (method !== 'GET' && method !== 'HEAD') {
    const token = getCsrfToken()
    if (token) headers['X-CSRF-Token'] = token
  }

  const res = await fetch(`${BASE}${path}`, {
    credentials: 'include',
    headers: { ...headers, ...options?.headers },
    ...options,
  })
  if (!res.ok) throw await responseError(res)
  return res.json()
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'POST', body: body ? JSON.stringify(body) : undefined }),
  patch: <T>(path: string, body: unknown) =>
    request<T>(path, { method: 'PATCH', body: JSON.stringify(body) }),
  put: <T>(path: string, body: unknown) =>
    request<T>(path, { method: 'PUT', body: JSON.stringify(body) }),
  delete: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
}

/**
 * GET a file from the API and hand it to the browser as a download. Errors
 * (404 no file, 409 integrity mismatch, 403…) reject with the readable message.
 */
export async function downloadFile(path: string, filename: string): Promise<void> {
  const res = await fetch(`${BASE}${path}`, { credentials: 'include' })
  if (!res.ok) throw await responseError(res)
  const url = URL.createObjectURL(await res.blob())
  try {
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    a.remove()
  } finally {
    // revoke on the next tick so the click has started the download
    setTimeout(() => URL.revokeObjectURL(url), 0)
  }
}
