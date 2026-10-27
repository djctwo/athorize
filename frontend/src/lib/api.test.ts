import { afterEach, describe, expect, it, vi } from 'vitest'
import { api, apiErrorMessage, responseError } from './api'

// E2E-9: FastAPI 422 bodies carry `detail` as an array; it used to surface as "[object Object]".
const PYDANTIC_422 = {
  detail: [
    { type: 'string_too_short', loc: ['body', 'password'], msg: 'String should have at least 12 characters', input: 'Ab1!' },
    { type: 'string_type', loc: ['body', 'performed_by'], msg: 'Input should be a valid string', input: null },
  ],
}

describe('apiErrorMessage', () => {
  it('turns a pydantic detail array into field: message pairs', () => {
    expect(apiErrorMessage(PYDANTIC_422, 422)).toBe(
      'password: String should have at least 12 characters; performed_by: Input should be a valid string',
    )
  })
  it('keeps a plain string detail', () => {
    expect(apiErrorMessage({ detail: "File type '.exe' not allowed" }, 415)).toBe("File type '.exe' not allowed")
  })
  it('falls back to a status sentence, never [object Object]', () => {
    expect(apiErrorMessage({}, 500)).toBe('Request failed (HTTP 500)')
    expect(apiErrorMessage(null, 403)).toMatch(/permission/)
    expect(apiErrorMessage({ detail: { message: 'nested' } }, 400)).toBe('nested')
    expect(apiErrorMessage({ detail: { foo: 1 } }, 400)).not.toContain('object Object')
  })
})

describe('api client errors', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('rejects with the readable message for a 422', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(PYDANTIC_422), { status: 422 })))
    await expect(api.post('/users', {})).rejects.toThrow('password: String should have at least 12 characters')
  })

  it('responseError keeps the status for callers that branch on it (409)', async () => {
    const err = await responseError(new Response(JSON.stringify({ detail: 'changed by someone else' }), { status: 409 }))
    expect(err.message).toBe('changed by someone else')
    expect(err.status).toBe(409)
  })

  it('handles a non-JSON error body', async () => {
    const err = await responseError(new Response('<html>bad gateway</html>', { status: 502 }))
    expect(err.message).toBe('Request failed (HTTP 502)')
  })
})
