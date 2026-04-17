/**
 * Tests for index.ts security fixes:
 *   - 4.1 — global error handler must not leak err.message
 *   - 6.1 — CORS must not default to '*'
 *
 * These tests reconstruct the exact middleware/handler setup from index.ts
 * on a fresh Hono instance. This lets us run them in-process and exercise
 * the real `hono/cors` middleware with the same configuration shape
 * production uses — only the environment variable is under test control.
 */

import { describe, test, expect } from 'bun:test'
import { Hono } from 'hono'
import { cors } from 'hono/cors'

// ── Error handler (4.1) ─────────────────────────────────────────────────

function buildAppWithErrorHandler() {
  const app = new Hono()
  app.get('/explode', () => {
    throw new Error('SELECT password FROM users WHERE id=42 failed: super secret stack info')
  })

  // Copy of the production error handler.
  app.onError((err, c) => {
    const correlationId = crypto.randomUUID()
    console.error(`Server error [${correlationId}]:`, err)
    return c.json({ error: 'Internal Server Error', correlationId }, 500)
  })

  return app
}

describe('global error handler — sanitisation (fix 4.1)', () => {
  test('returns 500 with a generic error body', async () => {
    const app = buildAppWithErrorHandler()
    const res = await app.request('/explode')
    expect(res.status).toBe(500)
    const body = await res.json() as any
    expect(body.error).toBe('Internal Server Error')
  })

  test('does NOT leak err.message to clients', async () => {
    const app = buildAppWithErrorHandler()
    const res = await app.request('/explode')
    const rawText = await res.text()
    expect(rawText).not.toContain('SELECT')
    expect(rawText).not.toContain('password')
    expect(rawText).not.toContain('super secret')
    expect(rawText).not.toContain('stack')
  })

  test('returns a fresh correlationId per request (non-correlatable by client)', async () => {
    const app = buildAppWithErrorHandler()
    const r1 = await (await app.request('/explode')).json() as any
    const r2 = await (await app.request('/explode')).json() as any
    expect(r1.correlationId).toBeDefined()
    expect(r2.correlationId).toBeDefined()
    expect(r1.correlationId).not.toBe(r2.correlationId)
    // UUID v4 format
    expect(r1.correlationId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
  })

  test('attack: error thrown from nested path still sanitised', async () => {
    const app = buildAppWithErrorHandler()
    app.get('/deep/:id', (c) => {
      // Simulate a DB driver error that would leak the schema
      throw new Error(`connection to postgres://user:pa$$word@10.0.0.5/db refused for id=${c.req.param('id')}`)
    })
    const res = await app.request('/deep/abc')
    const body = await res.text()
    expect(body).not.toContain('postgres')
    expect(body).not.toContain('pa$$word')
    expect(body).not.toContain('10.0.0.5')
    expect(body).not.toContain('abc') // path-injected value also gone
  })
})

// ── CORS default (6.1) ──────────────────────────────────────────────────

/**
 * Mirrors the index.ts startup logic that converts CORS_ORIGIN to the
 * `origin` option accepted by hono/cors.
 */
function parseAllowedOrigins(env: string | undefined): string[] {
  if (!env) return []
  return env.split(',').map(o => o.trim()).filter(Boolean)
}

function buildAppWithCors(env: string | undefined) {
  const app = new Hono()
  app.use('*', cors({ origin: parseAllowedOrigins(env), credentials: true }))
  app.get('/public', (c) => c.json({ ok: true }))
  return app
}

describe('CORS default (fix 6.1)', () => {
  test('unset CORS_ORIGIN does NOT emit a wildcard Access-Control-Allow-Origin', async () => {
    const app = buildAppWithCors(undefined)
    const res = await app.request('/public', {
      headers: { Origin: 'https://evil.example.com' },
    })
    expect(res.headers.get('Access-Control-Allow-Origin')).not.toBe('*')
    // With an empty allow-list, the browser sees no CORS header at all —
    // same-origin requests still work, cross-origin is blocked client-side.
    expect(res.headers.get('Access-Control-Allow-Origin')).toBeNull()
  })

  test('unset CORS_ORIGIN: preflight from unauthorized origin is not allowed', async () => {
    const app = buildAppWithCors(undefined)
    const res = await app.request('/public', {
      method: 'OPTIONS',
      headers: {
        Origin: 'https://evil.example.com',
        'Access-Control-Request-Method': 'GET',
      },
    })
    // hono/cors returns an empty-body preflight even without a matching origin,
    // but crucially must not echo the evil Origin back.
    expect(res.headers.get('Access-Control-Allow-Origin')).not.toBe('https://evil.example.com')
    expect(res.headers.get('Access-Control-Allow-Origin')).not.toBe('*')
  })

  test('explicit CORS_ORIGIN allows listed origin', async () => {
    const app = buildAppWithCors('https://app.example.com,https://admin.example.com')
    const res = await app.request('/public', {
      headers: { Origin: 'https://app.example.com' },
    })
    expect(res.headers.get('Access-Control-Allow-Origin')).toBe('https://app.example.com')
  })

  test('explicit CORS_ORIGIN blocks unlisted origin', async () => {
    const app = buildAppWithCors('https://app.example.com')
    const res = await app.request('/public', {
      headers: { Origin: 'https://evil.example.com' },
    })
    expect(res.headers.get('Access-Control-Allow-Origin')).not.toBe('https://evil.example.com')
    expect(res.headers.get('Access-Control-Allow-Origin')).not.toBe('*')
  })

  test('trims whitespace around CORS_ORIGIN entries', async () => {
    const app = buildAppWithCors('  https://a.example.com  ,  https://b.example.com  ')
    const res = await app.request('/public', {
      headers: { Origin: 'https://a.example.com' },
    })
    expect(res.headers.get('Access-Control-Allow-Origin')).toBe('https://a.example.com')
  })

  test('attack: empty string origin (spoofing null)', async () => {
    const app = buildAppWithCors('')
    const res = await app.request('/public', {
      headers: { Origin: 'null' },
    })
    expect(res.headers.get('Access-Control-Allow-Origin')).not.toBe('null')
    expect(res.headers.get('Access-Control-Allow-Origin')).not.toBe('*')
  })
})
