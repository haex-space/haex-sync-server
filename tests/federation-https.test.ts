/**
 * Tests for the federation DID-Web resolver (fix 1.3).
 *
 * The resolver used to silently fall back from HTTPS to HTTP if HTTPS failed,
 * which enabled MITM on the DID document — the attacker could serve a did.json
 * with their own public key over HTTP even for a did:web whose canonical
 * transport is HTTPS.
 *
 * We drive the REAL federationAuthMiddleware. A controllable global fetch
 * mock lets us simulate network errors per protocol, and the db/serverIdentity
 * mocks are the minimal surface needed to reach the resolver branch.
 */

import { describe, test, expect, mock, beforeAll, afterAll, beforeEach } from 'bun:test'
import { Hono } from 'hono'
import { spaceResource, createUcan } from '@haex-space/ucan'
import {
  makeIdentity,
  makeServerIdentity,
  buildDidDocument,
  buildFederationHeader,
  type Identity,
  type ServerIdentity,
} from './integration/helpers'
import { buildDbMock } from './helpers/db-mock'

const TEST_SPACE_ID = '11111111-1111-4111-8111-111111111111'

let mockMemberDids: string[] = []

mock.module('../src/db', () => buildDbMock({
  select: () => ({
    from: () => ({
      where: () => ({
        limit: () => {
          const did = mockMemberDids[0]
          return Promise.resolve(did ? [{ did }] : [])
        },
      }),
    }),
  }),
}))

mock.module('../src/services/serverIdentity', () => ({
  getServerIdentity: () => null,
  isFederationEnabled: () => true,
}))

let federationAuthMiddleware: any

beforeAll(async () => {
  ({ federationAuthMiddleware } = await import('../src/middleware/federationAuth'))
})

let relay: ServerIdentity
let origin: ServerIdentity
let user: Identity
let validRelayUcan: string
const originalFetch = globalThis.fetch

beforeAll(async () => {
  relay = await makeServerIdentity('relay.test.local')
  origin = await makeServerIdentity('origin.test.local')
  user = await makeIdentity()

  validRelayUcan = await createUcan({
    issuer: user.did,
    audience: relay.did,
    capabilities: { [spaceResource(TEST_SPACE_ID)]: 'server/relay' },
    expiration: Math.floor(Date.now() / 1000) + 3600,
  }, user.sign)

  mockMemberDids = [user.did]
})

afterAll(() => {
  globalThis.fetch = originalFetch
})

beforeEach(() => {
  // Reset to a permissive default fetch — individual tests override.
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url = typeof input === 'string' ? input : input.toString()
    if (url.startsWith('https://relay.test.local/.well-known/did.json')) {
      return new Response(JSON.stringify(buildDidDocument(relay)), { status: 200 })
    }
    return new Response('Not Found', { status: 404 })
  }) as unknown as typeof fetch
})

function buildApp() {
  const app = new Hono()
  app.use('*', federationAuthMiddleware)
  app.post('/test', (c: any) => c.json({ ok: true }))
  return app
}

// ── Tests ───────────────────────────────────────────────────────────────

describe('federation DID-Web resolver — HTTPS-only (fix 1.3)', () => {
  test('accepts DID document served over HTTPS', async () => {
    const app = buildApp()
    const header = await buildFederationHeader({
      server: relay,
      action: 'test',
      body: '',
      ucanToken: validRelayUcan,
    })

    const res = await app.request('/test', {
      method: 'POST',
      headers: { Authorization: header },
      body: '',
    })
    expect(res.status).toBe(200)
  })

  test('attack: MITM DID doc over HTTP is ignored — no silent fallback', async () => {
    // Attacker controls the network path and answers HTTPS with a connection
    // error, but serves a malicious did.json over HTTP. The pre-fix resolver
    // would have fetched the attacker's doc. We verify HTTP is never even
    // attempted.
    const evil = await makeServerIdentity('relay.test.local')
    let httpAttempted = false

    globalThis.fetch = (async (input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url.startsWith('http://relay.test.local/')) {
        httpAttempted = true
        return new Response(JSON.stringify(buildDidDocument(evil)), { status: 200 })
      }
      // Simulate HTTPS unavailable (connection refused / handshake failure)
      if (url.startsWith('https://relay.test.local/')) {
        throw new Error('TLS handshake failed')
      }
      return new Response('Not Found', { status: 404 })
    }) as unknown as typeof fetch

    const app = buildApp()
    const header = await buildFederationHeader({
      server: relay,
      action: 'test',
      body: '',
      ucanToken: validRelayUcan,
    })

    const res = await app.request('/test', {
      method: 'POST',
      headers: { Authorization: header },
      body: '',
    })
    expect(res.status).toBe(401)
    expect(httpAttempted).toBe(false)
  })

  test('rejects when HTTPS fetch throws (no fallback to HTTP)', async () => {
    globalThis.fetch = (async () => {
      throw new Error('ETIMEDOUT')
    }) as unknown as typeof fetch

    const app = buildApp()
    const header = await buildFederationHeader({
      server: relay,
      action: 'test',
      body: '',
      ucanToken: validRelayUcan,
    })

    const res = await app.request('/test', {
      method: 'POST',
      headers: { Authorization: header },
      body: '',
    })
    expect(res.status).toBe(401)
    const json = await res.json() as any
    expect(json.error).toMatch(/resolve/i)
  })

  test('rejects when HTTPS returns non-2xx', async () => {
    globalThis.fetch = (async () => new Response('not found', { status: 404 })) as unknown as typeof fetch

    const app = buildApp()
    const header = await buildFederationHeader({
      server: relay,
      action: 'test',
      body: '',
      ucanToken: validRelayUcan,
    })

    const res = await app.request('/test', {
      method: 'POST',
      headers: { Authorization: header },
      body: '',
    })
    expect(res.status).toBe(401)
  })
})
