import { describe, test, expect, mock, beforeAll, afterAll } from 'bun:test'
import { Hono } from 'hono'
import { spaceResource } from '@haex-space/ucan'
import { createUcan } from '@haex-space/ucan'
import {
  makeIdentity,
  makeServerIdentity,
  buildDidDocument,
  buildFederationHeader,
  makePrivateKeyBase64,
  createFederatedAuthHeader,
  type Identity,
  type ServerIdentity,
} from '../integration/helpers'

const TEST_SPACE_ID = '11111111-1111-1111-1111-111111111111'

// ── Mutable mock state (changed per test) ───────────────────────────

let mockMemberDids: string[] = []
let mockServerDid = ''

mock.module('../../src/db', () => ({
  db: {
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
  },
  spaceMembers: { did: 'did', spaceId: 'space_id', capability: 'capability' },
}))

mock.module('../../src/services/serverIdentity', () => ({
  getServerIdentity: () => ({ did: mockServerDid }),
  isFederationEnabled: () => true,
}))

// Import AFTER mocks are in place
import { federationAuthMiddleware } from '../../src/middleware/federationAuth'

// ── Shared state ────────────────────────────────────────────────────

let relay: ServerIdentity
let origin: ServerIdentity
let user: Identity
let userPrivateKeyBase64: string
let validRelayUcan: string
const originalFetch = globalThis.fetch

beforeAll(async () => {
  relay = await makeServerIdentity('relay.test.local')
  origin = await makeServerIdentity('origin.test.local')
  user = await makeIdentity()
  userPrivateKeyBase64 = await makePrivateKeyBase64(user.keyPair)

  validRelayUcan = await createUcan({
    issuer: user.did,
    audience: relay.did,
    capabilities: { [spaceResource(TEST_SPACE_ID)]: 'server/relay' },
    expiration: Math.floor(Date.now() / 1000) + 3600,
  }, user.sign)
})

afterAll(() => {
  globalThis.fetch = originalFetch
})

// ── Helpers ─────────────────────────────────────────────────────────

function setupTest(options?: { memberDids?: string[]; serverDid?: string }) {
  mockMemberDids = options?.memberDids ?? [user.did]
  mockServerDid = options?.serverDid ?? origin.did

  globalThis.fetch = (async (input: string | URL | Request) => {
    const url = typeof input === 'string' ? input : input.toString()
    if (url.includes('relay.test.local/.well-known/did.json')) {
      return new Response(JSON.stringify(buildDidDocument(relay)), { status: 200 })
    }
    if (url.includes('origin.test.local/.well-known/did.json')) {
      return new Response(JSON.stringify(buildDidDocument(origin)), { status: 200 })
    }
    return new Response('Not found', { status: 404 })
  }) as typeof fetch

  const app = new Hono()
  app.use('*', federationAuthMiddleware)
  app.post('/test', (c: any) => c.json({ ok: true, federation: c.get('federation') }))
  return app
}

// ── FEDERATION Layer ────────────────────────────────────────────────

describe('Federation Auth — FEDERATION layer', () => {
  test('rejects missing Authorization header', async () => {
    const app = setupTest()
    const res = await app.request('/test', { method: 'POST', body: '' })
    expect(res.status).toBe(401)
  })

  test('rejects wrong auth scheme', async () => {
    const app = setupTest()
    const res = await app.request('/test', {
      method: 'POST',
      headers: { Authorization: 'Bearer token' },
      body: '',
    })
    expect(res.status).toBe(401)
  })

  test('rejects malformed token (no dot)', async () => {
    const app = setupTest()
    const res = await app.request('/test', {
      method: 'POST',
      headers: { Authorization: 'FEDERATION nodot' },
      body: '',
    })
    expect(res.status).toBe(401)
    const json = await res.json() as any
    expect(json.error).toContain('Malformed')
  })

  test('rejects expired request', async () => {
    const app = setupTest()
    const header = await buildFederationHeader({
      server: relay,
      action: 'test',
      body: '',
      ucanToken: validRelayUcan,
      expiresInMs: -1000,
    })

    const res = await app.request('/test', {
      method: 'POST',
      headers: { Authorization: header },
      body: '',
    })
    expect(res.status).toBe(401)
    const json = await res.json() as any
    expect(json.error).toContain('expired')
  })

  test('rejects tampered body', async () => {
    const app = setupTest()
    const header = await buildFederationHeader({
      server: relay,
      action: 'test',
      body: '{"original":true}',
      ucanToken: validRelayUcan,
    })

    const res = await app.request('/test', {
      method: 'POST',
      headers: { Authorization: header, 'Content-Type': 'application/json' },
      body: '{"tampered":true}',
    })
    expect(res.status).toBe(401)
    const json = await res.json() as any
    expect(json.error).toContain('tampered')
  })

  test('rejects signature from wrong server key', async () => {
    const evil = await makeServerIdentity('relay.test.local')
    const app = setupTest()
    const header = await buildFederationHeader({
      server: evil,
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
    expect(json.error).toContain('signature')
  })

  test('rejects did:key as server DID', async () => {
    const app = setupTest()
    const header = await buildFederationHeader({
      server: { ...relay, did: user.did },
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
    expect(json.error).toContain('did:web')
  })

  test('rejects UCAN audience mismatch', async () => {
    const app = setupTest()
    const wrongAudienceUcan = await createUcan({
      issuer: user.did,
      audience: origin.did,
      capabilities: { [spaceResource(TEST_SPACE_ID)]: 'server/relay' },
      expiration: Math.floor(Date.now() / 1000) + 3600,
    }, user.sign)

    const header = await buildFederationHeader({
      server: relay,
      action: 'test',
      body: '',
      ucanToken: wrongAudienceUcan,
    })

    const res = await app.request('/test', {
      method: 'POST',
      headers: { Authorization: header },
      body: '',
    })
    expect(res.status).toBe(403)
    const json = await res.json() as any
    expect(json.error).toContain('audience')
  })

  test('rejects UCAN without server/relay capability', async () => {
    const app = setupTest()
    const wrongCapUcan = await createUcan({
      issuer: user.did,
      audience: relay.did,
      capabilities: { [spaceResource(TEST_SPACE_ID)]: 'space/read' },
      expiration: Math.floor(Date.now() / 1000) + 3600,
    }, user.sign)

    const header = await buildFederationHeader({
      server: relay,
      action: 'test',
      body: '',
      ucanToken: wrongCapUcan,
    })

    const res = await app.request('/test', {
      method: 'POST',
      headers: { Authorization: header },
      body: '',
    })
    expect(res.status).toBe(403)
    const json = await res.json() as any
    expect(json.error).toContain('server/relay')
  })

  test('rejects UCAN root issuer who is not a space member', async () => {
    const app = setupTest({ memberDids: [] })
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
    expect(res.status).toBe(403)
    const json = await res.json() as any
    expect(json.error).toContain('not a member')
  })

  test('accepts valid FEDERATION request', async () => {
    const app = setupTest()
    const body = '{"test":true}'
    const header = await buildFederationHeader({
      server: relay,
      action: 'test-action',
      body,
      ucanToken: validRelayUcan,
    })

    const res = await app.request('/test', {
      method: 'POST',
      headers: { Authorization: header, 'Content-Type': 'application/json' },
      body,
    })
    expect(res.status).toBe(200)
    const json = await res.json() as any
    expect(json.ok).toBe(true)
    expect(json.federation.serverDid).toBe(relay.did)
    expect(json.federation.userAuth).toBeNull()
  })
})

// ── Embedded User Auth ──────────────────────────────────────────────

describe('Federation Auth — embedded user auth', () => {
  test('rejects user auth with wrong serverDid', async () => {
    const app = setupTest({ serverDid: origin.did })
    const body = ''
    const userAuth = await createFederatedAuthHeader({
      did: user.did,
      privateKeyBase64: userPrivateKeyBase64,
      action: 'test',
      federation: { spaceId: TEST_SPACE_ID, serverDid: 'did:web:evil.com', relayDid: relay.did },
      body,
    })
    const header = await buildFederationHeader({
      server: relay, action: 'test', body, ucanToken: validRelayUcan, userAuthorization: userAuth,
    })

    const res = await app.request('/test', { method: 'POST', headers: { Authorization: header }, body })
    expect(res.status).toBe(403)
    const json = await res.json() as any
    expect(json.error).toContain('not intended for this server')
  })

  test('rejects user auth with tampered body', async () => {
    const app = setupTest({ serverDid: origin.did })
    const userAuth = await createFederatedAuthHeader({
      did: user.did,
      privateKeyBase64: userPrivateKeyBase64,
      action: 'test',
      federation: { spaceId: TEST_SPACE_ID, serverDid: origin.did, relayDid: relay.did },
      body: '{"original":true}',
    })
    const tamperedBody = '{"tampered":true}'
    const header = await buildFederationHeader({
      server: relay, action: 'test', body: tamperedBody, ucanToken: validRelayUcan, userAuthorization: userAuth,
    })

    const res = await app.request('/test', {
      method: 'POST',
      headers: { Authorization: header, 'Content-Type': 'application/json' },
      body: tamperedBody,
    })
    expect(res.status).toBe(401)
    const json = await res.json() as any
    expect(json.error).toContain('user auth invalid')
  })

  test('rejects identity spoofing (Eve signs as Alice)', async () => {
    const app = setupTest({ serverDid: origin.did })
    const eve = await makeIdentity()
    const eveKey = await makePrivateKeyBase64(eve.keyPair)
    const body = ''
    const userAuth = await createFederatedAuthHeader({
      did: user.did,
      privateKeyBase64: eveKey,
      action: 'test',
      federation: { spaceId: TEST_SPACE_ID, serverDid: origin.did, relayDid: relay.did },
      body,
    })
    const header = await buildFederationHeader({
      server: relay, action: 'test', body, ucanToken: validRelayUcan, userAuthorization: userAuth,
    })

    const res = await app.request('/test', { method: 'POST', headers: { Authorization: header }, body })
    expect(res.status).toBe(401)
    const json = await res.json() as any
    expect(json.error).toContain('user auth invalid')
  })

  test('rejects expired user auth', async () => {
    const app = setupTest({ serverDid: origin.did })
    const body = ''
    const userAuth = await createFederatedAuthHeader({
      did: user.did,
      privateKeyBase64: userPrivateKeyBase64,
      action: 'test',
      federation: { spaceId: TEST_SPACE_ID, serverDid: origin.did, relayDid: relay.did },
      body,
      expiresInMs: 1,
    })
    await new Promise(r => setTimeout(r, 10))
    const header = await buildFederationHeader({
      server: relay, action: 'test', body, ucanToken: validRelayUcan, userAuthorization: userAuth,
    })

    const res = await app.request('/test', { method: 'POST', headers: { Authorization: header }, body })
    expect(res.status).toBe(401)
    const json = await res.json() as any
    expect(json.error).toContain('user auth invalid')
  })

  test('rejects non-member user', async () => {
    const stranger = await makeIdentity()
    const strangerKey = await makePrivateKeyBase64(stranger.keyPair)
    const app = setupTest({ memberDids: [], serverDid: origin.did })
    const body = ''
    const userAuth = await createFederatedAuthHeader({
      did: stranger.did,
      privateKeyBase64: strangerKey,
      action: 'test',
      federation: { spaceId: TEST_SPACE_ID, serverDid: origin.did, relayDid: relay.did },
      body,
    })
    const header = await buildFederationHeader({
      server: relay, action: 'test', body, ucanToken: validRelayUcan, userAuthorization: userAuth,
    })

    const res = await app.request('/test', { method: 'POST', headers: { Authorization: header }, body })
    expect(res.status).toBe(403)
    const json = await res.json() as any
    expect(json.error).toContain('not a member')
  })

  test('accepts valid FEDERATION + user auth', async () => {
    const app = setupTest({ serverDid: origin.did })
    const body = '{"data":true}'
    const userAuth = await createFederatedAuthHeader({
      did: user.did,
      privateKeyBase64: userPrivateKeyBase64,
      action: 'sync-push',
      federation: { spaceId: TEST_SPACE_ID, serverDid: origin.did, relayDid: relay.did },
      body,
    })
    const header = await buildFederationHeader({
      server: relay, action: 'federation-proxy-post', body, ucanToken: validRelayUcan, userAuthorization: userAuth,
    })

    const res = await app.request('/test', {
      method: 'POST',
      headers: { Authorization: header, 'Content-Type': 'application/json' },
      body,
    })
    expect(res.status).toBe(200)
    const json = await res.json() as any
    expect(json.ok).toBe(true)
    expect(json.federation.userAuth).not.toBeNull()
    expect(json.federation.userAuth.did).toBe(user.did)
    expect(json.federation.userAuth.spaceId).toBe(TEST_SPACE_ID)
    expect(json.federation.userAuth.serverDid).toBe(origin.did)
    expect(json.federation.userAuth.relayDid).toBe(relay.did)
  })
})