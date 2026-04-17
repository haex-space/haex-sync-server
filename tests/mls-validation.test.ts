/**
 * Tests for the MLS router's UUID-guard middleware (3.2) and the
 * replacement of bare parseInt with Zod validation on GET /mls/messages (3.3).
 *
 * We exercise the REAL mlsRouter end-to-end:
 *   - No middleware is mocked — the real authDispatcher / didAuthMiddleware
 *     runs against DID-Auth headers constructed with production crypto.
 *   - Only the database and narrow service functions are stubbed, since a
 *     real Postgres instance isn't available in-process.
 *
 * This catches behaviour the duplication-heavy "re-implement the middleware"
 * approach would miss (e.g. middleware ordering, param resolution, …).
 */

import { describe, test, expect, mock, beforeAll } from 'bun:test'
import { isValidUuid } from '../src/utils/uuid'
import { buildDbMock, emptyChain } from './helpers/db-mock'
import { makeIdentity, createDidAuthHeader } from './integration/helpers'

const VALID_UUID = '11111111-1111-4111-8111-111111111111'

// The federation link cache is a process-global map; stub empty so the
// relay branch is never taken during non-federation tests.
mock.module('../src/services/federationClient', () => ({
  getFederationLinkForSpace: () => null,
  federatedProxyAsync: async () => ({ status: 500, data: { error: 'should not be called' } }),
}))

// didToSpkiPublicKey is used by a couple of handlers (token claim, etc.);
// none of our happy-path tests hit those handlers but we stub to be safe.
mock.module('../src/utils/didIdentity', () => ({ didToSpkiPublicKey: () => '' }))

// The handler chain has two distinct db.select() calls:
//   1. requireCapability → select(spaces.ownerId).from(spaces).where(...).limit(1)
//   2. list messages     → select(mlsMessages).from(...).where(...).orderBy(...).limit(N)
// The first needs to return the caller's did so authorization passes; the
// second can be empty. We differentiate by whether `.orderBy()` was called.
let callerDidForDb = 'did:key:placeholder'
mock.module('../src/db', () => buildDbMock({
  select: () => {
    const chain: any = {}
    let ordered = false
    chain.from = () => chain
    chain.where = () => chain
    chain.orderBy = () => { ordered = true; return chain }
    chain.limit = () => ordered
      ? Promise.resolve([]) // messages query — return zero rows
      : Promise.resolve([{ ownerId: callerDidForDb }]) // owner lookup
    return chain
  },
}))

let mlsRouter: { request: (path: string, init?: any) => Response | Promise<Response> }
let caller: { did: string; keyPair: CryptoKeyPair }

beforeAll(async () => {
  const id = await makeIdentity()
  caller = { did: id.did, keyPair: id.keyPair }
  callerDidForDb = id.did
  mlsRouter = (await import('../src/routes/mls')).default
})

// ── UUID guard (3.2) — no auth, guard runs first ────────────────────────

describe('mlsRouter — UUID guard rejects malformed path params', () => {
  const cases = [
    { name: 'non-UUID spaceId on GET invites', method: 'GET', path: '/not-a-uuid/invites', param: 'spaceId' },
    { name: 'non-UUID spaceId on POST accept', method: 'POST', path: '/bad/invites/bad/accept', param: 'spaceId' },
    { name: 'valid spaceId + non-UUID inviteId on decline', method: 'POST', path: `/${VALID_UUID}/invites/xxx/decline`, param: 'inviteId' },
    { name: 'non-UUID tokenId on delete', method: 'DELETE', path: `/${VALID_UUID}/invite-tokens/bad`, param: 'tokenId' },
    { name: 'non-UUID welcome id on delete', method: 'DELETE', path: `/${VALID_UUID}/mls/welcome/bad`, param: 'id' },
  ] as const

  for (const tc of cases) {
    test(tc.name, async () => {
      const res = await mlsRouter.request(tc.path, {
        method: tc.method,
        body: tc.method === 'POST' ? '{}' : undefined,
        headers: { 'Content-Type': 'application/json' },
      })
      expect(res.status).toBe(400)
      const body = await res.json() as any
      expect(body.error).toContain(tc.param)
    })
  }

  const attackPayloads = [
    { name: 'SQL injection', payload: "'; DROP TABLE spaces; --" },
    { name: 'null byte', payload: 'abc\x00def' },
    { name: 'path traversal', payload: '..%2F..%2Fetc%2Fpasswd' },
    { name: 'CRLF injection', payload: 'abc\r\nSet-Cookie: evil=1' },
    { name: 'unicode homoglyph', payload: 'іd' }, // Cyrillic 'і'
    { name: 'excessively long string', payload: 'a'.repeat(4096) },
  ]

  for (const attack of attackPayloads) {
    test(`attack: rejects ${attack.name} as spaceId`, async () => {
      const res = await mlsRouter.request(
        `/${encodeURIComponent(attack.payload)}/invites`,
        { method: 'GET' },
      )
      expect(res.status).toBe(400)
    })
  }

  test('isValidUuid helper: accepts valid, rejects malformed', () => {
    expect(isValidUuid(VALID_UUID)).toBe(true)
    expect(isValidUuid('not-a-uuid')).toBe(false)
  })
})

// ── parseInt → Zod on GET /mls/messages (3.3) ───────────────────────────
// These tests drive real auth + real middleware chain. Invalid query params
// must return 400 from zValidator, not bubble into a SQL-level crash.

describe('mlsRouter — GET /:spaceId/mls/messages query validation', () => {
  async function signedRequest(query: string) {
    const header = await createDidAuthHeader(caller.keyPair.privateKey, caller.did, 'mls-read', '')
    return mlsRouter.request(`/${VALID_UUID}/mls/messages${query}`, {
      method: 'GET',
      headers: { Authorization: header },
    })
  }

  test('rejects non-numeric after', async () => {
    const res = await signedRequest('?after=abc&limit=10')
    expect(res.status).toBe(400)
    const body = await res.json() as any
    expect(body.error).toContain('Invalid query')
  })

  test('rejects negative after', async () => {
    const res = await signedRequest('?after=-1&limit=10')
    expect(res.status).toBe(400)
  })

  test('rejects limit above 1000 cap', async () => {
    const res = await signedRequest('?after=0&limit=100000')
    expect(res.status).toBe(400)
  })

  test('rejects zero limit', async () => {
    const res = await signedRequest('?after=0&limit=0')
    expect(res.status).toBe(400)
  })

  test('rejects float limit', async () => {
    const res = await signedRequest('?after=0&limit=10.5')
    expect(res.status).toBe(400)
  })

  test('accepts missing params — defaults applied', async () => {
    const res = await signedRequest('')
    expect(res.status).toBe(200)
    const body = await res.json() as any
    expect(Array.isArray(body.messages)).toBe(true)
  })

  test('accepts valid bounds', async () => {
    const res = await signedRequest('?after=5&limit=50')
    expect(res.status).toBe(200)
  })

  test('attack: emoji-as-number would previously have produced NaN → SQL crash; now returns 400', async () => {
    const res = await signedRequest(`?after=${encodeURIComponent('🐉')}&limit=10`)
    expect(res.status).toBe(400)
  })
})
