import { describe, test, expect, mock, beforeAll } from 'bun:test'
import { buildDbMock, emptyChain } from './helpers/db-mock'
import { makeIdentity, createDidAuthHeader } from './integration/helpers'

const VALID_UUID = '11111111-1111-4111-8111-111111111111'

mock.module('../src/services/federationClient', () => ({
  getFederationLinkForSpace: () => null,
  federatedProxyAsync: async () => ({ status: 500, data: { error: 'should not be called' } }),
}))
mock.module('../src/utils/didIdentity', () => ({ didToSpkiPublicKey: () => '' }))

let mlsRouter: { request: (path: string, init?: any) => Response | Promise<Response> }
let caller: { did: string; keyPair: CryptoKeyPair }

describe('mlsRouter — pops array must match keyPackages length', () => {
  beforeAll(async () => {
    const id = await makeIdentity()
    caller = { did: id.did, keyPair: id.keyPair }

    // requireCapability's DID-Auth branch looks up the space owner; an empty
    // result means "caller is not the owner" (see src/middleware/ucanAuth.ts),
    // so a request with a *valid* body shape still gets rejected — just with
    // 403, not 400. That's exactly what we want: these tests only assert on
    // the Zod validation layer, not on the authorization outcome.
    mock.module('../src/db', () => buildDbMock({
      select: () => emptyChain(),
    }))
    mlsRouter = (await import('../src/routes/mls')).default
  })

  // authDispatcher (src/routes/mls.ts) runs globally before zValidator and
  // rejects any request without an Authorization header (401) before the
  // request ever reaches Zod. So these requests need a real signed DID-Auth
  // header — matching the bodyHash — to actually exercise the schema.
  async function signedRequest(bodyObj: unknown) {
    const body = JSON.stringify(bodyObj)
    const header = await createDidAuthHeader(caller.keyPair.privateKey, caller.did, 'mls-write', body)
    return mlsRouter.request(`/${VALID_UUID}/mls/key-packages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: header },
      body,
    })
  }

  test('POST /:spaceId/mls/key-packages rejects mismatched pops length', async () => {
    const res = await signedRequest({ keyPackages: ['a', 'b'], pops: ['x'] })
    expect(res.status).toBe(400)
  })

  test('POST /:spaceId/mls/key-packages accepts equal-length arrays (shape only — capability check rejects next with 403)', async () => {
    const res = await signedRequest({ keyPackages: ['a', 'b'], pops: ['x', 'y'] })
    // Zod validation passes (no 400); requireCapability rejects next — the
    // mocked space lookup returns no owner match, which is a deterministic
    // 403 (see src/middleware/ucanAuth.ts requireCapability).
    expect(res.status).toBe(403)
  })
})

// These tests exercise the full happy path (real DID-Auth header, requireCapability
// satisfied, handler body reached) with a custom db mock that captures what's passed
// to insert(...).values(...), so we can assert the `pop` column is genuinely the
// base64-decoded bytes of body.pops[i] — not just that the response is 2xx.
describe('mlsRouter — upload stores pop alongside keyPackage', () => {
  const INVITE_ID = '22222222-2222-4222-8222-222222222222'
  const TOKEN_ID = '33333333-3333-4333-8333-333333333333'

  let identityCaller: { did: string; keyPair: CryptoKeyPair }

  beforeAll(async () => {
    const id = await makeIdentity()
    identityCaller = { did: id.did, keyPair: id.keyPair }
  })

  test('POST /:spaceId/mls/key-packages inserts pop as base64-decoded bytes', async () => {
    let inserted: any[] = []
    let selectCallCount = 0

    mock.module('../src/db', () => buildDbMock({
      select: () => {
        selectCallCount++
        const isFirst = selectCallCount === 1
        const chain: any = {}
        chain.from = () => chain
        chain.where = () => chain
        chain.limit = () =>
          Promise.resolve(
            isFirst
              // requireCapability's DID-Auth branch: caller must be the space owner
              ? [{ ownerId: identityCaller.did }]
              // resolveDidIdentity
              : [{ did: identityCaller.did, publicKey: 'test-pubkey' }],
          )
        return chain
      },
      insert: () => ({
        values: (v: any[]) => { inserted = v; return Promise.resolve([]) },
      }),
    }))

    const { default: router } = await import('../src/routes/mls')

    const body = JSON.stringify({ keyPackages: ['a2V5'], pops: ['cG9w'] })
    const header = await createDidAuthHeader(identityCaller.keyPair.privateKey, identityCaller.did, 'mls-write', body)
    const res = await router.request(`/${VALID_UUID}/mls/key-packages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: header },
      body,
    })

    expect(res.status).toBe(201)
    expect(inserted.length).toBe(1)
    expect(inserted[0].pop).toEqual(Buffer.from('cG9w', 'base64'))
    expect(inserted[0].keyPackage).toEqual(Buffer.from('a2V5', 'base64'))
  })

  test('POST /:spaceId/invites/:inviteId/accept inserts pop as base64-decoded bytes', async () => {
    let inserted: any[] = []
    let selectCallCount = 0

    mock.module('../src/db', () => buildDbMock({
      select: () => {
        selectCallCount++
        const isFirst = selectCallCount === 1
        const chain: any = {}
        chain.from = () => chain
        chain.where = () => chain
        chain.limit = () =>
          Promise.resolve(
            isFirst
              // resolveDidIdentity
              ? [{ did: identityCaller.did, publicKey: 'test-pubkey' }]
              // pending invite lookup
              : [{ id: INVITE_ID, spaceId: VALID_UUID, inviteeDid: identityCaller.did, status: 'pending' }],
          )
        return chain
      },
      insert: () => emptyChain(),
      transaction: async (fn: (tx: any) => any) => {
        const tx = {
          update: () => emptyChain(),
          insert: () => ({
            values: (v: any[]) => { inserted = v; return Promise.resolve([]) },
          }),
        }
        return fn(tx)
      },
    }))

    const { default: router } = await import('../src/routes/mls')

    const body = JSON.stringify({ keyPackages: ['a2V5'], pops: ['cG9w'] })
    const header = await createDidAuthHeader(identityCaller.keyPair.privateKey, identityCaller.did, 'mls-write', body)
    const res = await router.request(`/${VALID_UUID}/invites/${INVITE_ID}/accept`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: header },
      body,
    })

    expect(res.status).toBe(200)
    expect(inserted.length).toBe(1)
    expect(inserted[0].pop).toEqual(Buffer.from('cG9w', 'base64'))
    expect(inserted[0].keyPackage).toEqual(Buffer.from('a2V5', 'base64'))
  })

  test('POST /:spaceId/invite-tokens/:tokenId/claim inserts pop as base64-decoded bytes', async () => {
    let inserted: any[] = []
    let selectCallCount = 0

    mock.module('../src/db', () => buildDbMock({
      select: () => {
        selectCallCount++
        const isFirst = selectCallCount === 1
        const chain: any = {}
        chain.from = () => chain
        chain.where = () => chain
        chain.limit = () =>
          Promise.resolve(
            isFirst
              // resolveDidIdentity — empty means "cross-server claim" branch
              ? []
              // invite token lookup
              : [{
                  id: TOKEN_ID,
                  spaceId: VALID_UUID,
                  createdByDid: 'did:key:zInviterPlaceholder',
                  expiresAt: new Date(Date.now() + 60_000),
                  usedCount: 0,
                  maxUses: 5,
                  capability: 'space/read',
                }],
          )
        return chain
      },
      insert: () => emptyChain(),
      transaction: async (fn: (tx: any) => any) => {
        const tx = {
          update: () => emptyChain(),
          insert: () => ({
            values: (v: any[]) => {
              // Three different inserts happen in this transaction (spaceInvites,
              // mlsKeyPackages, spaceMembers) — all tables resolve to the same mock
              // stub, so distinguish by shape: only the KeyPackage rows carry `keyPackage`.
              if (Array.isArray(v) && v[0] && 'keyPackage' in v[0]) inserted = v
              const p: any = Promise.resolve([])
              p.onConflictDoNothing = () => Promise.resolve([])
              return p
            },
          }),
        }
        return fn(tx)
      },
    }))

    const { default: router } = await import('../src/routes/mls')

    const body = JSON.stringify({ keyPackages: ['a2V5'], pops: ['cG9w'] })
    const header = await createDidAuthHeader(identityCaller.keyPair.privateKey, identityCaller.did, 'mls-write', body)
    const res = await router.request(`/${VALID_UUID}/invite-tokens/${TOKEN_ID}/claim`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: header },
      body,
    })

    expect(res.status).toBe(200)
    expect(inserted.length).toBe(1)
    expect(inserted[0].pop).toEqual(Buffer.from('cG9w', 'base64'))
    expect(inserted[0].keyPackage).toEqual(Buffer.from('a2V5', 'base64'))
  })
})
