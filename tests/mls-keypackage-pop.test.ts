import { describe, test, expect, mock, beforeAll } from 'bun:test'
import { isNotNull } from 'drizzle-orm'
import { buildDbMock, emptyChain, flattenSqlChunks } from './helpers/db-mock'
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
  // header — matching the request hash — to actually exercise the schema.
  async function signedRequest(bodyObj: unknown) {
    const body = JSON.stringify(bodyObj)
    const header = await createDidAuthHeader(caller.keyPair.privateKey, caller.did, {
      method: 'POST', path: `/${VALID_UUID}/mls/key-packages`, body,
    })
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
    const header = await createDidAuthHeader(identityCaller.keyPair.privateKey, identityCaller.did, {
      method: 'POST', path: `/${VALID_UUID}/mls/key-packages`, body,
    })
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
    const header = await createDidAuthHeader(identityCaller.keyPair.privateKey, identityCaller.did, {
      method: 'POST', path: `/${VALID_UUID}/invites/${INVITE_ID}/accept`, body,
    })
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
    const header = await createDidAuthHeader(identityCaller.keyPair.privateKey, identityCaller.did, {
      method: 'POST', path: `/${VALID_UUID}/invite-tokens/${TOKEN_ID}/claim`, body,
    })
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

// ============================================
// GET /:spaceId/mls/key-packages/:did — serves pop, skips legacy null-pop rows
// ============================================

// mlsKeyPackages.pop is normally a real drizzle Column; the shared tableStub
// proxy (see buildDbMock) collapses every column access to the same 'col'
// string, which would make it impossible to tell "the where-clause filters on
// pop" from "it filters on anything else." These tests substitute a unique
// marker string only for `pop` so we can walk the actual SQL condition tree
// built by isNotNull()/and() and confirm the fetch handler genuinely applies
// the filter — not just that it returns whatever row we hand it.
const POP_COLUMN_MARKER = 'POP_COLUMN_MARKER_FOR_WHERE_INTROSPECTION'

function whereFiltersNotNullOnPop(cond: any): boolean {
  const chunks = flattenSqlChunks(cond)
  for (let i = 0; i < chunks.length; i++) {
    if (chunks[i] === POP_COLUMN_MARKER) {
      const next = chunks[i + 1]
      if (next && Array.isArray(next.value) && String(next.value[0]).includes('is not null')) {
        return true
      }
    }
  }
  return false
}

// Pins the drizzle-orm internal shape that flattenSqlChunks()/
// whereFiltersNotNullOnPop() above depend on. If a future drizzle-orm bump
// changes how isNotNull() builds its queryChunks (e.g. wraps the param in a
// Param instance instead of embedding it raw, or reorders the chunks), this
// fails right here with a shape assertion — instead of surfacing as a
// confusing 500-vs-404 mismatch in the fetch-handler tests below.
test('drizzle isNotNull() produces the queryChunks shape our mock helper assumes (pins internal API surface)', () => {
  const marker = 'PINNING_TEST_MARKER_XYZ'
  const cond: any = isNotNull(marker as any)
  const chunks = flattenSqlChunks(cond)

  // isNotNull(x) is sql`${x} is not null`, which drizzle-orm compiles to
  // exactly three queryChunks: a leading empty StringChunk, the raw param
  // embedded as-is (drizzle does NOT wrap primitive sql`` params in a Param
  // instance — see node_modules/drizzle-orm/sql/sql.js `function sql`), and
  // a trailing StringChunk(" is not null").
  expect(chunks.length).toBe(3)
  expect(chunks[0].value).toEqual([''])
  expect(chunks[1]).toBe(marker)
  expect(chunks[2].value[0]).toContain('is not null')
})

describe('mlsRouter — fetch key package returns pop and skips legacy rows', () => {
  const TARGET_DID = 'did:key:zTargetDidForFetchPopTest0000000000000001'
  let owner: { did: string; keyPair: CryptoKeyPair }

  beforeAll(async () => {
    const id = await makeIdentity()
    owner = { did: id.did, keyPair: id.keyPair }
  })

  // Sets up the full happy-path chain: requireCapability (owner match) ->
  // accepted-invite lookup -> target identity lookup -> key package lookup.
  // `row` is what the (mocked) key-package query resolves to when the where
  // clause does NOT filter out a null pop; when the where clause DOES include
  // isNotNull(pop) and `row.pop` is null, the mock reports zero rows instead —
  // mirroring what a real Postgres filter would do to a legacy row.
  function mockHappyPathWithKeyPackageRow(row: { id: number; keyPackage: Buffer; pop: Buffer | null } | null) {
    let selectCallCount = 0

    const dbExports = buildDbMock({
      select: () => {
        selectCallCount++
        const callIndex = selectCallCount
        const chain: any = {}
        let whereArg: any = null
        chain.from = () => chain
        chain.where = (cond: any) => { whereArg = cond; return chain }
        chain.limit = () => {
          if (callIndex === 1) return Promise.resolve([{ ownerId: owner.did }]) // requireCapability
          if (callIndex === 2) return Promise.resolve([{ spaceId: VALID_UUID, inviteeDid: TARGET_DID, status: 'accepted', includeHistory: true }]) // accepted invite
          if (callIndex === 3) return Promise.resolve([{ did: TARGET_DID, publicKey: 'target-pubkey' }]) // target identity
          // key package lookup
          if (!row) return Promise.resolve([])
          if (row.pop === null && whereFiltersNotNullOnPop(whereArg)) return Promise.resolve([])
          return Promise.resolve([row])
        }
        return chain
      },
      update: () => ({
        set: () => ({
          where: () => Promise.resolve([]),
        }),
      }),
    })
    dbExports.mlsKeyPackages = {
      pop: POP_COLUMN_MARKER,
      spaceId: 'MOCK_SPACE_ID_COL',
      identityPublicKey: 'MOCK_IDENTITY_PK_COL',
      consumed: 'MOCK_CONSUMED_COL',
      id: 'MOCK_ID_COL',
    }
    mock.module('../src/db', () => dbExports)
  }

  test('GET returns pop as base64 for a row that has one', async () => {
    const popBytes = Buffer.from([1, 2, 3, 4, 5])
    const keyPackageBytes = Buffer.from([9, 9, 9])
    mockHappyPathWithKeyPackageRow({ id: 42, keyPackage: keyPackageBytes, pop: popBytes })

    const { default: router } = await import('../src/routes/mls')
    const header = await createDidAuthHeader(owner.keyPair.privateKey, owner.did, {
      path: `/${VALID_UUID}/mls/key-packages/${encodeURIComponent(TARGET_DID)}`,
    })
    const res = await router.request(`/${VALID_UUID}/mls/key-packages/${encodeURIComponent(TARGET_DID)}`, {
      method: 'GET',
      headers: { Authorization: header },
    })

    expect(res.status).toBe(200)
    const body = await res.json() as any
    expect(body.pop).toBe(popBytes.toString('base64'))
    expect(body.keyPackage).toBe(keyPackageBytes.toString('base64'))
  })

  test('GET treats a legacy row with pop = NULL as unavailable (404, not served without PoP)', async () => {
    mockHappyPathWithKeyPackageRow({ id: 43, keyPackage: Buffer.from([1]), pop: null })

    const { default: router } = await import('../src/routes/mls')
    const header = await createDidAuthHeader(owner.keyPair.privateKey, owner.did, {
      path: `/${VALID_UUID}/mls/key-packages/${encodeURIComponent(TARGET_DID)}`,
    })
    const res = await router.request(`/${VALID_UUID}/mls/key-packages/${encodeURIComponent(TARGET_DID)}`, {
      method: 'GET',
      headers: { Authorization: header },
    })

    expect(res.status).toBe(404)
    const body = await res.json() as any
    expect(body.error).toContain('No key packages available')
  })
})
