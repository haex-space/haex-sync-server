/**
 * DELETE /:spaceId/invite-tokens/:tokenId must not let a non-creator inviter
 * revoke someone else's token. Before this gate, the route was authorized
 * only on `invite`, so any invite-cap holder could delete every token in
 * the space — an authority stronger than the mint side implies. The space
 * owner keeps the ability to revoke anything.
 *
 * The mint side is pinned by mls-invite-token-attenuation.test.ts; this
 * file pins the revoke side.
 */
import { describe, test, expect, mock, beforeAll, beforeEach } from 'bun:test'
import { createUcan, spaceCapabilitySet, spaceResource } from '@haex-space/ucan'
import { buildDbMock, emptyChain } from './helpers/db-mock'
import { makeIdentity, createDidAuthHeader, type Identity } from './integration/helpers'

const SPACE_ID = '77777777-7777-4777-8777-777777777777'
const TOKEN_ID = '88888888-8888-4888-8888-888888888888'

mock.module('../src/services/federationClient', () => ({
  getFederationLinkForSpace: () => null,
  federatedProxyAsync: async () => ({ status: 500, data: { error: 'should not be called' } }),
}))
mock.module('../src/utils/didIdentity', () => ({ didToSpkiPublicKey: () => '' }))

const INVITER_SET = spaceCapabilitySet().read(true).invite(true).build()

let mlsRouter: { request: (path: string, init?: any) => Response | Promise<Response> }
let owner: Identity
let creator: Identity
let inviter: Identity

// Fixtures the tests flip between cases. tokenRow=undefined models a token
// that has already been deleted or never existed.
let tokenRow: { createdByDid: string } | undefined
let deleteCalled = false

beforeAll(async () => {
  owner = await makeIdentity()
  creator = await makeIdentity()
  inviter = await makeIdentity()

  mock.module('../src/db', () => buildDbMock({
    select: (columns?: Record<string, any>) => {
      const wants = columns ? Object.keys(columns).sort().join(',') : '*'
      const chain: any = {}
      chain.from = () => chain
      chain.where = () => chain
      if (wants === 'createdByDid') {
        chain.limit = () => Promise.resolve(tokenRow ? [tokenRow] : [])
      } else {
        // ownerId lookups (the middleware's root-of-trust check and the
        // handler's non-creator branch) both accept a row with `ownerId`.
        // Any unprojected select in the middleware chain lands here too.
        chain.limit = () => Promise.resolve([{ ownerId: owner.did }])
      }
      return chain
    },
    insert: () => emptyChain(),
    update: () => emptyChain(),
    delete: () => {
      const chain: any = {}
      chain.where = () => chain
      chain.returning = () => {
        deleteCalled = true
        return Promise.resolve(tokenRow ? [{ id: TOKEN_ID }] : [])
      }
      return chain
    },
  }))

  mlsRouter = (await import('../src/routes/mls')).default
})

beforeEach(() => {
  tokenRow = { createdByDid: creator.did }
  deleteCalled = false
})

async function ownerHeader(): Promise<string> {
  return createDidAuthHeader(owner.keyPair.privateKey, owner.did, 'mls-write', '')
}

/**
 * A member's UCAN delegated from the space owner. The proof chain matters:
 * a self-signed inviter token would be rejected by the owner-root check
 * before this handler is reached.
 */
async function inviterUcanHeader(who: Identity): Promise<string> {
  const expiration = Math.floor(Date.now() / 1000) + 3600
  const delegation = await createUcan(
    {
      issuer: owner.did,
      audience: who.did,
      capabilities: { [spaceResource(SPACE_ID)]: INVITER_SET },
      expiration,
      proofs: [],
    },
    owner.sign,
  )
  const token = await createUcan(
    {
      issuer: who.did,
      audience: who.did,
      capabilities: { [spaceResource(SPACE_ID)]: INVITER_SET },
      expiration,
      proofs: [delegation],
    },
    who.sign,
  )
  return `UCAN ${token}`
}

async function revoke(header: string): Promise<Response> {
  return mlsRouter.request(`/${SPACE_ID}/invite-tokens/${TOKEN_ID}`, {
    method: 'DELETE',
    headers: { Authorization: header },
  }) as Promise<Response>
}

describe('DELETE /:spaceId/invite-tokens/:tokenId — per-creator scope', () => {
  test('rejects an invite-cap holder who did not mint the token', async () => {
    const res = await revoke(await inviterUcanHeader(inviter))

    expect(res.status).toBe(403)
    const json = (await res.json()) as any
    // Fragment shared with haex-e2e-tests PR #88's positive-control assertion;
    // if this wording changes, the e2e-side assertion must move with it.
    expect(json.error).toContain('creator')
    expect(json.error).toContain('owner')
    // Auth failure must NOT be routed through the delete path.
    expect(deleteCalled).toBe(false)
  })

  test('allows the creator to revoke their own token', async () => {
    const res = await revoke(await inviterUcanHeader(creator))

    expect(res.status).toBe(200)
    const json = (await res.json()) as any
    expect(json.success).toBe(true)
    expect(deleteCalled).toBe(true)
  })

  test('allows the space owner to revoke a token they did not mint', async () => {
    // tokenRow.createdByDid is creator.did, not owner.did — the owner branch
    // is what carries the request through, not a coincidental id match.
    const res = await revoke(await ownerHeader())

    expect(res.status).toBe(200)
    expect(deleteCalled).toBe(true)
  })

  test('returns 404 for a non-existent token without exposing whether the caller would have been authorized', async () => {
    tokenRow = undefined
    const res = await revoke(await ownerHeader())

    expect(res.status).toBe(404)
    // The auth branch never got to touch delete: we responded from the
    // initial existence check.
    expect(deleteCalled).toBe(false)
  })
})
