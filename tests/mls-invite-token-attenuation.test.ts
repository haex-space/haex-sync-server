/**
 * POST /:spaceId/invite-tokens must not let a caller mint a token granting
 * more than the caller may delegate.
 *
 * Before this gate, createTokenSchema accepted any of space/admin|write|read
 * while the route was authorized only on `invite`, and the requested value was
 * written verbatim to space_invite_tokens.capability. Claiming a token has no
 * capability check of its own — the token UUID *is* the authorization — so an
 * invite-only member could mint an admin-granting token, claim it, and land an
 * `space/admin` row in space_members.
 *
 * These tests drive the real router with real signed auth, and assert on the
 * row actually handed to insert(), not just the status code.
 */
import { describe, test, expect, mock, beforeAll } from 'bun:test'
import { createUcan, spaceCapabilitySet, spaceResource } from '@haex-space/ucan'
import { buildDbMock } from './helpers/db-mock'
import {
  makeIdentity,
  createDidAuthHeader,
  ucanRequestHeaders,
  type Identity,
} from './integration/helpers'

const SPACE_ID = '44444444-4444-4444-8444-444444444444'
const TOKEN_ID = '55555555-5555-4555-8555-555555555555'

mock.module('../src/services/federationClient', () => ({
  getFederationLinkForSpace: () => null,
  federatedProxyAsync: async () => ({ status: 500, data: { error: 'should not be called' } }),
}))
mock.module('../src/utils/didIdentity', () => ({ didToSpkiPublicKey: () => '' }))

// D2 presets, spelled out here rather than imported so a regression in
// presetForLegacyTier cannot quietly redefine what these tests mean.
const INVITER_SET = spaceCapabilitySet().read(true).invite(true).build()

let mlsRouter: { request: (path: string, init?: any) => Response | Promise<Response> }
let owner: Identity
let inviter: Identity

/** Row captured from db.insert(spaceInviteTokens).values(...). */
let insertedToken: any = null
let ownerRow: { ownerId: string } | undefined

beforeAll(async () => {
  owner = await makeIdentity()
  inviter = await makeIdentity()
  ownerRow = { ownerId: owner.did }

  mock.module('../src/db', () => buildDbMock({
    select: () => {
      const chain: any = {}
      chain.from = () => chain
      chain.where = () => chain
      chain.limit = () => Promise.resolve(ownerRow ? [ownerRow] : [])
      return chain
    },
    insert: () => {
      const chain: any = {}
      chain.values = (values: any) => {
        insertedToken = values
        return chain
      }
      chain.returning = () => Promise.resolve([{
        id: TOKEN_ID,
        capability: insertedToken.capability,
        maxUses: insertedToken.maxUses,
        expiresAt: insertedToken.expiresAt,
        label: insertedToken.label ?? null,
      }])
      return chain
    },
  }))

  mlsRouter = (await import('../src/routes/mls')).default
})

/**
 * An inviter's UCAN delegated from the space owner.
 *
 * A self-signed inviter token would be rejected by the owner-root check before
 * attenuation is ever reached, so the proof chain matters: owner → inviter.
 */
async function inviterHeader(): Promise<string> {
  const expiration = Math.floor(Date.now() / 1000) + 3600
  const delegation = await createUcan(
    {
      issuer: owner.did,
      audience: inviter.did,
      capabilities: { [spaceResource(SPACE_ID)]: INVITER_SET },
      expiration,
      proofs: [],
    },
    owner.sign,
  )
  const token = await createUcan(
    {
      issuer: inviter.did,
      audience: inviter.did,
      capabilities: { [spaceResource(SPACE_ID)]: INVITER_SET },
      expiration,
      proofs: [delegation],
    },
    inviter.sign,
  )
  return `UCAN ${token}`
}

function tokenBody(capability: string) {
  return JSON.stringify({ capability, expiresInSeconds: 3600, maxUses: 1 })
}

async function createToken(header: string, capability: string, holder?: Identity) {
  insertedToken = null
  const path = `/${SPACE_ID}/invite-tokens`
  const body = tokenBody(capability)
  const authHeaders: Record<string, string> = holder
    ? await ucanRequestHeaders(holder, header, { method: 'POST', path, body })
    : { Authorization: header }
  const res = await mlsRouter.request(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders },
    body,
  })
  return res
}

/** DID-Auth header for the space owner, who is the root authority. */
async function ownerHeader(capability: string) {
  return createDidAuthHeader(owner.keyPair.privateKey, owner.did, 'mls-write', tokenBody(capability))
}

// ============================================
// Attenuation at the invite-token boundary
// ============================================

describe('POST /:spaceId/invite-tokens — grant attenuation', () => {
  test('rejects an invite-only caller minting an admin-granting token', async () => {
    const res = await createToken(await inviterHeader(), 'space/admin', inviter)

    expect(res.status).toBe(403)
    const json = (await res.json()) as any
    expect(json.error).toContain('exceeds caller authority')
    // Names the offending cap so an operator can see why
    expect(json.error).toContain('write')
    expect(insertedToken).toBeNull()
  })

  test('rejects an invite-only caller minting a write-granting token', async () => {
    const res = await createToken(await inviterHeader(), 'space/write', inviter)

    expect(res.status).toBe(403)
    const json = (await res.json()) as any
    expect(json.error).toContain('exceeds caller authority')
    expect(insertedToken).toBeNull()
  })

  // The point of the inviter preset holding read(delegatable:true): an inviter
  // must still be able to invite readers, or the invite cap does nothing.
  test('allows an invite-only caller to mint a read-granting token', async () => {
    const res = await createToken(await inviterHeader(), 'space/read', inviter)

    expect(res.status).toBe(201)
    expect(insertedToken).not.toBeNull()
    expect(insertedToken.capability).toBe('space/read')
    expect(insertedToken.spaceId).toBe(SPACE_ID)
    expect(insertedToken.createdByDid).toBe(inviter.did)
  })

  test('allows the space owner to mint an admin-granting token', async () => {
    const res = await createToken(await ownerHeader('space/admin'), 'space/admin')

    expect(res.status).toBe(201)
    expect(insertedToken).not.toBeNull()
    expect(insertedToken.capability).toBe('space/admin')
    expect(insertedToken.createdByDid).toBe(owner.did)
  })

  // Phase 1a interaction: attenuation is not the first gate. A self-signed
  // inviter token never reaches it, however well-formed the request is.
  test('rejects a self-signed inviter token before attenuation is reached', async () => {
    const expiration = Math.floor(Date.now() / 1000) + 3600
    const selfSigned = await createUcan(
      {
        issuer: inviter.did,
        audience: inviter.did,
        capabilities: { [spaceResource(SPACE_ID)]: INVITER_SET },
        expiration,
        proofs: [],
      },
      inviter.sign,
    )

    const res = await createToken(`UCAN ${selfSigned}`, 'space/read', inviter)

    expect(res.status).toBe(403)
    const json = (await res.json()) as any
    expect(json.error).toContain('must root in the space owner')
    expect(insertedToken).toBeNull()
  })

  // presetForLegacyTier throws on unknown input; the zod enum must make that
  // unreachable, so an unknown tier is a 400 from validation, never a 500.
  test('rejects an unknown capability tier at validation, not with a 500', async () => {
    const res = await createToken(await inviterHeader(), 'space/superuser', inviter)

    expect(res.status).toBe(400)
    expect(insertedToken).toBeNull()
  })
})
