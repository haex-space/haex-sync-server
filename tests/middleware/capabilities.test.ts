import { describe, test, expect, mock } from 'bun:test'
import type { Context } from 'hono'
import {
  createUcan,
  createWebCryptoVerifier,
  spaceCapabilitySet,
  spaceResource,
  verifyUcan,
  type SpaceCapabilitySet,
} from '@haex-space/ucan'

// Mock DB before importing the middleware — resolveCallerAuthority reads
// space_members (UCAN root issuer) and spaces (DID-auth owner). The two
// queries are told apart by the table handed to .from().
const SPACES = { id: 'id', ownerId: 'owner_id' }
const SPACE_MEMBERS = { did: 'did', spaceId: 'space_id', capability: 'capability' }

let memberRows: { did: string }[] = []
let spaceRows: { ownerId: string }[] = []

mock.module('../../src/db', () => ({
  db: {
    select: () => ({
      from: (table: unknown) => ({
        where: () => ({
          limit: () => Promise.resolve(table === SPACE_MEMBERS ? memberRows : spaceRows),
        }),
      }),
    }),
  },
  spaces: SPACES,
  spaceMembers: SPACE_MEMBERS,
}))

import { ownerCapabilitySet, resolveCallerAuthority } from '../../src/middleware/capabilities'
import { makeIdentity, type Identity } from '../integration/helpers'

// ============================================
// Test Helpers
// ============================================

const verify = createWebCryptoVerifier()

/** Minimal Context stand-in — resolveCallerAuthority only ever calls c.get(). */
function contextWith(values: Record<string, unknown>): Context {
  return { get: (key: string) => values[key] ?? null } as unknown as Context
}

/**
 * A genuinely signed and verified UCAN, so findRootIssuer walks a real proof
 * chain rather than a hand-shaped object.
 */
async function ucanContextFor(
  issuer: Identity,
  spaceId: string,
  capabilities: SpaceCapabilitySet,
) {
  const token = await createUcan(
    {
      issuer: issuer.did,
      audience: issuer.did,
      capabilities: { [spaceResource(spaceId)]: capabilities },
      expiration: Math.floor(Date.now() / 1000) + 3600,
      proofs: [],
    },
    issuer.sign,
  )
  const verified = await verifyUcan(token, verify)
  return {
    issuerDid: verified.payload.iss,
    publicKey: verified.payload.iss,
    capabilities: verified.payload.cap,
    verifiedUcan: verified,
  }
}

// ============================================
// resolveCallerAuthority — UCAN root issuer membership
// ============================================

// This is the guard that stops anyone self-signing arbitrary capabilities:
// a valid signature proves only who issued the token, never that they have
// any standing in the space. Both directions are asserted so that removing
// the guard fails the first test and over-tightening it fails the second.

describe('resolveCallerAuthority — UCAN membership guard', () => {
  test('rejects a UCAN whose chain root issuer is not a member of the space', async () => {
    memberRows = []
    const outsider = await makeIdentity()
    const spaceId = crypto.randomUUID()
    const ucan = await ucanContextFor(outsider, spaceId, spaceCapabilitySet().admin(true).build())

    const authority = await resolveCallerAuthority(contextWith({ ucan }), spaceId)

    expect(authority).toEqual({
      ok: false,
      status: 403,
      error: 'Forbidden - UCAN root issuer is not a member of this space',
    })
  })

  test('accepts a UCAN whose chain root issuer is a member of the space', async () => {
    const member = await makeIdentity()
    memberRows = [{ did: member.did }]
    const spaceId = crypto.randomUUID()
    const granted = spaceCapabilitySet().read(true).write(true).build()
    const ucan = await ucanContextFor(member, spaceId, granted)

    const authority = await resolveCallerAuthority(contextWith({ ucan }), spaceId)

    expect(authority).toEqual({ ok: true, capabilities: granted })
  })
})

// ============================================
// resolveCallerAuthority — DID-auth ownership
// ============================================

describe('resolveCallerAuthority — DID-auth ownership guard', () => {
  test('rejects a DID-auth caller who is not the space owner', async () => {
    const caller = await makeIdentity()
    const owner = await makeIdentity()
    spaceRows = [{ ownerId: owner.did }]
    const spaceId = crypto.randomUUID()

    const authority = await resolveCallerAuthority(
      contextWith({ didAuth: { did: caller.did } }),
      spaceId,
    )

    expect(authority).toEqual({
      ok: false,
      status: 403,
      error: 'Forbidden - Non-owners must provide a UCAN',
    })
  })

  test('accepts a DID-auth caller who owns the space, as root authority', async () => {
    const owner = await makeIdentity()
    spaceRows = [{ ownerId: owner.did }]
    const spaceId = crypto.randomUUID()

    const authority = await resolveCallerAuthority(
      contextWith({ didAuth: { did: owner.did } }),
      spaceId,
    )

    expect(authority).toEqual({ ok: true, capabilities: ownerCapabilitySet() })
  })
})
