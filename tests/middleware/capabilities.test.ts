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
// spaces.ownerId to establish the root of trust for both auth modes.
//
// Query scoping is pinned by watching which COLUMN the query touches, not by
// introspecting the SQL condition. tests/storageCredentials.race.test.ts
// replaces drizzle-orm's `eq` process-globally with a stub that discards its
// column argument, so a condition captured at `.where()` genuinely cannot
// distinguish spaces.id from spaces.ownerId once that mock is live. Observing
// the property access happens before `eq` ever sees the value, so it holds
// regardless of which `eq` won.
let columnReads: string[] = []
let spaceRows: { ownerId: string | null }[] = []
let lastWhere: unknown = null

function watchedTable(table: string) {
  return new Proxy({} as Record<string, string>, {
    get: (_target, property) => {
      if (typeof property !== 'string') return undefined
      const column = `${table}.${property}`
      columnReads.push(column)
      return column
    },
  })
}

mock.module('../../src/db', () => ({
  db: {
    select: () => ({
      from: () => ({
        where: (condition: unknown) => {
          lastWhere = condition
          return { limit: () => Promise.resolve(spaceRows) }
        },
      }),
    }),
  },
  spaces: watchedTable('spaces'),
  spaceMembers: watchedTable('space_members'),
}))

import { ownerCapabilitySet, resolveCallerAuthority } from '../../src/middleware/capabilities'
import { makeIdentity, type Identity } from '../integration/helpers'

// ============================================
// Test Helpers
// ============================================

const verify = createWebCryptoVerifier()

const ADMIN_CAP = spaceCapabilitySet().admin(true).build()
const WRITER_DELEGATABLE = spaceCapabilitySet().read(true).write(true).build()
const WRITER_FINAL = spaceCapabilitySet().read(false).write(false).build()
const ADMIN_PRESET = spaceCapabilitySet().read(true).write(true).invite(true).admin(false).build()

/** Minimal Context stand-in — resolveCallerAuthority only ever calls c.get(). */
function contextWith(values: Record<string, unknown>): Context {
  return { get: (key: string) => values[key] ?? null } as unknown as Context
}

async function signUcan(
  issuer: Identity,
  audience: string,
  spaceId: string,
  capabilities: SpaceCapabilitySet,
  proofs: string[] = [],
): Promise<string> {
  return createUcan(
    {
      issuer: issuer.did,
      audience,
      capabilities: { [spaceResource(spaceId)]: capabilities },
      expiration: Math.floor(Date.now() / 1000) + 3600,
      proofs,
    },
    issuer.sign,
  )
}

/**
 * A genuinely signed and verified UCAN, so the resolver walks a real proof
 * forest rather than a hand-shaped object.
 */
async function ucanContextFor(token: string) {
  const verified = await verifyUcan(token, verify)
  return {
    issuerDid: verified.payload.iss,
    publicKey: verified.payload.iss,
    capabilities: verified.payload.cap,
    verifiedUcan: verified,
  }
}

/**
 * True when `value` appears anywhere inside a captured condition, whatever
 * shape the live `eq` gave it. Deliberately structure-agnostic: it pins that
 * the predicate carries this space id without depending on drizzle internals.
 */
function conditionMentions(node: unknown, value: string, depth = 0): boolean {
  if (depth > 20) return false
  if (node === value) return true
  if (Array.isArray(node)) return node.some((n) => conditionMentions(n, value, depth + 1))
  if (node && typeof node === 'object') {
    return Object.values(node).some((v) => conditionMentions(v, value, depth + 1))
  }
  return false
}

const OWNER_ROOT_ERROR = {
  ok: false,
  status: 403,
  error: 'Forbidden - UCAN chain must root in the space owner',
} as const

// ============================================
// resolveCallerAuthority — proof-forest root of trust
// ============================================

// Two bypasses in @haex-space/ucan@0.2.0 make "the root issuer is a member"
// insufficient, both verified against the real verifyUcan:
//
//   1. verifyUcan skips the delegation-chain check entirely when prf is empty
//      (dist/index.mjs:296), so a self-signed root asserts any capability.
//   2. findRootIssuer follows proofs[0] only (dist/index.mjs:396-401), while
//      verifyDelegationChain is satisfied by ANY proof whose aud matches the
//      issuer. The proof that authorizes and the proof that determines the
//      root need not be the same proof.
//
// The rule that closes both: every root in the forest must be the space owner.

describe('resolveCallerAuthority — proof-forest root of trust', () => {
  test('rejects a member self-signing a root that claims admin', async () => {
    // This identity is a genuine space member recorded as space/read. That no
    // longer buys any root authority — which is precisely the point.
    const owner = await makeIdentity()
    const member = await makeIdentity()
    spaceRows = [{ ownerId: owner.did }]
    const spaceId = crypto.randomUUID()

    const token = await signUcan(member, member.did, spaceId, ADMIN_CAP)
    const authority = await resolveCallerAuthority(
      contextWith({ ucan: await ucanContextFor(token) }),
      spaceId,
    )

    expect(authority).toEqual(OWNER_ROOT_ERROR)
  })

  test('rejects a self-signed root laundered behind a member-signed proof in slot 0', async () => {
    const owner = await makeIdentity()
    const member = await makeIdentity()
    const attacker = await makeIdentity()
    const bystander = await makeIdentity()
    spaceRows = [{ ownerId: owner.did }]
    const spaceId = crypto.randomUUID()

    // Slot 0: a real member-signed UCAN, audienced to an unrelated third
    // party and not even mentioning the target space. Only there to be what
    // findRootIssuer walks into.
    const borrowed = await signUcan(member, bystander.did, crypto.randomUUID(), ADMIN_CAP)
    // Slot 1: the attacker's own self-signed root, which is what actually
    // satisfies verifyDelegationChain.
    const selfRoot = await signUcan(attacker, attacker.did, spaceId, ADMIN_CAP)
    const outer = await signUcan(attacker, attacker.did, spaceId, ADMIN_CAP, [borrowed, selfRoot])

    const authority = await resolveCallerAuthority(
      contextWith({ ucan: await ucanContextFor(outer) }),
      spaceId,
    )

    expect(authority).toEqual(OWNER_ROOT_ERROR)
  })

  test('rejects a self-signed root laundered behind an OWNER-signed proof in slot 0', async () => {
    // The realistic variant: every invitee legitimately holds an owner-signed
    // UCAN to park in slot 0. findRootIssuer then reports the owner, so a
    // check of only slot 0's root would accept this. Walking every root is
    // what rejects it.
    const owner = await makeIdentity()
    const attacker = await makeIdentity()
    const bystander = await makeIdentity()
    spaceRows = [{ ownerId: owner.did }]
    const spaceId = crypto.randomUUID()

    const borrowed = await signUcan(owner, bystander.did, crypto.randomUUID(), ADMIN_CAP)
    const selfRoot = await signUcan(attacker, attacker.did, spaceId, ADMIN_CAP)
    const outer = await signUcan(attacker, attacker.did, spaceId, ADMIN_CAP, [borrowed, selfRoot])

    const authority = await resolveCallerAuthority(
      contextWith({ ucan: await ucanContextFor(outer) }),
      spaceId,
    )

    expect(authority).toEqual(OWNER_ROOT_ERROR)
  })

  test('rejects when the space does not exist', async () => {
    // Reachable: a UCAN may name a space this server has never seen. With no
    // owner to anchor against, the only safe answer is no.
    const owner = await makeIdentity()
    spaceRows = []
    const spaceId = crypto.randomUUID()

    const token = await signUcan(owner, owner.did, spaceId, ADMIN_CAP)
    const authority = await resolveCallerAuthority(
      contextWith({ ucan: await ucanContextFor(token) }),
      spaceId,
    )

    expect(authority).toEqual(OWNER_ROOT_ERROR)
  })

  test('rejects when the space row carries no owner', async () => {
    // spaces.owner_id is notNull() in the schema, so this is defence in depth
    // against a future schema change or a partially-populated row, not a state
    // reachable today. A null owner must never authorize anyone.
    const owner = await makeIdentity()
    spaceRows = [{ ownerId: null }]
    const spaceId = crypto.randomUUID()

    const token = await signUcan(owner, owner.did, spaceId, ADMIN_CAP)
    const authority = await resolveCallerAuthority(
      contextWith({ ucan: await ucanContextFor(token) }),
      spaceId,
    )

    expect(authority).toEqual(OWNER_ROOT_ERROR)
  })

  test("accepts the owner's own root UCAN", async () => {
    const owner = await makeIdentity()
    spaceRows = [{ ownerId: owner.did }]
    const spaceId = crypto.randomUUID()

    const token = await signUcan(owner, owner.did, spaceId, ADMIN_CAP)
    const authority = await resolveCallerAuthority(
      contextWith({ ucan: await ucanContextFor(token) }),
      spaceId,
    )

    expect(authority).toEqual({ ok: true, capabilities: ADMIN_CAP })
  })

  test('accepts a legitimately delegated invitee token and returns its declared caps', async () => {
    const owner = await makeIdentity()
    const invitee = await makeIdentity()
    spaceRows = [{ ownerId: owner.did }]
    const spaceId = crypto.randomUUID()

    const delegation = await signUcan(owner, invitee.did, spaceId, WRITER_DELEGATABLE)
    const token = await signUcan(invitee, invitee.did, spaceId, WRITER_FINAL, [delegation])

    const authority = await resolveCallerAuthority(
      contextWith({ ucan: await ucanContextFor(token) }),
      spaceId,
    )

    expect(authority).toEqual({ ok: true, capabilities: WRITER_FINAL })
  })

  test('accepts a two-hop owner → admin → writer chain', async () => {
    const owner = await makeIdentity()
    const admin = await makeIdentity()
    const writer = await makeIdentity()
    spaceRows = [{ ownerId: owner.did }]
    const spaceId = crypto.randomUUID()

    const hop1 = await signUcan(owner, admin.did, spaceId, ADMIN_PRESET)
    const hop2 = await signUcan(admin, writer.did, spaceId, WRITER_DELEGATABLE, [hop1])
    const token = await signUcan(writer, writer.did, spaceId, WRITER_FINAL, [hop2])

    const authority = await resolveCallerAuthority(
      contextWith({ ucan: await ucanContextFor(token) }),
      spaceId,
    )

    expect(authority).toEqual({ ok: true, capabilities: WRITER_FINAL })
  })
})

// ============================================
// resolveCallerAuthority — query scoping
// ============================================

// The owner lookup is the only DB-side input to the root-of-trust decision,
// so its predicate carries the whole weight of "this space". A mock that
// discards .where() cannot tell a correctly scoped query from one filtering
// on the wrong column entirely.

describe('resolveCallerAuthority — owner lookup scoping', () => {
  test('scopes the UCAN-path owner lookup to spaces.id and this space', async () => {
    const owner = await makeIdentity()
    spaceRows = [{ ownerId: owner.did }]
    const spaceId = crypto.randomUUID()
    const token = await signUcan(owner, owner.did, spaceId, ADMIN_CAP)
    const ucan = await ucanContextFor(token)

    columnReads = []
    lastWhere = null
    await resolveCallerAuthority(contextWith({ ucan }), spaceId)

    expect(columnReads).toContain('spaces.id')
    expect(conditionMentions(lastWhere, spaceId)).toBe(true)
  })

  test('scopes the DID-auth owner lookup to spaces.id and this space', async () => {
    const owner = await makeIdentity()
    spaceRows = [{ ownerId: owner.did }]
    const spaceId = crypto.randomUUID()

    columnReads = []
    lastWhere = null
    await resolveCallerAuthority(contextWith({ didAuth: { did: owner.did } }), spaceId)

    expect(columnReads).toContain('spaces.id')
    expect(conditionMentions(lastWhere, spaceId)).toBe(true)
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

  test('rejects a DID-auth caller when the space does not exist', async () => {
    const caller = await makeIdentity()
    spaceRows = []
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

describe('resolveCallerAuthority — no auth context', () => {
  test('rejects a request with neither a UCAN nor DID-auth', async () => {
    const spaceId = crypto.randomUUID()

    const authority = await resolveCallerAuthority(contextWith({}), spaceId)

    expect(authority).toEqual({
      ok: false,
      status: 403,
      error: 'Forbidden - No auth context',
    })
  })
})

describe('resolveCallerAuthority — missing capability entry', () => {
  test('rejects a UCAN with no capability entry for this space resource', async () => {
    const owner = await makeIdentity()
    const otherSpaceId = crypto.randomUUID()
    const spaceId = crypto.randomUUID()
    spaceRows = [{ ownerId: owner.did }]

    const token = await signUcan(owner, owner.did, otherSpaceId, ADMIN_CAP)
    const ucan = await ucanContextFor(token)

    const authority = await resolveCallerAuthority(contextWith({ ucan }), spaceId)

    expect(authority).toEqual({
      ok: false,
      status: 403,
      error: `Forbidden - Insufficient capability for ${spaceResource(spaceId)}`,
    })
  })
})
