/**
 * Two authorization holes in spacesRouter, both rooted in trusting the cached
 * `space_members.capability` column:
 *
 *  1. POST /:spaceId/members is gated on `invite` but lets the caller name the
 *     capability granted to the invitee, written verbatim to space_members.
 *     An invite-only holder could grant `write`.
 *  2. DELETE /my-admin-spaces authorizes purely on that cached column, with no
 *     capability check at all, and cascade-deletes the space.
 *
 * Both drive the real router with real signed auth and assert on the rows
 * actually handed to the db, not just status codes.
 */
import { describe, test, expect, mock, beforeAll } from 'bun:test'
import { createUcan, spaceCapabilitySet, spaceResource } from '@haex-space/ucan'
import { buildDbMock, emptyChain } from './helpers/db-mock'
import { makeIdentity, createDidAuthHeader, type Identity } from './integration/helpers'

const SPACE_ID = '66666666-6666-4666-8666-666666666666'
const OWNED_A = '77777777-7777-4777-8777-777777777777'
const OWNED_B = '88888888-8888-4888-8888-888888888888'

mock.module('../src/services/federationClient', () => ({
  getFederationLinkForSpace: () => null,
  federatedProxyAsync: async () => ({ status: 500, data: { error: 'should not be called' } }),
}))
mock.module('../src/routes/ws', () => ({
  broadcastToSpace: () => {},
  updateMembershipCache: () => {},
  sendToDid: () => {},
}))
const INVITER_SET = spaceCapabilitySet().read(true).invite(true).build()
const INVITEE_DID = 'did:key:zInvitee'

let spacesRouter: { request: (path: string, init?: any) => Response | Promise<Response> }
let owner: Identity
let inviter: Identity

/** Row captured from db.insert(spaceMembers).values(...). */
let insertedMember: any = null
/** Space ids passed to db.delete(spaces).where(...), in order. */
let deletedSpaceIds: string[] = []
/** Rows the mocked `spaces` owner-scan returns. */
let ownedRows: { id: string }[] = []
/** Rows the mocked space_members admin-scan returns (pre-fix code path). */
let adminMembershipRows: { spaceId: string }[] = []

/** A thenable that also answers .limit() — some call sites await, some paginate. */
function resultChain(rows: any[]) {
  const chain: any = Promise.resolve(rows)
  chain.limit = () => Promise.resolve(rows)
  return chain
}

beforeAll(async () => {
  owner = await makeIdentity()
  inviter = await makeIdentity()

  mock.module('../src/db', () => buildDbMock({
    // Discriminated by the requested projection rather than by call order, so
    // adding an unrelated lookup ahead of these cannot silently misroute them.
    select: (columns?: Record<string, any>) => {
      const wants = columns ? Object.keys(columns).sort().join(',') : '*'
      const rows =
        wants === 'ownerId' ? [{ ownerId: owner.did }] // root-of-trust lookup
        : wants === 'id' ? ownedRows // owner scan (post-fix)
        : wants === 'spaceId' ? adminMembershipRows // membership scan (pre-fix)
        : wants === '*' ? [{ did: INVITEE_DID, publicKey: 'invitee-pubkey' }] // resolveDidIdentity
        : [] // "already a member?" probe — never already a member here
      const chain: any = {}
      chain.from = () => chain
      chain.where = () => resultChain(rows)
      chain.limit = () => Promise.resolve(rows)
      return chain
    },
    insert: () => {
      const chain: any = {}
      chain.values = (values: any) => {
        insertedMember = values
        return chain
      }
      chain.returning = () => Promise.resolve([insertedMember ?? {}])
      chain.onConflictDoNothing = () => chain
      chain.onConflictDoUpdate = () => chain
      return chain
    },
    delete: () => {
      const chain: any = {}
      // eq(spaces.id, <uuid>) — recover the uuid from the captured condition
      chain.where = (condition: any) => {
        const found = findUuid(condition)
        if (found) deletedSpaceIds.push(found)
        return Promise.resolve([])
      }
      return chain
    },
    update: () => emptyChain(),
  }))

  spacesRouter = (await import('../src/routes/spaces')).default
})

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

/** Recover a uuid from a drizzle condition whatever shape the live eq gave it. */
function findUuid(node: unknown, depth = 0): string | null {
  if (depth > 20) return null
  if (typeof node === 'string') return UUID_RE.test(node) ? node : null
  if (Array.isArray(node)) {
    for (const n of node) {
      const hit = findUuid(n, depth + 1)
      if (hit) return hit
    }
    return null
  }
  if (node && typeof node === 'object') {
    for (const v of Object.values(node)) {
      const hit = findUuid(v, depth + 1)
      if (hit) return hit
    }
  }
  return null
}

/** An inviter UCAN delegated from the space owner (self-signed would be rejected). */
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

async function inviteMember(header: string, capability: string) {
  insertedMember = null
  const body = JSON.stringify({ did: INVITEE_DID, label: 'New member', capability })
  return spacesRouter.request(`/${SPACE_ID}/members`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: header },
    body,
  })
}

// ============================================
// Task 1.4 — POST /:spaceId/members attenuation
// ============================================

describe('POST /:spaceId/members — grant attenuation', () => {
  test('rejects an invite-only caller granting write', async () => {
    const res = await inviteMember(await inviterHeader(), 'space/write')

    expect(res.status).toBe(403)
    const json = (await res.json()) as any
    expect(json.error).toContain('exceeds caller authority')
    expect(json.error).toContain('write')
    expect(insertedMember).toBeNull()
  })

  // The inviter preset holds read(delegatable:true) precisely so this works.
  test('allows an invite-only caller granting read', async () => {
    const res = await inviteMember(await inviterHeader(), 'space/read')

    expect(res.status).toBe(201)
    expect(insertedMember).not.toBeNull()
    expect(insertedMember.capability).toBe('space/read')
    expect(insertedMember.spaceId).toBe(SPACE_ID)
    expect(insertedMember.did).toBe(INVITEE_DID)
    expect(insertedMember.invitedBy).toBe(inviter.did)
  })

  test('allows the space owner granting write', async () => {
    const body = JSON.stringify({
      did: INVITEE_DID,
      label: 'New member',
      capability: 'space/write',
    })
    const header = await createDidAuthHeader(
      owner.keyPair.privateKey,
      owner.did,
      'space-write',
      body,
    )
    insertedMember = null

    const res = await spacesRouter.request(`/${SPACE_ID}/members`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: header },
      body,
    })

    expect(res.status).toBe(201)
    expect(insertedMember).not.toBeNull()
    expect(insertedMember.capability).toBe('space/write')
    expect(insertedMember.invitedBy).toBe(owner.did)
  })
})
// ============================================
// Task 1.5 — DELETE /my-admin-spaces ownership
// ============================================

async function deleteMyAdminSpaces(caller: Identity) {
  deletedSpaceIds = []
  const header = await createDidAuthHeader(caller.keyPair.privateKey, caller.did, 'space-delete', '')
  return spacesRouter.request('/my-admin-spaces', {
    method: 'DELETE',
    headers: { Authorization: header },
  })
}

describe('DELETE /my-admin-spaces — scoped to owned spaces', () => {
  // The final step of the escalation chain: space_members.capability is a
  // cached column an attacker could have written. Administering a space must
  // not authorize destroying it — that would delete someone else's space.
  test('deletes nothing for an admin who does not own the space', async () => {
    ownedRows = []
    adminMembershipRows = [{ spaceId: OWNED_A }, { spaceId: OWNED_B }]

    const res = await deleteMyAdminSpaces(inviter)

    expect(res.status).toBe(200)
    const json = (await res.json()) as any
    expect(json.deletedSpaces).toBe(0)
    expect(deletedSpaceIds).toEqual([])
  })

  test('deletes exactly the spaces the caller owns', async () => {
    ownedRows = [{ id: OWNED_A }, { id: OWNED_B }]
    adminMembershipRows = []

    const res = await deleteMyAdminSpaces(owner)

    expect(res.status).toBe(200)
    const json = (await res.json()) as any
    expect(json.deletedSpaces).toBe(2)
    expect(deletedSpaceIds).toEqual([OWNED_A, OWNED_B])
  })
})
