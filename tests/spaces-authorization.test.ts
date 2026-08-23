/**
 * Authorization holes in spacesRouter:
 *
 *  1. POST /:spaceId/members is gated on `invite` but lets the caller name the
 *     capability granted to the invitee, written verbatim to space_members.
 *     An invite-only holder could grant `write`.
 *  2. DELETE /my-admin-spaces authorized purely off the cached
 *     space_members.capability column, with no capability check at all, and
 *     cascade-deletes the space.
 *  3. A UCAN carries no proof of possession, so a member's own credential —
 *     the owner's delegation to them — can be presented verbatim to make
 *     getCallerDid() report the owner. Routes whose authority is
 *     identity-shaped therefore require DID-Auth.
 *
 * All drive the real router with real signed auth and assert on the rows
 * actually handed to the db, not just status codes.
 */
import { describe, test, expect, mock, beforeAll } from 'bun:test'
import { createUcan, spaceCapabilitySet, spaceResource } from '@haex-space/ucan'
import { buildDbMock, emptyChain } from './helpers/db-mock'
import {
  makeIdentity,
  createDidAuthHeader,
  ucanRequestHeaders,
  type Identity,
} from './integration/helpers'

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
let reader: Identity

/** Captured from the transfer-ownership transaction. */
let transferredOwnerTo: string | null = null
/** Read through a call so TS control-flow narrowing does not collapse the type. */
const takeTransferredOwner = (): string | null => transferredOwnerTo

/** Row captured from db.insert(spaceMembers).values(...). */
let insertedMember: any = null
/** Space ids passed to db.delete(spaces).where(...), in order. */
let deletedSpaceIds: string[] = []
/**
 * The `spaces` table, keyed by owner. The mock answers the owner-scan from
 * this by the DID in the query's predicate, so ownership scoping is genuinely
 * exercised rather than dictated by a per-test fixture.
 */
let spacesByOwner: Record<string, { id: string }[]> = {}
/** Rows the mocked space_members admin-scan returns (pre-fix code path). */
let adminMembershipRows: { spaceId: string }[] = []
/** Columns the handlers touched, so a wrong-column query is detectable. */
let columnReads: string[] = []

/** A thenable that also answers .limit() — some call sites await, some paginate. */
function resultChain(rows: any[]) {
  const chain: any = Promise.resolve(rows)
  chain.limit = () => Promise.resolve(rows)
  return chain
}

beforeAll(async () => {
  owner = await makeIdentity()
  inviter = await makeIdentity()
  reader = await makeIdentity()

  mock.module('../src/db', () => ({
    ...buildDbMock({
    // Discriminated by the requested projection rather than by call order, so
    // adding an unrelated lookup ahead of these cannot silently misroute them.
    select: (columns?: Record<string, any>) => {
      const wants = columns ? Object.keys(columns).sort().join(',') : '*'
      const chain: any = {}
      chain.from = () => chain
      chain.where = (condition: any) => {
        const rows =
          // owner scan: answered from the DID the query actually filters on
          wants === 'id' ? (spacesByOwner[findDid(condition) ?? ''] ?? [])
          : wants === 'ownerId' ? [{ ownerId: owner.did }] // root-of-trust lookup
          : wants === 'spaceId' ? adminMembershipRows // membership scan (pre-fix)
          : wants === '*' ? [{ did: INVITEE_DID, publicKey: 'invitee-pubkey' }]
          : [] // "already a member?" probe — never already a member here
        return resultChain(rows)
      }
      chain.limit = () => Promise.resolve([])
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
    // Shared by transfer-ownership (select the target member, update rows) and
    // the bulk-delete transaction (select owned spaces, delete each). The two
    // selects are told apart by requested projection, same as the top-level
    // select mock above.
    transaction: async (fn: (tx: any) => any) => fn({
      select: (columns?: Record<string, any>) => {
        const wants = columns ? Object.keys(columns).sort().join(',') : '*'
        const chain: any = {}
        chain.from = () => chain
        if (wants === 'id') {
          chain.where = (condition: any) => resultChain(spacesByOwner[findDid(condition) ?? ''] ?? [])
          return chain
        }
        chain.where = () => chain
        chain.limit = () => Promise.resolve([{ did: transferTargetDid }])
        return chain
      },
      update: () => {
        const chain: any = {}
        chain.set = (values: any) => {
          if (values.ownerId) transferredOwnerTo = values.ownerId
          return chain
        }
        chain.where = () => Promise.resolve([])
        return chain
      },
      insert: () => emptyChain(),
      delete: () => {
        const chain: any = {}
        chain.where = (condition: any) => {
          const found = findUuid(condition)
          if (found) deletedSpaceIds.push(found)
          return Promise.resolve([])
        }
        return chain
      },
    }),
    }),
    // Override the `spaces` table so column access is observable. buildDbMock's
    // shared stub collapses every column to the same value, which would make a
    // query on the wrong column indistinguishable from a correct one.
    spaces: new Proxy({} as Record<string, string>, {
      get: (_t, property) => {
        if (typeof property !== 'string') return undefined
        columnReads.push(`spaces.${property}`)
        return `spaces.${property}`
      },
    }),
  }))

  spacesRouter = (await import('../src/routes/spaces')).default
})

let transferTargetDid = ''

/** base64url JWT payload → object. */
function decodePayload(jwt: string): any {
  let b64 = jwt.split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/')
  while (b64.length % 4 !== 0) b64 += '='
  return JSON.parse(atob(b64))
}

/**
 * A lifted `prf[0]`: the owner's delegation to a reader, pulled back out of the
 * reader's own re-issued token and presented directly.
 *
 * Nothing compares a UCAN's `aud` against the presenter, so this is a bearer
 * token — and because its `iss` is the owner, `getCallerDid()` reports the
 * OWNER while the capability set stays read-tier. Capability gates therefore
 * still bind; gates that read caller identity do not.
 */
async function liftedOwnerDelegation(
  holder: Identity = reader,
  caps = spaceCapabilitySet().read(false).build(),
): Promise<string> {
  const expiration = Math.floor(Date.now() / 1000) + 3600
  const delegation = await createUcan(
    {
      issuer: owner.did,
      audience: holder.did,
      capabilities: { [spaceResource(SPACE_ID)]: caps },
      expiration,
      proofs: [],
    },
    owner.sign,
  )
  const reissued = await createUcan(
    {
      issuer: holder.did,
      audience: holder.did,
      capabilities: { [spaceResource(SPACE_ID)]: caps },
      expiration,
      proofs: [delegation],
    },
    holder.sign,
  )
  return `UCAN ${decodePayload(reissued).prf[0]}`
}

/** Recover a did:key from a drizzle condition, whatever shape the live eq gave it. */
function findDid(node: unknown, depth = 0): string | null {
  if (depth > 20) return null
  if (typeof node === 'string') return node.startsWith('did:key:') ? node : null
  if (Array.isArray(node)) {
    for (const n of node) {
      const hit = findDid(n, depth + 1)
      if (hit) return hit
    }
    return null
  }
  if (node && typeof node === 'object') {
    for (const v of Object.values(node)) {
      const hit = findDid(v, depth + 1)
      if (hit) return hit
    }
  }
  return null
}

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

async function inviteMember(header: string, capability: string, holder: Identity = inviter) {
  insertedMember = null
  const body = JSON.stringify({ did: INVITEE_DID, label: 'New member', capability })
  const path = `/${SPACE_ID}/members`
  return spacesRouter.request(path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(await ucanRequestHeaders(holder, header, { method: 'POST', path, body })),
    },
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
      { method: 'POST', path: `/${SPACE_ID}/members`, body },
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
  columnReads = []
  // The owner owns two spaces; the inviter owns none. Both tests share this,
  // so which spaces get deleted depends on the query, not on the fixture.
  spacesByOwner = { [owner.did]: [{ id: OWNED_A }, { id: OWNED_B }] }
  const header = await createDidAuthHeader(caller.keyPair.privateKey, caller.did, {
    method: 'DELETE', path: '/my-admin-spaces',
  })
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
    // space_members says this caller administers both spaces. Irrelevant now.
    adminMembershipRows = [{ spaceId: OWNED_A }, { spaceId: OWNED_B }]

    const res = await deleteMyAdminSpaces(inviter)

    expect(res.status).toBe(200)
    const json = (await res.json()) as any
    expect(json.deletedSpaces).toBe(0)
    expect(deletedSpaceIds).toEqual([])
  })

  test('deletes exactly the spaces the caller owns', async () => {
    adminMembershipRows = []

    const res = await deleteMyAdminSpaces(owner)

    expect(res.status).toBe(200)
    const json = (await res.json()) as any
    expect(json.deletedSpaces).toBe(2)
    expect(deletedSpaceIds).toEqual([OWNED_A, OWNED_B])
  })

  test('scopes the space scan to spaces.ownerId', async () => {
    await deleteMyAdminSpaces(owner)

    expect(columnReads).toContain('spaces.ownerId')
  })
})

// ============================================
// Task 1.6 — stopgaps for UCAN bearer semantics
// ============================================

// A UCAN carries no proof of possession: nothing checks `aud` against the
// presenter. A member's own credential is the owner's delegation to them, so
// presenting it verbatim makes getCallerDid() report the owner. Capability
// gates still bind (caps do not escalate), but any route that authorizes off
// caller identity — or has no capability gate at all — does not.
//
// The real remedy is an audience check, which is a wire-format change. These
// tests pin the stopgap: routes whose authority is identity-shaped require
// DID-Auth, which is genuine proof of possession.

describe('DELETE /my-admin-spaces — rejects UCAN auth', () => {
  test('a lifted owner delegation cannot delete the owner\'s spaces', async () => {
    deletedSpaceIds = []
    spacesByOwner = { [owner.did]: [{ id: OWNED_A }, { id: OWNED_B }] }

    const res = await spacesRouter.request('/my-admin-spaces', {
      method: 'DELETE',
      headers: { Authorization: await liftedOwnerDelegation() },
    })

    expect(res.status).toBe(401)
    expect(deletedSpaceIds).toEqual([])
  })

  test('DID-Auth still deletes the owner\'s spaces', async () => {
    const res = await deleteMyAdminSpaces(owner)

    expect(res.status).toBe(200)
    expect(deletedSpaceIds).toEqual([OWNED_A, OWNED_B])
  })
})

describe('POST /:spaceId/transfer-ownership — rejects UCAN auth', () => {
  // A delegated admin holds admin(delegatable:false) precisely so it cannot
  // mint further admins. Naming itself as transfer target would hand it the
  // fully-delegatable owner set, defeating that invariant.
  // A delegated admin cannot re-issue an admin token to itself — admin is
  // non-delegatable, so verifyUcan rejects that outright. The reachable shape
  // is presenting the owner's delegation verbatim, which passes the admin gate
  // and names the holder as target.
  test('a lifted admin delegation cannot transfer ownership to its holder', async () => {
    transferredOwnerTo = null
    transferTargetDid = inviter.did
    const adminSet = spaceCapabilitySet().read(true).write(true).invite(true).admin(false).build()
    const header = await liftedOwnerDelegation(inviter, adminSet)
    const path = `/${SPACE_ID}/transfer-ownership`
    const body = JSON.stringify({ targetDid: inviter.did })

    const res = await spacesRouter.request(path, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(await ucanRequestHeaders(inviter, header, { method: 'POST', path, body })),
      },
      body,
    })

    expect(res.status).toBe(401)
    expect(takeTransferredOwner()).toBeNull()
  })

  test('the owner can still transfer ownership over DID-Auth', async () => {
    transferredOwnerTo = null
    transferTargetDid = inviter.did
    const body = JSON.stringify({ targetDid: inviter.did })
    const header = await createDidAuthHeader(
      owner.keyPair.privateKey,
      owner.did,
      { method: 'POST', path: `/${SPACE_ID}/transfer-ownership`, body },
    )

    const res = await spacesRouter.request(`/${SPACE_ID}/transfer-ownership`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: header },
      body,
    })

    expect(res.status).toBe(200)
    expect(takeTransferredOwner()).toBe(inviter.did)
  })
})
