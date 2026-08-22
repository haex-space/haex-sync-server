/**
 * GET /:spaceId/invites must not hand out other people's UCANs.
 *
 * The route is gated on `read` and returned `ucan` for every invite in the
 * space, so a read-tier member could harvest a pending admin invite's UCAN and
 * replay it verbatim — nothing binds a UCAN to its presenter. That yielded a
 * full takeover in review: mint admin, transfer ownership.
 *
 * The UCAN is emitted only for the invite addressed to the caller. A boolean
 * `hasUcan` keeps the presence signal that the legitimate consumer needs.
 */
import { describe, test, expect, mock, beforeAll } from 'bun:test'
import { createUcan, spaceCapabilitySet, spaceResource } from '@haex-space/ucan'
import { buildDbMock, emptyChain } from './helpers/db-mock'
import { makeIdentity, ucanRequestHeaders, type Identity } from './integration/helpers'

const SPACE_ID = '99999999-9999-4999-8999-999999999999'
const ADMIN_INVITE_UCAN = 'eyJhbGciOiJFZERTQSJ9.ADMIN_INVITE_UCAN_SECRET.sig'
const OWN_INVITE_UCAN = 'eyJhbGciOiJFZERTQSJ9.OWN_INVITE_UCAN.sig'

mock.module('../src/services/federationClient', () => ({
  getFederationLinkForSpace: () => null,
  federatedProxyAsync: async () => ({ status: 500, data: { error: 'should not be called' } }),
}))
mock.module('../src/utils/didIdentity', () => ({ didToSpkiPublicKey: () => '' }))

let mlsRouter: { request: (path: string, init?: any) => Response | Promise<Response> }
let owner: Identity
let member: Identity
let unprojectedCalls = 0

/** Thenable that also answers from/where/limit with itself. */
function node(rows: any[]) {
  const n: any = Promise.resolve(rows)
  n.from = () => n
  n.where = () => n
  n.limit = () => Promise.resolve(rows)
  n.orderBy = () => n
  return n
}

/** One invite for a pending admin (someone else), one for the caller. */
function inviteRows() {
  return [
    {
      id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      inviterPublicKey: 'owner-pubkey',
      inviteeDid: 'did:key:zPendingAdmin',
      ucan: ADMIN_INVITE_UCAN,
      tokenId: null,
      status: 'pending',
      includeHistory: false,
      expiresAt: null,
      createdAt: new Date(),
      respondedAt: null,
    },
    {
      id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      inviterPublicKey: 'owner-pubkey',
      inviteeDid: member.did,
      ucan: OWN_INVITE_UCAN,
      tokenId: null,
      status: 'accepted',
      includeHistory: false,
      expiresAt: null,
      createdAt: new Date(),
      respondedAt: null,
    },
    {
      // Token-based invite: no UCAN stored yet. This is the case the inviter's
      // device uses hasUcan to detect, so it must report false.
      id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      inviterPublicKey: 'owner-pubkey',
      inviteeDid: 'did:key:zTokenJoiner',
      ucan: null,
      tokenId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
      status: 'accepted',
      includeHistory: false,
      expiresAt: null,
      createdAt: new Date(),
      respondedAt: null,
    },
  ]
}

beforeAll(async () => {
  owner = await makeIdentity()
  member = await makeIdentity()

  mock.module('../src/db', () => buildDbMock({
    // A self-returning thenable: some call sites await .where() directly, others
    // chain .limit(1). Projection tells most queries apart; the two unprojected
    // ones (resolveDidIdentity, then the invite listing) go by order.
    select: (columns?: Record<string, any>) => {
      const wants = columns ? Object.keys(columns).sort().join(',') : '*'
      if (wants === 'ownerId') return node([{ ownerId: owner.did }]) // root of trust
      if (wants === 'did') return node([{ did: member.did }]) // is a member
      if (wants === '*') {
        unprojectedCalls++
        return unprojectedCalls === 1
          ? node([{ did: member.did, publicKey: 'member-pubkey' }]) // resolveDidIdentity
          : node(inviteRows())
      }
      return node([])
    },
    insert: () => emptyChain(),
    update: () => emptyChain(),
    delete: () => emptyChain(),
  }))

  mlsRouter = (await import('../src/routes/mls')).default
})

/** A read-tier member's credential: the owner's delegation to them. */
async function memberHeader(): Promise<string> {
  const expiration = Math.floor(Date.now() / 1000) + 3600
  const readerSet = spaceCapabilitySet().read(true).build()
  const delegation = await createUcan(
    {
      issuer: owner.did,
      audience: member.did,
      capabilities: { [spaceResource(SPACE_ID)]: readerSet },
      expiration,
      proofs: [],
    },
    owner.sign,
  )
  const token = await createUcan(
    {
      issuer: member.did,
      audience: member.did,
      capabilities: { [spaceResource(SPACE_ID)]: readerSet },
      expiration,
      proofs: [delegation],
    },
    member.sign,
  )
  return `UCAN ${token}`
}

async function listInvites() {
  unprojectedCalls = 0
  const header = await memberHeader()
  const path = `/${SPACE_ID}/invites`
  const res = await mlsRouter.request(path, {
    headers: await ucanRequestHeaders(member, header, { method: 'GET', path }),
  })
  return { res, body: (await res.json()) as any }
}

describe('GET /:spaceId/invites — UCANs are not shared across invitees', () => {
  test("omits the ucan of an invite addressed to someone else", async () => {
    const { res, body } = await listInvites()

    expect(res.status).toBe(200)
    const other = body.invites.find((i: any) => i.inviteeDid === 'did:key:zPendingAdmin')
    expect(other).toBeDefined()
    expect(other.ucan).toBeNull()
    // The whole response must not carry the secret anywhere
    expect(JSON.stringify(body)).not.toContain('ADMIN_INVITE_UCAN_SECRET')
  })

  test('still returns the caller\'s own ucan', async () => {
    const { body } = await listInvites()

    const own = body.invites.find((i: any) => i.inviteeDid === member.did)
    expect(own).toBeDefined()
    expect(own.ucan).toBe(OWN_INVITE_UCAN)
  })

  test('reports ucan presence for other invites without revealing it', async () => {
    const { body } = await listInvites()

    const other = body.invites.find((i: any) => i.inviteeDid === 'did:key:zPendingAdmin')
    // The one legitimate consumer only needs to know whether a UCAN exists
    // (haex-vault realtime.ts uses it to decide whether to mint one).
    expect(other.hasUcan).toBe(true)
    expect(body.invites.find((i: any) => i.inviteeDid === member.did).hasUcan).toBe(true)
  })

  test('reports hasUcan false for a token invite with no UCAN yet', async () => {
    const { body } = await listInvites()

    const tokenInvite = body.invites.find((i: any) => i.inviteeDid === 'did:key:zTokenJoiner')
    expect(tokenInvite).toBeDefined()
    expect(tokenInvite.hasUcan).toBe(false)
    expect(tokenInvite.ucan).toBeNull()
  })

  test('still lists every invite with its non-secret fields', async () => {
    const { body } = await listInvites()

    expect(body.invites).toHaveLength(3)
    expect(body.invites.map((i: any) => i.status).sort()).toEqual(['accepted', 'accepted', 'pending'])
  })
})
