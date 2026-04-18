/**
 * Regression: mlsRouter UUID-guard middleware must respect the mount prefix.
 *
 * The router is mounted at `/spaces` in index.ts (app.route('/spaces', mlsRoutes)).
 * An earlier attempt parsed segments from new URL(c.req.url).pathname, which in
 * Hono 4 still contains the mount prefix. segments[0] was therefore always the
 * literal "spaces", so every request under /spaces/:spaceId/… returned 400
 * "Invalid spaceId: must be a UUID" — silently breaking createInviteToken,
 * server-invite endpoints, MLS rejoin, etc.
 *
 * The previous mls-validation.test.ts called mlsRouter.request() directly,
 * bypassing the mount, which is why the bug wasn't caught locally.
 *
 * These tests simulate the production routing topology.
 */

import { describe, test, expect, mock, beforeAll } from 'bun:test'
import { Hono } from 'hono'
import { buildDbMock } from './helpers/db-mock'
import { makeIdentity, createDidAuthHeader } from './integration/helpers'

const VALID_UUID = '11111111-1111-4111-8111-111111111111'

// Stub federation so the relay branch is never taken.
mock.module('../src/services/federationClient', () => ({
  getFederationLinkForSpace: () => null,
  federatedProxyAsync: async () => ({ status: 500, data: { error: 'should not be called' } }),
}))

mock.module('../src/utils/didIdentity', () => ({ didToSpkiPublicKey: () => '' }))

// Make requireCapability pass: owner lookup returns the caller's DID.
let callerDid = 'did:key:placeholder'
mock.module('../src/db', () => buildDbMock({
  select: () => {
    const chain: any = {}
    chain.from = () => chain
    chain.where = () => chain
    chain.limit = () => Promise.resolve([{ ownerId: callerDid }])
    return chain
  },
  insert: () => {
    const chain: any = {}
    chain.values = () => chain
    chain.returning = () => Promise.resolve([{
      id: VALID_UUID,
      capability: 'space/read',
      maxUses: 1,
      expiresAt: new Date(Date.now() + 3600_000),
      label: null,
    }])
    return chain
  },
}))

let app: Hono
let caller: { did: string; keyPair: CryptoKeyPair }

beforeAll(async () => {
  const id = await makeIdentity()
  caller = { did: id.did, keyPair: id.keyPair }
  callerDid = id.did

  // Production mount: mlsRouter lives under /spaces/*.
  const mlsRouter = (await import('../src/routes/mls')).default
  app = new Hono()
  app.route('/spaces', mlsRouter)
})

describe('mlsRouter — mount-prefix aware UUID guard', () => {
  test('valid UUID spaceId with mount prefix is NOT rejected as "spaces"', async () => {
    // Reproduces the original bug: pre-fix this returned 400 "Invalid spaceId"
    // because segments[0] was "spaces", not the UUID.
    const header = await createDidAuthHeader(
      caller.keyPair.privateKey,
      caller.did,
      'space-create',
      JSON.stringify({ capability: 'space/read', expiresInSeconds: 3600 }),
    )

    const res = await app.request(`/spaces/${VALID_UUID}/invite-tokens`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: header,
      },
      body: JSON.stringify({ capability: 'space/read', expiresInSeconds: 3600 }),
    })

    // The specific assertion: we should NOT see the UUID-guard error fire.
    // The actual handler may still 5xx because the mock chain is approximate,
    // but the 400 "Invalid spaceId" path must not trigger.
    if (res.status === 400) {
      const body = await res.json() as { error?: string }
      expect(body.error ?? '').not.toContain('Invalid spaceId')
    }
  })

  test('malformed spaceId with mount prefix IS still rejected', async () => {
    const res = await app.request(`/spaces/not-a-uuid/invite-tokens`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    })
    expect(res.status).toBe(400)
    const body = await res.json() as { error: string }
    expect(body.error).toContain('Invalid spaceId')
  })

  test('malformed inviteId on valid space+mount IS rejected', async () => {
    const res = await app.request(`/spaces/${VALID_UUID}/invites/bad/accept`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    })
    expect(res.status).toBe(400)
    const body = await res.json() as { error: string }
    expect(body.error).toContain('Invalid inviteId')
  })

  test('malformed tokenId on valid space+mount IS rejected', async () => {
    const res = await app.request(`/spaces/${VALID_UUID}/invite-tokens/bad`, {
      method: 'DELETE',
    })
    expect(res.status).toBe(400)
    const body = await res.json() as { error: string }
    expect(body.error).toContain('Invalid tokenId')
  })
})
