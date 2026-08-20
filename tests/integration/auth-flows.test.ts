import { describe, test, expect, mock, beforeEach } from 'bun:test'
import { Hono } from 'hono'
import { createUcan, spaceCapabilitySet, spaceResource } from '@haex-space/ucan'

// Mock DB before importing middleware — resolveCallerAuthority reads
// spaces.ownerId to anchor the root of trust for the UCAN proof forest.
// Defaults to an unrelated DID so forged/self-signed roots are rejected;
// tests that exercise a legitimate grant set it to their own issuer.
const UNRELATED_OWNER = 'did:key:zUnrelatedSpaceOwner'
let mockSpaceOwnerDid = UNRELATED_OWNER

mock.module('../../src/db', () => ({
  db: {
    select: () => ({
      from: () => ({
        where: () => ({
          limit: () => Promise.resolve([{ ownerId: mockSpaceOwnerDid }]),
        }),
      }),
    }),
  },
  spaces: { id: 'id', ownerId: 'owner_id' },
  spaceMembers: { did: 'did', spaceId: 'space_id', capability: 'capability' },
}))

import { authDispatcher } from '../../src/middleware/authDispatcher'
import { requireCapability } from '../../src/middleware/ucanAuth'
import {
  makeIdentity,
  createDidAuthHeader,
  createUcanHeader,
  base64urlEncode,
} from './helpers'

// ============================================
// App Factories
// ============================================

// Defence in depth, not a correctness dependency: every test generates fresh
// identities, so a leaked owner can only ever be a stale unrelated DID, which
// is fail-closed anyway. Resetting keeps each test's setup self-evident.
beforeEach(() => {
  mockSpaceOwnerDid = UNRELATED_OWNER
})

/** App with authDispatcher — routes check didAuth/ucan context */
function createDispatcherApp() {
  const app = new Hono()
  app.use('*', authDispatcher)

  // DID-Auth-only endpoint (e.g. space creation)
  app.post('/spaces', (c) => {
    const didAuth = c.get('didAuth')
    if (!didAuth) return c.json({ error: 'DID-Auth required' }, 401)
    return c.json({ ok: true, did: didAuth.did })
  })

  // UCAN-protected space endpoint with capability check
  app.get('/spaces/:spaceId', async (c) => {
    const spaceId = c.req.param('spaceId')
    const error = await requireCapability(c, spaceId, 'read')
    if (error) return error
    return c.json({ ok: true, spaceId })
  })

  app.put('/spaces/:spaceId', async (c) => {
    const spaceId = c.req.param('spaceId')
    const error = await requireCapability(c, spaceId, 'write')
    if (error) return error
    return c.json({ ok: true, spaceId })
  })

  app.post('/spaces/:spaceId/invite', async (c) => {
    const spaceId = c.req.param('spaceId')
    const error = await requireCapability(c, spaceId, 'invite')
    if (error) return error
    return c.json({ ok: true, spaceId })
  })

  app.delete('/spaces/:spaceId', async (c) => {
    const spaceId = c.req.param('spaceId')
    const error = await requireCapability(c, spaceId, 'admin')
    if (error) return error
    return c.json({ ok: true, spaceId })
  })

  // Mixed endpoint: accepts both auth types
  app.get('/mixed', (c) => {
    const didAuth = c.get('didAuth')
    const ucan = c.get('ucan')
    return c.json({
      authType: didAuth ? 'did' : ucan ? 'ucan' : 'none',
      did: didAuth?.did ?? null,
      issuerDid: ucan?.issuerDid ?? null,
    })
  })

  return app
}

// ============================================
// 1. Space creation requires DID-Auth, rejects UCAN
// ============================================

describe('Space creation requires DID-Auth', () => {
  test('DID-Auth request succeeds for space creation', async () => {
    const app = createDispatcherApp()
    const id = await makeIdentity()
    const body = JSON.stringify({ name: 'my-space' })
    const header = await createDidAuthHeader(id.keyPair.privateKey, id.did, 'create-space', body)

    const res = await app.request('/spaces', {
      method: 'POST',
      headers: { Authorization: header, 'Content-Type': 'application/json' },
      body,
    })
    expect(res.status).toBe(200)
    const json = (await res.json()) as any
    expect(json.ok).toBe(true)
    expect(json.did).toBe(id.did)
  })

  test('UCAN request returns 401 for DID-Auth-only endpoint', async () => {
    const app = createDispatcherApp()
    const id = await makeIdentity()
    const spaceId = crypto.randomUUID()
    const header = await createUcanHeader(id, spaceId, 'space/admin')

    const res = await app.request('/spaces', {
      method: 'POST',
      headers: { Authorization: header, 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'my-space' }),
    })
    // Route handler checks c.get('didAuth') which is null for UCAN auth
    expect(res.status).toBe(401)
    const json = (await res.json()) as any
    expect(json.error).toContain('DID-Auth required')
  })
})

// ============================================
// 2. Space operations require UCAN, correct capability enforced
// ============================================

describe('Space operations require UCAN with correct capability', () => {
  test('space/read cannot satisfy space/write requirement', async () => {
    const app = createDispatcherApp()
    const id = await makeIdentity()
    const spaceId = crypto.randomUUID()
    const header = await createUcanHeader(id, spaceId, 'space/read')
    mockSpaceOwnerDid = id.did

    const res = await app.request(`/spaces/${spaceId}`, {
      method: 'PUT',
      headers: { Authorization: header },
    })
    expect(res.status).toBe(403)
  })

  test('space/write satisfies space/write requirement', async () => {
    const app = createDispatcherApp()
    const id = await makeIdentity()
    const spaceId = crypto.randomUUID()
    const header = await createUcanHeader(id, spaceId, 'space/write')
    mockSpaceOwnerDid = id.did

    const res = await app.request(`/spaces/${spaceId}`, {
      method: 'PUT',
      headers: { Authorization: header },
    })
    expect(res.status).toBe(200)
    const json = (await res.json()) as any
    expect(json.ok).toBe(true)
  })

  test('UCAN for wrong spaceId is rejected', async () => {
    const app = createDispatcherApp()
    const id = await makeIdentity()
    const ownedSpace = crypto.randomUUID()
    const targetSpace = crypto.randomUUID()
    const header = await createUcanHeader(id, ownedSpace, 'space/admin')

    const res = await app.request(`/spaces/${targetSpace}`, {
      method: 'GET',
      headers: { Authorization: header },
    })
    expect(res.status).toBe(403)
  })
})

// ============================================
// 3. Mixed auth: dispatcher correctly routes both schemes
// ============================================

describe('Mixed auth dispatching', () => {
  test('DID request populates didAuth context', async () => {
    const app = createDispatcherApp()
    const id = await makeIdentity()
    const header = await createDidAuthHeader(id.keyPair.privateKey, id.did, 'read')

    const res = await app.request('/mixed', {
      headers: { Authorization: header },
    })
    expect(res.status).toBe(200)
    const json = (await res.json()) as any
    expect(json.authType).toBe('did')
    expect(json.did).toBe(id.did)
    expect(json.issuerDid).toBeNull()
  })

  test('UCAN request populates ucan context', async () => {
    const app = createDispatcherApp()
    const id = await makeIdentity()
    const spaceId = crypto.randomUUID()
    const header = await createUcanHeader(id, spaceId, 'space/read')

    const res = await app.request('/mixed', {
      headers: { Authorization: header },
    })
    expect(res.status).toBe(200)
    const json = (await res.json()) as any
    expect(json.authType).toBe('ucan')
    expect(json.issuerDid).toBe(id.did)
    expect(json.did).toBeNull()
  })
})

// ============================================
// 4. Attack: JWT Bearer scheme rejected everywhere
// ============================================

describe('Attack: Bearer scheme rejected', () => {
  test('Bearer token is rejected by auth dispatcher', async () => {
    const app = createDispatcherApp()

    const res = await app.request('/spaces', {
      method: 'POST',
      headers: { Authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.fake' },
      body: '{}',
    })
    expect(res.status).toBe(401)
    const json = (await res.json()) as any
    expect(json.error).toContain('Unsupported')
  })

  test('Bearer token is rejected on UCAN-protected routes', async () => {
    const app = createDispatcherApp()
    const spaceId = crypto.randomUUID()

    const res = await app.request(`/spaces/${spaceId}`, {
      headers: { Authorization: 'Bearer some-jwt-token' },
    })
    expect(res.status).toBe(401)
  })
})

// ============================================
// 5. Attack: cross-space UCAN (space A token for space B)
// ============================================

describe('Attack: cross-space UCAN', () => {
  test('UCAN for space A cannot access space B', async () => {
    const app = createDispatcherApp()
    const id = await makeIdentity()
    const spaceA = crypto.randomUUID()
    const spaceB = crypto.randomUUID()

    const header = await createUcanHeader(id, spaceA, 'space/admin')

    // Try to read space B with space A's token
    const res = await app.request(`/spaces/${spaceB}`, {
      method: 'GET',
      headers: { Authorization: header },
    })
    expect(res.status).toBe(403)
    const json = (await res.json()) as any
    expect(json.error).toContain('Insufficient capability')
  })

  test('UCAN for space A cannot write to space B', async () => {
    const app = createDispatcherApp()
    const id = await makeIdentity()
    const spaceA = crypto.randomUUID()
    const spaceB = crypto.randomUUID()

    const header = await createUcanHeader(id, spaceA, 'space/admin')

    const res = await app.request(`/spaces/${spaceB}`, {
      method: 'PUT',
      headers: { Authorization: header },
    })
    expect(res.status).toBe(403)
  })

  test('UCAN for space A cannot delete space B', async () => {
    const app = createDispatcherApp()
    const id = await makeIdentity()
    const spaceA = crypto.randomUUID()
    const spaceB = crypto.randomUUID()

    const header = await createUcanHeader(id, spaceA, 'space/admin')

    const res = await app.request(`/spaces/${spaceB}`, {
      method: 'DELETE',
      headers: { Authorization: header },
    })
    expect(res.status).toBe(403)
  })
})

// ============================================
// 6. Attack: DID-Auth with body tampering
// ============================================

describe('Attack: DID-Auth body tampering', () => {
  test('signed body A, sent body B is rejected', async () => {
    const app = createDispatcherApp()
    const id = await makeIdentity()

    const originalBody = JSON.stringify({ name: 'safe-space' })
    const tamperedBody = JSON.stringify({ name: 'safe-space', role: 'admin', steal: true })

    const header = await createDidAuthHeader(
      id.keyPair.privateKey,
      id.did,
      'create-space',
      originalBody,
    )

    const res = await app.request('/spaces', {
      method: 'POST',
      headers: { Authorization: header, 'Content-Type': 'application/json' },
      body: tamperedBody,
    })
    expect(res.status).toBe(401)
    const json = (await res.json()) as any
    expect(json.error).toContain('body')
  })

  test('empty body signed, non-empty body sent is rejected', async () => {
    const app = createDispatcherApp()
    const id = await makeIdentity()

    const header = await createDidAuthHeader(id.keyPair.privateKey, id.did, 'create-space', '')

    const res = await app.request('/spaces', {
      method: 'POST',
      headers: { Authorization: header, 'Content-Type': 'application/json' },
      body: '{"injected":"payload"}',
    })
    expect(res.status).toBe(401)
  })
})

// ============================================
// 7. Attack: expired UCAN with valid delegation chain
// ============================================

describe('Attack: expired UCAN', () => {
  test('expired UCAN is rejected even with valid signature', async () => {
    const app = createDispatcherApp()
    const id = await makeIdentity()
    const spaceId = crypto.randomUUID()

    const header = await createUcanHeader(id, spaceId, 'space/admin', {
      expiration: Math.floor(Date.now() / 1000) - 60, // expired 60s ago
    })

    const res = await app.request(`/spaces/${spaceId}`, {
      method: 'GET',
      headers: { Authorization: header },
    })
    expect(res.status).toBe(401)
    const json = (await res.json()) as any
    expect(json.error).toContain('expired')
  })

  test('expired UCAN with delegation chain is rejected', async () => {
    const app = createDispatcherApp()
    const admin = await makeIdentity()
    const member = await makeIdentity()
    const spaceId = crypto.randomUUID()

    // Admin delegates to member (valid)
    const delegationToken = await createUcan(
      {
        issuer: admin.did,
        audience: member.did,
        capabilities: { [spaceResource(spaceId)]: spaceCapabilitySet().write(true).build() },
        expiration: Math.floor(Date.now() / 1000) + 3600,
        proofs: [],
      },
      admin.sign,
    )

    // Member creates expired token with valid proof
    const expiredToken = await createUcan(
      {
        issuer: member.did,
        audience: member.did,
        capabilities: { [spaceResource(spaceId)]: spaceCapabilitySet().write(true).build() },
        expiration: Math.floor(Date.now() / 1000) - 10, // expired
        proofs: [delegationToken],
      },
      member.sign,
    )

    const res = await app.request(`/spaces/${spaceId}`, {
      method: 'PUT',
      headers: { Authorization: `UCAN ${expiredToken}` },
    })
    expect(res.status).toBe(401)
  })
})

// ============================================
// 8. Capability hierarchy respected
// ============================================

describe('Orthogonal capabilities', () => {
  // Each route requires its exact capability; no cap implies another.

  test('space/admin does not satisfy space/write', async () => {
    const app = createDispatcherApp()
    const id = await makeIdentity()
    const spaceId = crypto.randomUUID()
    const header = await createUcanHeader(id, spaceId, 'space/admin')
    mockSpaceOwnerDid = id.did

    const res = await app.request(`/spaces/${spaceId}`, {
      method: 'PUT',
      headers: { Authorization: header },
    })
    expect(res.status).toBe(403)
  })

  test('space/admin does not satisfy space/read', async () => {
    const app = createDispatcherApp()
    const id = await makeIdentity()
    const spaceId = crypto.randomUUID()
    const header = await createUcanHeader(id, spaceId, 'space/admin')
    mockSpaceOwnerDid = id.did

    const res = await app.request(`/spaces/${spaceId}`, {
      method: 'GET',
      headers: { Authorization: header },
    })
    expect(res.status).toBe(403)
  })

  test('space/admin does not satisfy space/invite', async () => {
    const app = createDispatcherApp()
    const id = await makeIdentity()
    const spaceId = crypto.randomUUID()
    const header = await createUcanHeader(id, spaceId, 'space/admin')
    mockSpaceOwnerDid = id.did

    const res = await app.request(`/spaces/${spaceId}/invite`, {
      method: 'POST',
      headers: { Authorization: header },
    })
    expect(res.status).toBe(403)
  })

  test('space/admin satisfies space/admin', async () => {
    const app = createDispatcherApp()
    const id = await makeIdentity()
    const spaceId = crypto.randomUUID()
    const header = await createUcanHeader(id, spaceId, 'space/admin')
    mockSpaceOwnerDid = id.did

    const res = await app.request(`/spaces/${spaceId}`, {
      method: 'DELETE',
      headers: { Authorization: header },
    })
    expect(res.status).toBe(200)
  })

  test('space/write does not satisfy space/read', async () => {
    const app = createDispatcherApp()
    const id = await makeIdentity()
    const spaceId = crypto.randomUUID()
    const header = await createUcanHeader(id, spaceId, 'space/write')
    mockSpaceOwnerDid = id.did

    const res = await app.request(`/spaces/${spaceId}`, {
      method: 'GET',
      headers: { Authorization: header },
    })
    expect(res.status).toBe(403)
  })

  test('space/write does NOT satisfy space/invite', async () => {
    const app = createDispatcherApp()
    const id = await makeIdentity()
    const spaceId = crypto.randomUUID()
    const header = await createUcanHeader(id, spaceId, 'space/write')
    mockSpaceOwnerDid = id.did

    const res = await app.request(`/spaces/${spaceId}/invite`, {
      method: 'POST',
      headers: { Authorization: header },
    })
    expect(res.status).toBe(403)
  })

  test('space/write does NOT satisfy space/admin', async () => {
    const app = createDispatcherApp()
    const id = await makeIdentity()
    const spaceId = crypto.randomUUID()
    const header = await createUcanHeader(id, spaceId, 'space/write')
    mockSpaceOwnerDid = id.did

    const res = await app.request(`/spaces/${spaceId}`, {
      method: 'DELETE',
      headers: { Authorization: header },
    })
    expect(res.status).toBe(403)
  })

  test('space/read does NOT satisfy space/write', async () => {
    const app = createDispatcherApp()
    const id = await makeIdentity()
    const spaceId = crypto.randomUUID()
    const header = await createUcanHeader(id, spaceId, 'space/read')
    mockSpaceOwnerDid = id.did

    const res = await app.request(`/spaces/${spaceId}`, {
      method: 'PUT',
      headers: { Authorization: header },
    })
    expect(res.status).toBe(403)
  })

  test('space/read does NOT satisfy space/invite', async () => {
    const app = createDispatcherApp()
    const id = await makeIdentity()
    const spaceId = crypto.randomUUID()
    const header = await createUcanHeader(id, spaceId, 'space/read')
    mockSpaceOwnerDid = id.did

    const res = await app.request(`/spaces/${spaceId}/invite`, {
      method: 'POST',
      headers: { Authorization: header },
    })
    expect(res.status).toBe(403)
  })

  test('space/read does NOT satisfy space/admin', async () => {
    const app = createDispatcherApp()
    const id = await makeIdentity()
    const spaceId = crypto.randomUUID()
    const header = await createUcanHeader(id, spaceId, 'space/read')
    mockSpaceOwnerDid = id.did

    const res = await app.request(`/spaces/${spaceId}`, {
      method: 'DELETE',
      headers: { Authorization: header },
    })
    expect(res.status).toBe(403)
  })

  test('space/invite does not satisfy space/write', async () => {
    const app = createDispatcherApp()
    const id = await makeIdentity()
    const spaceId = crypto.randomUUID()
    const header = await createUcanHeader(id, spaceId, 'space/invite')
    mockSpaceOwnerDid = id.did

    const res = await app.request(`/spaces/${spaceId}`, {
      method: 'PUT',
      headers: { Authorization: header },
    })
    expect(res.status).toBe(403)
  })

  test('space/invite does not satisfy space/read', async () => {
    const app = createDispatcherApp()
    const id = await makeIdentity()
    const spaceId = crypto.randomUUID()
    const header = await createUcanHeader(id, spaceId, 'space/invite')
    mockSpaceOwnerDid = id.did

    const res = await app.request(`/spaces/${spaceId}`, {
      method: 'GET',
      headers: { Authorization: header },
    })
    expect(res.status).toBe(403)
  })

  test('space/invite does NOT satisfy space/admin', async () => {
    const app = createDispatcherApp()
    const id = await makeIdentity()
    const spaceId = crypto.randomUUID()
    const header = await createUcanHeader(id, spaceId, 'space/invite')
    mockSpaceOwnerDid = id.did

    const res = await app.request(`/spaces/${spaceId}`, {
      method: 'DELETE',
      headers: { Authorization: header },
    })
    expect(res.status).toBe(403)
  })
})
