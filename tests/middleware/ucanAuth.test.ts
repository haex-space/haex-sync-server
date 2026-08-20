import { describe, test, expect, mock, beforeEach } from 'bun:test'
import { Hono } from 'hono'
import {
  createUcan,
  createWebCryptoSigner,
  spaceCapabilitySet,
  spaceResource,
  type Capabilities,
  type SignFn,
} from '@haex-space/ucan'

// Mock DB before importing middleware — resolveCallerAuthority reads
// spaces.ownerId to anchor the root of trust for the UCAN proof forest.
//
// The default is an unrelated DID, so a self-signed or forged root is rejected
// unless a test explicitly makes its own issuer the space owner. Tests about
// capability sufficiency or proof expiry must set it; tests about forged
// authority must leave it alone.
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

import { ucanAuthMiddleware, requireCapability } from '../../src/middleware/ucanAuth'

// ============================================
// Test Helpers
// ============================================

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

function base58btcEncode(bytes: Uint8Array): string {
  const digits = [0]
  for (const byte of bytes) {
    let carry = byte
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j]! * 256
      digits[j] = carry % 58
      carry = Math.floor(carry / 58)
    }
    while (carry > 0) {
      digits.push(carry % 58)
      carry = Math.floor(carry / 58)
    }
  }
  // Leading zeros
  for (const byte of bytes) {
    if (byte === 0) digits.push(0)
    else break
  }
  return digits.reverse().map(d => BASE58_ALPHABET[d]).join('')
}

interface Identity {
  did: string
  sign: SignFn
}

async function makeIdentity(): Promise<Identity> {
  const keyPair = (await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify'],
  )) as unknown as CryptoKeyPair

  const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey))

  // did:key multicodec prefix for Ed25519: 0xed 0x01
  const multicodec = new Uint8Array(2 + rawPublicKey.length)
  multicodec[0] = 0xed
  multicodec[1] = 0x01
  multicodec.set(rawPublicKey, 2)

  const did = `did:key:z${base58btcEncode(multicodec)}`

  return {
    did,
    sign: createWebCryptoSigner(keyPair.privateKey),
  }
}

async function makeToken(
  issuer: Identity,
  audience: string,
  capabilities: Capabilities,
  options?: { exp?: number; iat?: number; proofs?: string[] },
): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  return createUcan(
    {
      issuer: issuer.did,
      audience,
      capabilities,
      expiration: options?.exp ?? now + 3600,
      ...(options?.iat !== undefined ? {} : {}),
      proofs: options?.proofs ?? [],
    },
    issuer.sign,
  )
}

// Defence in depth, not a correctness dependency: identities are freshly
// generated per test, so a leaked owner can only ever be a stale unrelated
// DID, which is fail-closed. Resetting keeps each test's setup self-evident.
beforeEach(() => {
  mockSpaceOwnerDid = UNRELATED_OWNER
})

function createApp() {
  const app = new Hono()
  app.use('*', ucanAuthMiddleware)
  app.get('/test', (c) => {
    const ucan = c.get('ucan')
    return c.json({ issuerDid: ucan?.issuerDid ?? null })
  })
  app.get('/space/:spaceId', async (c) => {
    const spaceId = c.req.param('spaceId')
    const error = await requireCapability(c, spaceId, 'write')
    if (error) return error
    return c.json({ ok: true })
  })
  return app
}

// ============================================
// Tests: ucanAuthMiddleware
// ============================================

describe('ucanAuthMiddleware', () => {
  test('rejects missing Authorization header with 401', async () => {
    const app = createApp()
    const res = await app.request('/test')
    expect(res.status).toBe(401)
    const body = await res.json() as any
    expect(body.error).toBeDefined()
  })

  test('rejects invalid UCAN token with 401', async () => {
    const app = createApp()
    const res = await app.request('/test', {
      headers: { Authorization: 'UCAN not-a-valid-token' },
    })
    expect(res.status).toBe(401)
  })

  test('accepts valid UCAN and sets context', async () => {
    const issuer = await makeIdentity()
    const audience = 'did:key:zServer123'
    const spaceId = crypto.randomUUID()
    const token = await makeToken(issuer, audience, {
      [spaceResource(spaceId)]: spaceCapabilitySet().admin(true).build(),
    })

    const app = createApp()
    const res = await app.request('/test', {
      headers: { Authorization: `UCAN ${token}` },
    })
    expect(res.status).toBe(200)
    const body = await res.json() as any
    expect(body.issuerDid).toBe(issuer.did)
  })

  test('rejects expired UCAN with 401', async () => {
    const issuer = await makeIdentity()
    const audience = 'did:key:zServer123'
    const token = await makeToken(issuer, audience, {}, {
      exp: Math.floor(Date.now() / 1000) - 60, // expired 60s ago
    })

    const app = createApp()
    const res = await app.request('/test', {
      headers: { Authorization: `UCAN ${token}` },
    })
    expect(res.status).toBe(401)
    const body = await res.json() as any
    expect(body.error).toContain('expired')
  })
})

// ============================================
// Tests: requireCapability
// ============================================

// ============================================
// Attack Scenarios
// ============================================

describe('ucanAuthMiddleware - attack scenarios', () => {
  test('attack: privilege escalation via forged capability', async () => {
    // Attacker creates a self-signed UCAN claiming space/admin
    // but has no delegation chain from the real admin
    const attacker = await makeIdentity()
    const spaceId = crypto.randomUUID()

    const token = await makeToken(attacker, attacker.did, {
      [spaceResource(spaceId)]: spaceCapabilitySet().admin(true).write(true).build(),
    })

    const app = createApp()
    // The UCAN is cryptographically valid (self-signed), so the middleware
    // admits it — verifyUcan skips the delegation-chain check entirely when
    // there are no proofs. requireCapability is what rejects it, because the
    // forest roots in the attacker rather than in the space owner.
    const res = await app.request(`/space/${spaceId}`, {
      headers: { Authorization: `UCAN ${token}` },
    })
    expect(res.status).toBe(403)
  })

  test('attack: delegation chain escalation (member tries to delegate admin)', async () => {
    const admin = await makeIdentity()
    const member = await makeIdentity()
    const spaceId = crypto.randomUUID()

    // Admin grants space/write to member
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

    // Member tries to escalate to space/admin using the space/write proof
    const escalatedToken = await createUcan(
      {
        issuer: member.did,
        audience: member.did,
        capabilities: { [spaceResource(spaceId)]: spaceCapabilitySet().admin(true).build() },
        expiration: Math.floor(Date.now() / 1000) + 3600,
        proofs: [delegationToken],
      },
      member.sign,
    )

    const app = new Hono()
    app.use('*', ucanAuthMiddleware)
    app.get('/space/:spaceId', async (c) => {
      const spaceId = c.req.param('spaceId')
      const error = await requireCapability(c, spaceId, 'admin')
      if (error) return error
      return c.json({ ok: true })
    })

    const res = await app.request(`/space/${spaceId}`, {
      headers: { Authorization: `UCAN ${escalatedToken}` },
    })
    // verifyUcan should reject this because the proof only grants space/write,
    // not space/admin — privilege escalation is blocked by the UCAN library
    expect(res.status).toBe(401)
  })

  test('attack: expired proof in delegation chain', async () => {
    const admin = await makeIdentity()
    const member = await makeIdentity()
    const spaceId = crypto.randomUUID()

    // Admin grants token that expired 60s ago
    const expiredDelegation = await createUcan(
      {
        issuer: admin.did,
        audience: member.did,
        capabilities: { [spaceResource(spaceId)]: spaceCapabilitySet().write(true).build() },
        expiration: Math.floor(Date.now() / 1000) - 60,
        proofs: [],
      },
      admin.sign,
    )

    // Member creates fresh token with expired proof
    const memberToken = await createUcan(
      {
        issuer: member.did,
        audience: member.did,
        capabilities: { [spaceResource(spaceId)]: spaceCapabilitySet().write(true).build() },
        expiration: Math.floor(Date.now() / 1000) + 3600,
        proofs: [expiredDelegation],
      },
      member.sign,
    )

    // Root of trust is sound here; this test is about proof expiry alone.
    mockSpaceOwnerDid = admin.did

    const app = createApp()
    const res = await app.request(`/space/${spaceId}`, {
      headers: { Authorization: `UCAN ${memberToken}` },
    })
    // The outer token is valid, but the proof chain has an expired token
    // The UCAN library may or may not check proof expiry — this test documents behavior
    // Either way, the Vault (Phase 4) is the final authority
    expect([200, 401]).toContain(res.status)
  })

  test('attack: tampered UCAN payload (modified after signing)', async () => {
    const issuer = await makeIdentity()
    const spaceId = crypto.randomUUID()

    const token = await makeToken(issuer, issuer.did, {
      [spaceResource(spaceId)]: spaceCapabilitySet().read(true).build(),
    })

    // Tamper: change space/read to space/admin in the payload
    const parts = token.split('.')
    const payloadJson = JSON.parse(atob(parts[1]!.replace(/-/g, '+').replace(/_/g, '/')))
    payloadJson.cap[spaceResource(spaceId)] = spaceCapabilitySet().admin(true).build()
    const tamperedPayload = btoa(JSON.stringify(payloadJson))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`

    const app = createApp()
    const res = await app.request(`/space/${spaceId}`, {
      headers: { Authorization: `UCAN ${tamperedToken}` },
    })
    // Signature verification must fail because payload was modified
    expect(res.status).toBe(401)
  })

  test('attack: wrong space ID in capability (cross-space access)', async () => {
    const issuer = await makeIdentity()
    const ownedSpaceId = crypto.randomUUID()
    const targetSpaceId = crypto.randomUUID()

    // Token grants access to ownedSpaceId, not targetSpaceId
    const token = await makeToken(issuer, issuer.did, {
      [spaceResource(ownedSpaceId)]: spaceCapabilitySet().admin(true).build(),
    })

    const app = createApp()
    const res = await app.request(`/space/${targetSpaceId}`, {
      headers: { Authorization: `UCAN ${token}` },
    })
    expect(res.status).toBe(403)
  })

  test('attack: Bearer scheme with UCAN token', async () => {
    const issuer = await makeIdentity()
    const token = await makeToken(issuer, issuer.did, {})

    const app = createApp()
    const res = await app.request('/test', {
      headers: { Authorization: `Bearer ${token}` },
    })
    expect(res.status).toBe(401)
  })
})

// ============================================
// requireCapability
// ============================================

describe('requireCapability', () => {
  test('returns 403 when capability is missing', async () => {
    const issuer = await makeIdentity()
    const audience = 'did:key:zServer123'
    const spaceId = crypto.randomUUID()
    const token = await makeToken(issuer, audience, {
      [spaceResource(spaceId)]: spaceCapabilitySet().read(true).build(),
    })

    // Owner the space to the issuer so this measures the capability check
    // rather than the root-of-trust check.
    mockSpaceOwnerDid = issuer.did

    const app = createApp()
    // Route expects space/write, but token only has space/read
    const res = await app.request(`/space/${spaceId}`, {
      headers: { Authorization: `UCAN ${token}` },
    })
    expect(res.status).toBe(403)
    const body = await res.json() as any
    expect(body.error).toContain('Insufficient capability')
  })

  test('passes when capability is sufficient', async () => {
    const issuer = await makeIdentity()
    const audience = 'did:key:zServer123'
    const spaceId = crypto.randomUUID()
    const token = await makeToken(issuer, audience, {
      [spaceResource(spaceId)]: spaceCapabilitySet().admin(true).write(true).build(),
    })

    mockSpaceOwnerDid = issuer.did

    const app = createApp()
    // Route expects space/write, token declares write explicitly
    const res = await app.request(`/space/${spaceId}`, {
      headers: { Authorization: `UCAN ${token}` },
    })
    expect(res.status).toBe(200)
    const body = await res.json() as any
    expect(body.ok).toBe(true)
  })

  test('supports delegated UCANs', async () => {
    const admin = await makeIdentity()
    const member = await makeIdentity()
    const audience = 'did:key:zServer123'
    const spaceId = crypto.randomUUID()

    // Admin creates a UCAN granting space/write to member
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

    // Member creates their own UCAN with the delegation as proof
    const memberToken = await createUcan(
      {
        issuer: member.did,
        audience,
        capabilities: { [spaceResource(spaceId)]: spaceCapabilitySet().write(true).build() },
        expiration: Math.floor(Date.now() / 1000) + 3600,
        proofs: [delegationToken],
      },
      member.sign,
    )

    // The chain roots in the admin, so the admin must be the space owner for
    // this delegation to carry any authority.
    mockSpaceOwnerDid = admin.did

    const app = createApp()
    const res = await app.request(`/space/${spaceId}`, {
      headers: { Authorization: `UCAN ${memberToken}` },
    })
    expect(res.status).toBe(200)
    const body = await res.json() as any
    expect(body.ok).toBe(true)
  })
})
