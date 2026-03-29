import { describe, test, expect } from 'bun:test'
import { Hono } from 'hono'
import {
  createUcan,
  createWebCryptoSigner,
  createWebCryptoVerifier,
  spaceResource,
  type Capability,
  type Capabilities,
  type SignFn,
} from '@haex-space/ucan'
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
  const keyPair = await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair

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

function createApp() {
  const app = new Hono()
  app.use('*', ucanAuthMiddleware)
  app.get('/test', (c) => {
    const ucan = c.get('ucan')
    return c.json({ issuerDid: ucan?.issuerDid ?? null })
  })
  app.get('/space/:spaceId', (c) => {
    const spaceId = c.req.param('spaceId')
    const error = requireCapability(c, spaceId, 'space/write')
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
    const body = await res.json()
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
      [spaceResource(spaceId)]: 'space/admin',
    })

    const app = createApp()
    const res = await app.request('/test', {
      headers: { Authorization: `UCAN ${token}` },
    })
    expect(res.status).toBe(200)
    const body = await res.json()
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
    const body = await res.json()
    expect(body.error).toContain('expired')
  })
})

// ============================================
// Tests: requireCapability
// ============================================

describe('requireCapability', () => {
  test('returns 403 when capability is missing', async () => {
    const issuer = await makeIdentity()
    const audience = 'did:key:zServer123'
    const spaceId = crypto.randomUUID()
    const token = await makeToken(issuer, audience, {
      [spaceResource(spaceId)]: 'space/read',
    })

    const app = createApp()
    // Route expects space/write, but token only has space/read
    const res = await app.request(`/space/${spaceId}`, {
      headers: { Authorization: `UCAN ${token}` },
    })
    expect(res.status).toBe(403)
    const body = await res.json()
    expect(body.error).toBeDefined()
  })

  test('passes when capability is sufficient', async () => {
    const issuer = await makeIdentity()
    const audience = 'did:key:zServer123'
    const spaceId = crypto.randomUUID()
    const token = await makeToken(issuer, audience, {
      [spaceResource(spaceId)]: 'space/admin',
    })

    const app = createApp()
    // Route expects space/write, token has space/admin (sufficient)
    const res = await app.request(`/space/${spaceId}`, {
      headers: { Authorization: `UCAN ${token}` },
    })
    expect(res.status).toBe(200)
    const body = await res.json()
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
        capabilities: { [spaceResource(spaceId)]: 'space/write' },
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
        capabilities: { [spaceResource(spaceId)]: 'space/write' },
        expiration: Math.floor(Date.now() / 1000) + 3600,
        proofs: [delegationToken],
      },
      member.sign,
    )

    const app = createApp()
    const res = await app.request(`/space/${spaceId}`, {
      headers: { Authorization: `UCAN ${memberToken}` },
    })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.ok).toBe(true)
  })
})
