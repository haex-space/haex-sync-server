import { describe, test, expect } from 'bun:test'
import { Hono } from 'hono'
import { didAuthMiddleware } from '../../src/middleware/didAuth'

// --- Test Helpers ---

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

function base58btcEncode(bytes: Uint8Array): string {
  // Count leading zeros
  let leadingZeros = 0
  for (const b of bytes) {
    if (b !== 0) break
    leadingZeros++
  }

  // Convert bytes to a big integer
  let num = 0n
  for (const b of bytes) {
    num = num * 256n + BigInt(b)
  }

  // Convert to base58
  let result = ''
  while (num > 0n) {
    const remainder = Number(num % 58n)
    num = num / 58n
    result = BASE58_ALPHABET[remainder] + result
  }

  // Add leading '1's for leading zeros
  return '1'.repeat(leadingZeros) + result
}

function base64urlEncode(data: string | Uint8Array): string {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data
  const base64 = btoa(String.fromCharCode(...bytes))
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function generateEd25519Keypair() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify']
  ) as CryptoKeyPair

  // Export raw public key (32 bytes)
  const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey))

  // Build did:key: multicodec prefix [0xed, 0x01] + 32-byte pubkey, base58btc, prefix "did:key:z"
  const multicodecBytes = new Uint8Array(2 + rawPublicKey.length)
  multicodecBytes[0] = 0xed
  multicodecBytes[1] = 0x01
  multicodecBytes.set(rawPublicKey, 2)
  const did = `did:key:z${base58btcEncode(multicodecBytes)}`

  return { keyPair, did, rawPublicKey }
}

async function createDidAuthHeader(
  privateKey: CryptoKey,
  did: string,
  action: string,
  body?: string
): Promise<string> {
  const bodyBytes = new TextEncoder().encode(body ?? '')
  const bodyHashBuffer = await crypto.subtle.digest('SHA-256', bodyBytes)
  const bodyHash = base64urlEncode(new Uint8Array(bodyHashBuffer))

  const payload = JSON.stringify({
    did,
    action,
    timestamp: Date.now(),
    bodyHash,
  })

  const payloadEncoded = base64urlEncode(payload)
  const payloadBytes = new TextEncoder().encode(payloadEncoded)
  const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', privateKey, payloadBytes))
  const signatureEncoded = base64urlEncode(signature)

  return `DID ${payloadEncoded}.${signatureEncoded}`
}

function createTestApp() {
  const app = new Hono()
  app.use('*', didAuthMiddleware)
  app.post('/test', (c) => {
    const didAuth = c.get('didAuth')
    return c.json({ ok: true, didAuth })
  })
  app.get('/test', (c) => {
    const didAuth = c.get('didAuth')
    return c.json({ ok: true, didAuth })
  })
  return app
}

// --- Tests ---

describe('DID-Auth Middleware', () => {
  test('rejects missing Authorization header', async () => {
    const app = createTestApp()
    const res = await app.request('/test', { method: 'POST', body: '' })
    expect(res.status).toBe(401)
    const json = await res.json()
    expect(json.error).toContain('Missing')
  })

  test('rejects wrong auth scheme (Bearer)', async () => {
    const app = createTestApp()
    const res = await app.request('/test', {
      method: 'POST',
      headers: { Authorization: 'Bearer sometoken' },
      body: '',
    })
    expect(res.status).toBe(401)
    const json = await res.json()
    expect(json.error).toContain('DID')
  })

  test('rejects expired timestamp (60 seconds old)', async () => {
    const app = createTestApp()
    const { keyPair, did } = await generateEd25519Keypair()
    const body = ''

    // Build an auth header with a stale timestamp
    const bodyBytes = new TextEncoder().encode(body)
    const bodyHashBuffer = await crypto.subtle.digest('SHA-256', bodyBytes)
    const bodyHash = base64urlEncode(new Uint8Array(bodyHashBuffer))

    const payload = JSON.stringify({
      did,
      action: 'test',
      timestamp: Date.now() - 60_000, // 60 seconds ago
      bodyHash,
    })

    const payloadEncoded = base64urlEncode(payload)
    const payloadBytes = new TextEncoder().encode(payloadEncoded)
    const signature = new Uint8Array(
      await crypto.subtle.sign('Ed25519', keyPair.privateKey, payloadBytes)
    )
    const signatureEncoded = base64urlEncode(signature)

    const res = await app.request('/test', {
      method: 'POST',
      headers: { Authorization: `DID ${payloadEncoded}.${signatureEncoded}` },
      body,
    })
    expect(res.status).toBe(401)
    const json = await res.json()
    expect(json.error).toContain('expired')
  })

  test('rejects invalid signature (signed with wrong key)', async () => {
    const app = createTestApp()
    const { did } = await generateEd25519Keypair()
    const { keyPair: wrongKeyPair } = await generateEd25519Keypair()
    const body = 'some body'

    // Sign with wrong key but use DID from first keypair
    const authHeader = await createDidAuthHeader(
      wrongKeyPair.privateKey,
      did,
      'test',
      body
    )

    const res = await app.request('/test', {
      method: 'POST',
      headers: { Authorization: authHeader },
      body,
    })
    expect(res.status).toBe(401)
    const json = await res.json()
    expect(json.error).toContain('signature')
  })

  test('rejects wrong body hash', async () => {
    const app = createTestApp()
    const { keyPair, did } = await generateEd25519Keypair()

    // Create header with one body, send a different body
    const authHeader = await createDidAuthHeader(
      keyPair.privateKey,
      did,
      'test',
      'original body'
    )

    const res = await app.request('/test', {
      method: 'POST',
      headers: { Authorization: authHeader },
      body: 'tampered body',
    })
    expect(res.status).toBe(401)
    const json = await res.json()
    expect(json.error).toContain('body')
  })

  test('accepts valid DID-signed request', async () => {
    const app = createTestApp()
    const { keyPair, did, rawPublicKey } = await generateEd25519Keypair()
    const body = JSON.stringify({ hello: 'world' })

    const authHeader = await createDidAuthHeader(
      keyPair.privateKey,
      did,
      'sync',
      body
    )

    const res = await app.request('/test', {
      method: 'POST',
      headers: {
        Authorization: authHeader,
        'Content-Type': 'application/json',
      },
      body,
    })
    expect(res.status).toBe(200)
    const json = await res.json()
    expect(json.ok).toBe(true)
    expect(json.didAuth).toBeTruthy()
    expect(json.didAuth.did).toBe(did)
    expect(json.didAuth.action).toBe('sync')
    expect(json.didAuth.userId).toBe('')
    expect(json.didAuth.tier).toBe('')

    // Verify publicKey is hex-encoded
    const expectedHex = Array.from(rawPublicKey).map(b => b.toString(16).padStart(2, '0')).join('')
    expect(json.didAuth.publicKey).toBe(expectedHex)
  })

  test('accepts valid GET request with empty body', async () => {
    const app = createTestApp()
    const { keyPair, did } = await generateEd25519Keypair()

    const authHeader = await createDidAuthHeader(
      keyPair.privateKey,
      did,
      'read',
      undefined
    )

    const res = await app.request('/test', {
      method: 'GET',
      headers: { Authorization: authHeader },
    })
    expect(res.status).toBe(200)
    const json = await res.json()
    expect(json.didAuth.did).toBe(did)
    expect(json.didAuth.action).toBe('read')
  })
})
