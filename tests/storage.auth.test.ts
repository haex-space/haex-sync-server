/**
 * Tests for the storage DID-Auth body-hash verification (fix 1.2).
 *
 * Runs the REAL storageAuthMiddleware against a tiny Hono app that simply
 * reports success if the middleware calls next(). The only external
 * dependency that is stubbed is the identity resolution query against the
 * database — everything cryptographic (hash computation, Ed25519 verify) is
 * executed end-to-end against WebCrypto.
 */

import { describe, test, expect, mock, beforeAll } from 'bun:test'
import { Hono } from 'hono'
import { buildDbMock } from './helpers/db-mock'

// ── Test helpers (base58btc / base64url) ───────────────────────────────

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

function base58btcEncode(bytes: Uint8Array): string {
  let leadingZeros = 0
  for (const b of bytes) {
    if (b !== 0) break
    leadingZeros++
  }
  let num = 0n
  for (const b of bytes) num = num * 256n + BigInt(b)
  let result = ''
  while (num > 0n) {
    const remainder = Number(num % 58n)
    num = num / 58n
    result = BASE58_ALPHABET[remainder] + result
  }
  return '1'.repeat(leadingZeros) + result
}

function base64urlEncode(data: string | Uint8Array): string {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

async function generateDidKeypair() {
  const keyPair = (await crypto.subtle.generateKey(
    { name: 'Ed25519' }, true, ['sign', 'verify'],
  )) as unknown as CryptoKeyPair
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey))
  const multicodec = new Uint8Array(2 + raw.length)
  multicodec[0] = 0xed
  multicodec[1] = 0x01
  multicodec.set(raw, 2)
  return {
    keyPair,
    did: `did:key:z${base58btcEncode(multicodec)}`,
  }
}

async function createStorageDidHeader(
  privateKey: CryptoKey,
  did: string,
  body: string,
  opts?: { tamperBodyHash?: boolean; omitBodyHash?: boolean; timestamp?: number },
): Promise<string> {
  const bodyBytes = new TextEncoder().encode(body)
  const hashBuf = await crypto.subtle.digest('SHA-256', bodyBytes)
  let bodyHash = base64urlEncode(new Uint8Array(hashBuf))
  if (opts?.tamperBodyHash) bodyHash = bodyHash.slice(0, -2) + 'AA'

  const payload: any = {
    did,
    action: 'storage-put',
    timestamp: opts?.timestamp ?? Date.now(),
  }
  if (!opts?.omitBodyHash) payload.bodyHash = bodyHash

  const payloadJson = JSON.stringify(payload)
  const payloadEncoded = base64urlEncode(payloadJson)
  const signature = new Uint8Array(
    await crypto.subtle.sign('Ed25519', privateKey, new TextEncoder().encode(payloadEncoded)),
  )
  return `DID ${payloadEncoded}.${base64urlEncode(signature)}`
}

// ── Mocks ───────────────────────────────────────────────────────────────

// Identity lookup is the only DB call made by the DID-Auth branch.
// Return a stable stub so we can focus on body-hash logic.
const MOCKED_USER_ID = '00000000-0000-4000-8000-000000000000'
mock.module('../src/db', () => {
  const chain: any = {
    from: () => chain,
    where: () => chain,
    limit: () => Promise.resolve([{ supabaseUserId: MOCKED_USER_ID }]),
  }
  return buildDbMock({ select: () => chain })
})

// We don't want ENV-required MinIO admin side-effects when the module loads.
mock.module('../src/services/minioAdmin', () => ({
  provisionUserStorage: async () => {},
}))

mock.module('../src/services/storageCredentials', () => ({
  getCredentialsByAccessKeyId: async () => null,
}))

let storageAuthMiddleware: (c: any, next: () => Promise<void>) => Promise<any>

beforeAll(async () => {
  ({ storageAuthMiddleware } = await import('../src/routes/storage'))
})

function buildApp() {
  const app = new Hono<{ Variables: { storageUser: { userId: string }; bufferedBody?: Uint8Array } }>()
  app.use('*', storageAuthMiddleware)
  // The DID-Auth middleware consumes the raw body to compute its hash and
  // stashes the bytes in context. Handlers must consume that buffer instead
  // of re-reading raw.body — this mirrors the real PUT handler in
  // storage.ts and proves the buffer is forwarded correctly.
  app.put('/s3/*', async (c) => {
    const buffered = c.get('bufferedBody')
    return c.json({
      ok: true,
      user: c.get('storageUser'),
      bodyLen: buffered?.byteLength ?? null,
    })
  })
  app.get('/s3/*', async (c) => c.json({ ok: true, user: c.get('storageUser') }))
  return app
}

// ── Tests ───────────────────────────────────────────────────────────────

describe('storage DID-Auth — body-hash verification (fix 1.2)', () => {
  test('rejects request without bodyHash in payload', async () => {
    const app = buildApp()
    const { keyPair, did } = await generateDidKeypair()
    const body = 'some body'
    const header = await createStorageDidHeader(keyPair.privateKey, did, body, { omitBodyHash: true })

    const res = await app.request('/s3/file.txt', {
      method: 'PUT',
      headers: { Authorization: header },
      body,
    })
    expect(res.status).toBe(401)
    const json = await res.json() as any
    expect(json.error).toMatch(/missing|bodyHash/i)
  })

  test('attack: body tampering — header was signed over original, client sends different body', async () => {
    const app = buildApp()
    const { keyPair, did } = await generateDidKeypair()
    const originalBody = JSON.stringify({ file: 'safe.txt', size: 10 })
    const maliciousBody = JSON.stringify({ file: '../../etc/passwd', size: 999999 })
    const header = await createStorageDidHeader(keyPair.privateKey, did, originalBody)

    const res = await app.request('/s3/safe.txt', {
      method: 'PUT',
      headers: { Authorization: header, 'Content-Type': 'application/json' },
      body: maliciousBody,
    })
    expect(res.status).toBe(401)
    const json = await res.json() as any
    expect(json.error).toMatch(/body|tampered/i)
  })

  test('attack: bodyHash is well-formed but does not match request body', async () => {
    const app = buildApp()
    const { keyPair, did } = await generateDidKeypair()
    const body = 'x'.repeat(128)
    // Generate a header whose bodyHash has been post-hoc tampered.
    const header = await createStorageDidHeader(keyPair.privateKey, did, body, { tamperBodyHash: true })

    const res = await app.request('/s3/file.bin', {
      method: 'PUT',
      headers: { Authorization: header },
      body,
    })
    // The hash mismatches, so even though the body is the real one, the
    // request is rejected — AND the signature would fail too because the
    // payload is different. Either failure is acceptable; both are 401.
    expect(res.status).toBe(401)
  })

  test('attack: signature-replay across different bodies', async () => {
    const app = buildApp()
    const { keyPair, did } = await generateDidKeypair()

    // Valid header for a 1-byte body.
    const headerForSmall = await createStorageDidHeader(keyPair.privateKey, did, 'x')

    // Attacker replays that header while sending a multi-MB body.
    const largeBody = 'A'.repeat(5_000_000)
    const res = await app.request('/s3/huge.bin', {
      method: 'PUT',
      headers: { Authorization: headerForSmall },
      body: largeBody,
    })
    expect(res.status).toBe(401)
  })

  test('attack: empty body but header signed over non-empty body', async () => {
    const app = buildApp()
    const { keyPair, did } = await generateDidKeypair()
    const header = await createStorageDidHeader(keyPair.privateKey, did, '{"data":"real"}')

    const res = await app.request('/s3/empty.txt', {
      method: 'PUT',
      headers: { Authorization: header },
      body: '',
    })
    expect(res.status).toBe(401)
  })

  test('rejects expired timestamp (60s old)', async () => {
    const app = buildApp()
    const { keyPair, did } = await generateDidKeypair()
    const body = ''
    const header = await createStorageDidHeader(keyPair.privateKey, did, body, { timestamp: Date.now() - 60_000 })

    const res = await app.request('/s3/x', {
      method: 'GET',
      headers: { Authorization: header },
    })
    expect(res.status).toBe(401)
  })

  test('accepts valid DID-signed PUT (happy path)', async () => {
    const app = buildApp()
    const { keyPair, did } = await generateDidKeypair()
    const body = JSON.stringify({ hello: 'world' })
    const header = await createStorageDidHeader(keyPair.privateKey, did, body)

    const res = await app.request('/s3/file.json', {
      method: 'PUT',
      headers: { Authorization: header, 'Content-Type': 'application/json' },
      body,
    })
    expect(res.status).toBe(200)
    const json = await res.json() as any
    expect(json.ok).toBe(true)
    expect(json.user.userId).toBe(MOCKED_USER_ID)
    // Verifies the buffered-body plumbing: the consumed body is forwarded
    // to handlers intact so PUT can still stream bytes to MinIO.
    expect(json.bodyLen).toBe(new TextEncoder().encode(body).byteLength)
  })

  test('buffered body survives binary content (byte-perfect forwarding)', async () => {
    const app = buildApp()
    const { keyPair, did } = await generateDidKeypair()
    // Bytes that would be mangled by a naive text()/UTF-8 round-trip.
    const binary = new Uint8Array([0xff, 0xfe, 0x00, 0x01, 0x80, 0xc3, 0x28])

    const hashBuf = await crypto.subtle.digest('SHA-256', binary)
    const bodyHash = base64urlEncode(new Uint8Array(hashBuf))
    const payload = JSON.stringify({
      did,
      action: 'storage-put',
      timestamp: Date.now(),
      bodyHash,
    })
    const payloadEncoded = base64urlEncode(payload)
    const signature = new Uint8Array(
      await crypto.subtle.sign('Ed25519', keyPair.privateKey, new TextEncoder().encode(payloadEncoded)),
    )
    const header = `DID ${payloadEncoded}.${base64urlEncode(signature)}`

    // Pass the Uint8Array directly — Fetch/Hono treat it as raw bytes.
    const res = await app.request('/s3/bin', {
      method: 'PUT',
      headers: { Authorization: header, 'Content-Type': 'application/octet-stream' },
      body: binary,
    })
    expect(res.status).toBe(200)
    const json = await res.json() as any
    expect(json.bodyLen).toBe(binary.byteLength)
  })

  test('accepts valid GET with empty body', async () => {
    const app = buildApp()
    const { keyPair, did } = await generateDidKeypair()
    const header = await createStorageDidHeader(keyPair.privateKey, did, '')

    const res = await app.request('/s3/list', {
      method: 'GET',
      headers: { Authorization: header },
    })
    expect(res.status).toBe(200)
  })

  test('attack: DID spoofing (wrong signing key)', async () => {
    const app = buildApp()
    const victim = await generateDidKeypair()
    const attacker = await generateDidKeypair()
    const body = 'x'
    // Sign with attacker's key but claim victim's DID.
    const header = await createStorageDidHeader(attacker.keyPair.privateKey, victim.did, body)

    const res = await app.request('/s3/file', {
      method: 'PUT',
      headers: { Authorization: header },
      body,
    })
    expect(res.status).toBe(401)
  })

  test('attack: truncated signature', async () => {
    const app = buildApp()
    const { keyPair, did } = await generateDidKeypair()
    const body = '{}'
    const header = await createStorageDidHeader(keyPair.privateKey, did, body)
    const [head, sig] = header.split('.', 2) as [string, string]
    const truncated = `${head}.${sig.slice(0, 10)}`

    const res = await app.request('/s3/file', {
      method: 'PUT',
      headers: { Authorization: truncated },
      body,
    })
    expect(res.status).toBe(401)
  })

  test('rejects unknown auth scheme', async () => {
    const app = buildApp()
    const res = await app.request('/s3/file', {
      method: 'GET',
      headers: { Authorization: 'Bearer whatever' },
    })
    expect(res.status).toBe(401)
    const json = await res.json() as any
    expect(json.error).toMatch(/Unsupported|DID/i)
  })
})
