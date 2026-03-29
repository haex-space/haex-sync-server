# Phase 3: Server-Enforcement Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace Supabase JWT + Space Token auth with UCAN + DID-Auth on all endpoints in haex-sync-server.

**Architecture:** Three auth schemes via one `Authorization` header: `UCAN <token>` for space-scoped operations, `DID <payload>.<signature>` for identity-scoped operations (space creation, invite accept), and no auth for public endpoints. Server is an untrusted relay — UCAN verification is optimization, not the security boundary (Vault is, in Phase 4).

**Tech Stack:** Hono (Bun), `@haex-space/ucan` (Ed25519 UCAN library), Drizzle ORM, WebCrypto (Ed25519)

**Design doc:** `docs/plans/2026-03-29-phase3-server-enforcement.md`

---

## Task 1: Add `@haex-space/ucan` dependency + shared auth types

**Files:**
- Modify: `package.json`
- Create: `src/middleware/types.ts`

**Step 1: Install dependency**

```bash
cd /home/haex/Projekte/haex-sync-server
pnpm add @haex-space/ucan
```

**Step 2: Create shared auth context types**

Create `src/middleware/types.ts`:

```typescript
import type { VerifiedUcan, Capabilities, Capability } from '@haex-space/ucan'

export interface UcanContext {
  issuerDid: string
  publicKey: string
  capabilities: Capabilities
  verifiedUcan: VerifiedUcan
}

export interface DidContext {
  did: string
  publicKey: string
  userId: string
  tier: string
  action: string
}

declare module 'hono' {
  interface ContextVariableMap {
    ucan: UcanContext | null
    didAuth: DidContext | null
  }
}
```

**Step 3: Commit**

```bash
git add package.json pnpm-lock.yaml src/middleware/types.ts
git commit -m "feat: add @haex-space/ucan dependency and auth context types"
```

---

## Task 2: DID-Auth middleware

**Files:**
- Create: `src/middleware/didAuth.ts`
- Create: `tests/middleware/didAuth.test.ts`

**Step 1: Write failing tests**

Create `tests/middleware/didAuth.test.ts`:

```typescript
import { describe, test, expect, beforeAll } from 'bun:test'
import { Hono } from 'hono'
import { didAuthMiddleware } from '../../src/middleware/didAuth'

// Test helpers for Ed25519 key generation and signing
async function generateEd25519Keypair() {
  const keypair = await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify'],
  )
  const rawPublicKey = new Uint8Array(
    await crypto.subtle.exportKey('raw', keypair.publicKey),
  )
  // Build did:key from Ed25519 multicodec [0xed, 0x01, ...pubkey]
  const multicodec = new Uint8Array([0xed, 0x01, ...rawPublicKey])
  const did = `did:key:z${base58btcEncode(multicodec)}`
  return { keypair, did, publicKey: rawPublicKey, publicKeyBase64: btoa(String.fromCharCode(...rawPublicKey)) }
}

function base58btcEncode(bytes: Uint8Array): string {
  const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  let num = 0n
  for (const byte of bytes) num = num * 256n + BigInt(byte)
  let str = ''
  while (num > 0n) {
    str = ALPHABET[Number(num % 58n)] + str
    num = num / 58n
  }
  for (const byte of bytes) {
    if (byte !== 0) break
    str = '1' + str
  }
  return str
}

function base64urlEncode(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function createDidAuthHeader(
  keypair: CryptoKeyPair,
  did: string,
  action: string,
  body: string,
) {
  const bodyHash = Array.from(
    new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body))),
  ).map(b => b.toString(16).padStart(2, '0')).join('')

  const payload = {
    did,
    action,
    timestamp: Math.floor(Date.now() / 1000),
    bodyHash,
  }

  const payloadBytes = new TextEncoder().encode(JSON.stringify(payload))
  const signature = new Uint8Array(
    await crypto.subtle.sign('Ed25519', keypair.privateKey, payloadBytes),
  )

  return `DID ${base64urlEncode(payloadBytes)}.${base64urlEncode(signature)}`
}

describe('DID-Auth Middleware', () => {
  test('rejects request without Authorization header', async () => {
    const app = new Hono()
    app.use('/*', didAuthMiddleware)
    app.post('/test', (c) => c.json({ ok: true }))

    const res = await app.request('/test', { method: 'POST' })
    expect(res.status).toBe(401)
  })

  test('rejects request with wrong auth scheme', async () => {
    const app = new Hono()
    app.use('/*', didAuthMiddleware)
    app.post('/test', (c) => c.json({ ok: true }))

    const res = await app.request('/test', {
      method: 'POST',
      headers: { Authorization: 'Bearer some-token' },
    })
    expect(res.status).toBe(401)
  })

  test('rejects request with expired timestamp', async () => {
    const { keypair, did } = await generateEd25519Keypair()
    const body = JSON.stringify({ hello: 'world' })

    const bodyHash = Array.from(
      new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body))),
    ).map(b => b.toString(16).padStart(2, '0')).join('')

    const payload = { did, action: 'test', timestamp: Math.floor(Date.now() / 1000) - 60, bodyHash }
    const payloadBytes = new TextEncoder().encode(JSON.stringify(payload))
    const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', keypair.privateKey, payloadBytes))
    const header = `DID ${base64urlEncode(payloadBytes)}.${base64urlEncode(signature)}`

    const app = new Hono()
    app.use('/*', didAuthMiddleware)
    app.post('/test', (c) => c.json({ ok: true }))

    const res = await app.request('/test', {
      method: 'POST',
      headers: { Authorization: header, 'Content-Type': 'application/json' },
      body,
    })
    expect(res.status).toBe(401)
  })

  test('rejects request with invalid signature', async () => {
    const { keypair, did } = await generateEd25519Keypair()
    const { keypair: otherKeypair } = await generateEd25519Keypair()
    const body = JSON.stringify({ hello: 'world' })

    const bodyHash = Array.from(
      new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body))),
    ).map(b => b.toString(16).padStart(2, '0')).join('')

    const payload = { did, action: 'test', timestamp: Math.floor(Date.now() / 1000), bodyHash }
    const payloadBytes = new TextEncoder().encode(JSON.stringify(payload))
    // Sign with wrong key
    const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', otherKeypair.privateKey, payloadBytes))
    const header = `DID ${base64urlEncode(payloadBytes)}.${base64urlEncode(signature)}`

    const app = new Hono()
    app.use('/*', didAuthMiddleware)
    app.post('/test', (c) => c.json({ ok: true }))

    const res = await app.request('/test', {
      method: 'POST',
      headers: { Authorization: header, 'Content-Type': 'application/json' },
      body,
    })
    expect(res.status).toBe(401)
  })

  test('rejects request with wrong body hash', async () => {
    const { keypair, did } = await generateEd25519Keypair()
    const body = JSON.stringify({ hello: 'world' })

    const payload = { did, action: 'test', timestamp: Math.floor(Date.now() / 1000), bodyHash: 'wrong' }
    const payloadBytes = new TextEncoder().encode(JSON.stringify(payload))
    const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', keypair.privateKey, payloadBytes))
    const header = `DID ${base64urlEncode(payloadBytes)}.${base64urlEncode(signature)}`

    const app = new Hono()
    app.use('/*', didAuthMiddleware)
    app.post('/test', (c) => c.json({ ok: true }))

    const res = await app.request('/test', {
      method: 'POST',
      headers: { Authorization: header, 'Content-Type': 'application/json' },
      body,
    })
    expect(res.status).toBe(401)
  })

  test('accepts valid DID-signed request', async () => {
    const { keypair, did } = await generateEd25519Keypair()
    const body = JSON.stringify({ hello: 'world' })
    const header = await createDidAuthHeader(keypair, did, 'test', body)

    const app = new Hono()
    app.use('/*', didAuthMiddleware)
    app.post('/test', (c) => {
      const ctx = c.get('didAuth')
      return c.json({ did: ctx!.did, action: ctx!.action })
    })

    const res = await app.request('/test', {
      method: 'POST',
      headers: { Authorization: header, 'Content-Type': 'application/json' },
      body,
    })
    expect(res.status).toBe(200)
    const data = await res.json()
    expect(data.did).toBe(did)
    expect(data.action).toBe('test')
  })
})
```

**Step 2: Run tests to verify they fail**

```bash
cd /home/haex/Projekte/haex-sync-server && bun test tests/middleware/didAuth.test.ts
```

Expected: FAIL — `didAuthMiddleware` does not exist yet.

**Step 3: Implement DID-Auth middleware**

Create `src/middleware/didAuth.ts`:

```typescript
import type { Context, Next } from 'hono'
import { didToPublicKey } from '@haex-space/ucan'
import { db, identities } from '../db'
import { eq } from 'drizzle-orm'
import type { DidContext } from './types'

const TIMESTAMP_TOLERANCE_S = 30

function base64urlDecode(str: string): Uint8Array {
  // Add padding
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4)
  const binary = atob(padded.replace(/-/g, '+').replace(/_/g, '/'))
  return Uint8Array.from(binary, (c) => c.charCodeAt(0))
}

/**
 * DID-Auth Middleware
 *
 * Verifies requests signed with Ed25519 private key.
 * Format: Authorization: DID <base64url(json-payload)>.<base64url(signature)>
 *
 * Payload: { did, action, timestamp, bodyHash }
 *
 * Sets c.didAuth on success. Does NOT look up the identity in the database —
 * that is the route handler's responsibility (allows the middleware to be tested
 * without a database).
 */
export const didAuthMiddleware = async (c: Context, next: Next) => {
  const authHeader = c.req.header('Authorization')

  if (!authHeader || !authHeader.startsWith('DID ')) {
    return c.json({ error: 'Authorization header with DID scheme required' }, 401)
  }

  const token = authHeader.substring(4) // Remove 'DID '
  const dotIndex = token.indexOf('.')
  if (dotIndex === -1) {
    return c.json({ error: 'Invalid DID auth format' }, 401)
  }

  const payloadB64 = token.substring(0, dotIndex)
  const signatureB64 = token.substring(dotIndex + 1)

  let payload: { did: string; action: string; timestamp: number; bodyHash: string }
  try {
    const payloadBytes = base64urlDecode(payloadB64)
    payload = JSON.parse(new TextDecoder().decode(payloadBytes))
  } catch {
    return c.json({ error: 'Invalid DID auth payload' }, 401)
  }

  if (!payload.did || !payload.action || !payload.timestamp || !payload.bodyHash) {
    return c.json({ error: 'Missing required fields in DID auth payload' }, 401)
  }

  // Timestamp check (±30 seconds)
  const now = Math.floor(Date.now() / 1000)
  if (Math.abs(now - payload.timestamp) > TIMESTAMP_TOLERANCE_S) {
    return c.json({ error: 'DID auth timestamp expired or too far in the future' }, 401)
  }

  // Body hash verification
  const body = await c.req.text()
  const bodyHashBytes = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body)),
  )
  const bodyHash = Array.from(bodyHashBytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')

  if (bodyHash !== payload.bodyHash) {
    return c.json({ error: 'Body hash mismatch' }, 401)
  }

  // Extract public key from DID and verify Ed25519 signature
  let publicKeyBytes: Uint8Array
  try {
    publicKeyBytes = didToPublicKey(payload.did)
  } catch {
    return c.json({ error: 'Invalid DID format' }, 401)
  }

  try {
    const publicKey = await crypto.subtle.importKey(
      'raw',
      publicKeyBytes,
      { name: 'Ed25519' },
      false,
      ['verify'],
    )

    const payloadBytes = base64urlDecode(payloadB64)
    const signatureBytes = base64urlDecode(signatureB64)

    const valid = await crypto.subtle.verify(
      'Ed25519',
      publicKey,
      signatureBytes,
      payloadBytes,
    )

    if (!valid) {
      return c.json({ error: 'Invalid DID signature' }, 401)
    }
  } catch {
    return c.json({ error: 'Signature verification failed' }, 401)
  }

  c.set('didAuth', {
    did: payload.did,
    publicKey: Array.from(publicKeyBytes).map(b => b.toString(16).padStart(2, '0')).join(''),
    userId: '', // Resolved by route handler via identity lookup
    tier: '',   // Resolved by route handler via identity lookup
    action: payload.action,
  } satisfies DidContext)

  await next()
}

/**
 * Helper: Resolve DID to identity from database.
 * Called by route handlers after didAuthMiddleware.
 */
export async function resolveDidIdentity(did: string) {
  const [identity] = await db
    .select()
    .from(identities)
    .where(eq(identities.did, did))
    .limit(1)
  return identity ?? null
}
```

**Step 4: Run tests**

```bash
cd /home/haex/Projekte/haex-sync-server && bun test tests/middleware/didAuth.test.ts
```

Expected: All tests pass (the pure-crypto tests don't need DB; the `accepts valid DID-signed request` test works because we set `didAuth` context without DB lookup).

**Step 5: Commit**

```bash
git add src/middleware/didAuth.ts tests/middleware/didAuth.test.ts
git commit -m "feat: add DID-Auth middleware with Ed25519 signature verification"
```

---

## Task 3: UCAN-Auth middleware

**Files:**
- Create: `src/middleware/ucanAuth.ts`
- Create: `tests/middleware/ucanAuth.test.ts`

**Step 1: Write failing tests**

Create `tests/middleware/ucanAuth.test.ts`:

```typescript
import { describe, test, expect } from 'bun:test'
import { Hono } from 'hono'
import { ucanAuthMiddleware, requireCapability } from '../../src/middleware/ucanAuth'
import { createUcan, createWebCryptoSigner, spaceResource } from '@haex-space/ucan'
import type { Capability } from '@haex-space/ucan'

// Reuse base58btc helper from didAuth tests
function base58btcEncode(bytes: Uint8Array): string {
  const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  let num = 0n
  for (const byte of bytes) num = num * 256n + BigInt(byte)
  let str = ''
  while (num > 0n) {
    str = ALPHABET[Number(num % 58n)] + str
    num = num / 58n
  }
  for (const byte of bytes) {
    if (byte !== 0) break
    str = '1' + str
  }
  return str
}

async function makeIdentity() {
  const keypair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
  const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', keypair.publicKey))
  const multicodec = new Uint8Array([0xed, 0x01, ...rawPub])
  const did = `did:key:z${base58btcEncode(multicodec)}`
  const sign = createWebCryptoSigner(keypair.privateKey)
  return { keypair, did, sign, rawPub }
}

describe('UCAN-Auth Middleware', () => {
  test('rejects missing Authorization header', async () => {
    const app = new Hono()
    app.use('/*', ucanAuthMiddleware)
    app.get('/test', (c) => c.json({ ok: true }))

    const res = await app.request('/test')
    expect(res.status).toBe(401)
  })

  test('rejects invalid UCAN token', async () => {
    const app = new Hono()
    app.use('/*', ucanAuthMiddleware)
    app.get('/test', (c) => c.json({ ok: true }))

    const res = await app.request('/test', {
      headers: { Authorization: 'UCAN not-a-valid-token' },
    })
    expect(res.status).toBe(401)
  })

  test('accepts valid UCAN and sets context', async () => {
    const admin = await makeIdentity()
    const spaceId = 'test-space-123'

    const token = await createUcan({
      issuer: admin.did,
      audience: admin.did,
      capabilities: { [spaceResource(spaceId)]: 'space/admin' },
      expiration: Math.floor(Date.now() / 1000) + 3600,
    }, admin.sign)

    const app = new Hono()
    app.use('/*', ucanAuthMiddleware)
    app.get('/test', (c) => {
      const ctx = c.get('ucan')
      return c.json({ issuerDid: ctx!.issuerDid })
    })

    const res = await app.request('/test', {
      headers: { Authorization: `UCAN ${token}` },
    })
    expect(res.status).toBe(200)
    const data = await res.json()
    expect(data.issuerDid).toBe(admin.did)
  })

  test('rejects expired UCAN', async () => {
    const admin = await makeIdentity()

    const token = await createUcan({
      issuer: admin.did,
      audience: admin.did,
      capabilities: { [spaceResource('space-1')]: 'space/admin' },
      expiration: Math.floor(Date.now() / 1000) - 10, // expired
    }, admin.sign)

    const app = new Hono()
    app.use('/*', ucanAuthMiddleware)
    app.get('/test', (c) => c.json({ ok: true }))

    const res = await app.request('/test', {
      headers: { Authorization: `UCAN ${token}` },
    })
    expect(res.status).toBe(401)
  })
})

describe('requireCapability', () => {
  test('returns 403 when capability is missing', async () => {
    const admin = await makeIdentity()
    const spaceId = 'space-1'

    const token = await createUcan({
      issuer: admin.did,
      audience: admin.did,
      capabilities: { [spaceResource(spaceId)]: 'space/read' },
      expiration: Math.floor(Date.now() / 1000) + 3600,
    }, admin.sign)

    const app = new Hono()
    app.use('/*', ucanAuthMiddleware)
    app.get('/spaces/:spaceId', (c) => {
      const spaceId = c.req.param('spaceId')
      const error = requireCapability(c, spaceId, 'space/admin')
      if (error) return error
      return c.json({ ok: true })
    })

    const res = await app.request('/spaces/space-1', {
      headers: { Authorization: `UCAN ${token}` },
    })
    expect(res.status).toBe(403)
  })

  test('passes when capability is sufficient', async () => {
    const admin = await makeIdentity()
    const spaceId = 'space-1'

    const token = await createUcan({
      issuer: admin.did,
      audience: admin.did,
      capabilities: { [spaceResource(spaceId)]: 'space/admin' },
      expiration: Math.floor(Date.now() / 1000) + 3600,
    }, admin.sign)

    const app = new Hono()
    app.use('/*', ucanAuthMiddleware)
    app.get('/spaces/:spaceId', (c) => {
      const spaceId = c.req.param('spaceId')
      const error = requireCapability(c, spaceId, 'space/write')
      if (error) return error
      return c.json({ ok: true })
    })

    const res = await app.request('/spaces/space-1', {
      headers: { Authorization: `UCAN ${token}` },
    })
    expect(res.status).toBe(200)
  })

  test('supports delegated UCANs', async () => {
    const admin = await makeIdentity()
    const member = await makeIdentity()
    const spaceId = 'space-1'

    // Admin creates root UCAN
    const rootToken = await createUcan({
      issuer: admin.did,
      audience: member.did,
      capabilities: { [spaceResource(spaceId)]: 'space/write' },
      expiration: Math.floor(Date.now() / 1000) + 3600,
    }, admin.sign)

    // Member delegates to self (simulating presenting the token)
    const delegated = await createUcan({
      issuer: member.did,
      audience: member.did,
      capabilities: { [spaceResource(spaceId)]: 'space/write' },
      expiration: Math.floor(Date.now() / 1000) + 3600,
      proofs: [rootToken],
    }, member.sign)

    const app = new Hono()
    app.use('/*', ucanAuthMiddleware)
    app.get('/spaces/:spaceId', (c) => {
      const spaceId = c.req.param('spaceId')
      const error = requireCapability(c, spaceId, 'space/write')
      if (error) return error
      return c.json({ ok: true })
    })

    const res = await app.request('/spaces/space-1', {
      headers: { Authorization: `UCAN ${delegated}` },
    })
    expect(res.status).toBe(200)
  })
})
```

**Step 2: Run tests to verify they fail**

```bash
cd /home/haex/Projekte/haex-sync-server && bun test tests/middleware/ucanAuth.test.ts
```

Expected: FAIL — `ucanAuthMiddleware` does not exist.

**Step 3: Implement UCAN-Auth middleware**

Create `src/middleware/ucanAuth.ts`:

```typescript
import type { Context, Next } from 'hono'
import {
  decodeUcan,
  verifyUcan,
  createWebCryptoVerifier,
  satisfies,
  spaceResource,
  type Capability,
  type VerifiedUcan,
} from '@haex-space/ucan'
import type { UcanContext } from './types'

const verify = createWebCryptoVerifier()

/**
 * UCAN-Auth Middleware
 *
 * Verifies UCAN tokens from Authorization: UCAN <token> header.
 * Checks: signature chain, expiry.
 * Does NOT check capabilities — that's done per route via requireCapability().
 * Does NOT check identity in DB — that's the route handler's job.
 */
export const ucanAuthMiddleware = async (c: Context, next: Next) => {
  const authHeader = c.req.header('Authorization')

  if (!authHeader || !authHeader.startsWith('UCAN ')) {
    return c.json({ error: 'Authorization header with UCAN scheme required' }, 401)
  }

  const token = authHeader.substring(5) // Remove 'UCAN '

  let verified: VerifiedUcan
  try {
    verified = await verifyUcan(token, verify)
  } catch (err) {
    const message = err instanceof Error ? err.message : 'UCAN verification failed'
    return c.json({ error: `Invalid UCAN: ${message}` }, 401)
  }

  // Check expiry
  const now = Math.floor(Date.now() / 1000)
  if (verified.payload.exp <= now) {
    return c.json({ error: 'UCAN expired' }, 401)
  }

  // Check not-before (iat)
  if (verified.payload.iat > now + 30) {
    return c.json({ error: 'UCAN issued in the future' }, 401)
  }

  c.set('ucan', {
    issuerDid: verified.payload.iss,
    publicKey: verified.payload.iss, // DID is the identifier
    capabilities: verified.payload.cap,
    verifiedUcan: verified,
  } satisfies UcanContext)

  await next()
}

/**
 * Check if the UCAN in context has the required capability for a space.
 * Returns a Response if the check fails, null if it passes.
 *
 * Usage in route handlers:
 *   const error = requireCapability(c, spaceId, 'space/write')
 *   if (error) return error
 */
export function requireCapability(
  c: Context,
  spaceId: string,
  required: Capability,
): Response | null {
  const ucanCtx = c.get('ucan')
  if (!ucanCtx) {
    return c.json({ error: 'No UCAN context' }, 401)
  }

  const resource = spaceResource(spaceId)
  const held = ucanCtx.capabilities[resource]

  if (!held || !satisfies(held, required)) {
    return c.json(
      { error: `Insufficient capability: need ${required} for ${resource}` },
      403,
    )
  }

  return null
}
```

**Step 4: Run tests**

```bash
cd /home/haex/Projekte/haex-sync-server && bun test tests/middleware/ucanAuth.test.ts
```

Expected: All pass.

**Step 5: Commit**

```bash
git add src/middleware/ucanAuth.ts tests/middleware/ucanAuth.test.ts
git commit -m "feat: add UCAN-Auth middleware with capability checks"
```

---

## Task 4: Auth dispatcher middleware

**Files:**
- Create: `src/middleware/authDispatcher.ts`
- Create: `tests/middleware/authDispatcher.test.ts`

**Step 1: Write failing tests**

Create `tests/middleware/authDispatcher.test.ts`:

```typescript
import { describe, test, expect } from 'bun:test'
import { Hono } from 'hono'
import { authDispatcher } from '../../src/middleware/authDispatcher'

describe('Auth Dispatcher', () => {
  test('returns 401 for missing Authorization header', async () => {
    const app = new Hono()
    app.use('/*', authDispatcher)
    app.get('/test', (c) => c.json({ ok: true }))

    const res = await app.request('/test')
    expect(res.status).toBe(401)
  })

  test('returns 401 for unknown auth scheme', async () => {
    const app = new Hono()
    app.use('/*', authDispatcher)
    app.get('/test', (c) => c.json({ ok: true }))

    const res = await app.request('/test', {
      headers: { Authorization: 'Bearer some-jwt' },
    })
    expect(res.status).toBe(401)
  })

  test('dispatches to UCAN handler for UCAN scheme', async () => {
    const app = new Hono()
    app.use('/*', authDispatcher)
    app.get('/test', (c) => c.json({ ok: true }))

    // Invalid UCAN, but should dispatch to UCAN handler (which rejects it)
    const res = await app.request('/test', {
      headers: { Authorization: 'UCAN invalid-token' },
    })
    // Should be 401 from UCAN handler, not the dispatcher
    expect(res.status).toBe(401)
    const data = await res.json() as { error: string }
    expect(data.error).toContain('UCAN')
  })

  test('dispatches to DID handler for DID scheme', async () => {
    const app = new Hono()
    app.use('/*', authDispatcher)
    app.post('/test', (c) => c.json({ ok: true }))

    // Invalid DID, but should dispatch to DID handler
    const res = await app.request('/test', {
      method: 'POST',
      headers: { Authorization: 'DID invalid' },
    })
    expect(res.status).toBe(401)
    const data = await res.json() as { error: string }
    expect(data.error).toContain('DID')
  })
})
```

**Step 2: Implement auth dispatcher**

Create `src/middleware/authDispatcher.ts`:

```typescript
import type { Context, Next } from 'hono'
import { didAuthMiddleware } from './didAuth'
import { ucanAuthMiddleware } from './ucanAuth'

/**
 * Auth Dispatcher
 *
 * Routes to the correct auth middleware based on the Authorization header scheme.
 * Supports: UCAN <token>, DID <payload>.<signature>
 */
export const authDispatcher = async (c: Context, next: Next) => {
  const authHeader = c.req.header('Authorization')

  if (!authHeader) {
    return c.json({ error: 'Authorization header required' }, 401)
  }

  if (authHeader.startsWith('UCAN ')) {
    return ucanAuthMiddleware(c, next)
  }

  if (authHeader.startsWith('DID ')) {
    return didAuthMiddleware(c, next)
  }

  return c.json({ error: 'Unsupported authorization scheme. Use UCAN or DID.' }, 401)
}
```

**Step 3: Run tests**

```bash
cd /home/haex/Projekte/haex-sync-server && bun test tests/middleware/
```

Expected: All tests pass.

**Step 4: Commit**

```bash
git add src/middleware/authDispatcher.ts tests/middleware/authDispatcher.test.ts
git commit -m "feat: add auth dispatcher routing to UCAN or DID handlers"
```

---

## Task 5: Add `did` column to `space_members`

**Files:**
- Modify: `src/db/schema.ts`

**Step 1: Add `did` column**

In `src/db/schema.ts`, update the `spaceMembers` table definition:

```typescript
// Add to spaceMembers:
did: text("did").notNull(), // did:key:z... of the member
```

The publicKey column stays — it's used for existing lookups and sync validation.

**Step 2: Generate migration**

```bash
cd /home/haex/Projekte/haex-sync-server && pnpm db:generate
```

Review the generated migration SQL. It should add a `did` column to `space_members`.

**Step 3: Commit**

```bash
git add src/db/schema.ts drizzle/
git commit -m "feat: add did column to space_members table"
```

---

## Task 6: Refactor space routes — Create Space (DID-Auth)

**Files:**
- Modify: `src/routes/spaces.ts`

This is the biggest refactor. We split it into sub-tasks.

**Step 1: Replace middleware and helper functions**

Replace the top of `src/routes/spaces.ts`:

```typescript
import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { db, spaces, spaceMembers, identities } from '../db'
import { authDispatcher } from '../middleware/authDispatcher'
import { requireCapability } from '../middleware/ucanAuth'
import { resolveDidIdentity } from '../middleware/didAuth'
import { eq, and } from 'drizzle-orm'

const spacesRouter = new Hono()

// All space routes require auth (UCAN or DID)
spacesRouter.use('/*', authDispatcher)

const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

function isValidUuid(id: string): boolean {
  return uuidRegex.test(id)
}

/** Get caller's DID from either UCAN or DID-Auth context */
function getCallerDid(c: any): string | null {
  const ucan = c.get('ucan')
  if (ucan) return ucan.issuerDid
  const didAuth = c.get('didAuth')
  if (didAuth) return didAuth.did
  return null
}
```

**Step 2: Rewrite POST / (Create Space) for DID-Auth**

```typescript
const createSpaceSchema = z.object({
  id: z.string().uuid(),
  encryptedName: z.string(),
  nameNonce: z.string(),
  label: z.string().min(1),
})

spacesRouter.post('/', zValidator('json', createSpaceSchema), async (c) => {
  const didAuth = c.get('didAuth')
  if (!didAuth) {
    return c.json({ error: 'Space creation requires DID-Auth' }, 401)
  }

  const body = c.req.valid('json')

  try {
    const identity = await resolveDidIdentity(didAuth.did)
    if (!identity || !identity.supabaseUserId) {
      return c.json({ error: 'Identity not found or not verified' }, 403)
    }

    // TODO: Check quota/tier when space limits are enforced

    await db.transaction(async (tx) => {
      await tx.insert(spaces).values({
        id: body.id,
        ownerId: identity.supabaseUserId!,
        encryptedName: body.encryptedName,
        nameNonce: body.nameNonce,
      })

      await tx.insert(spaceMembers).values({
        spaceId: body.id,
        publicKey: identity.publicKey,
        did: identity.did,
        label: body.label,
        role: 'admin',
        invitedBy: null,
      })
    })

    return c.json({ success: true }, 201)
  } catch (error) {
    console.error('Create space error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})
```

Note: `keyGrant` is removed from the schema — MLS replaces key grants.

**Step 3: Rewrite GET / (List Spaces) for UCAN-Auth**

```typescript
spacesRouter.get('/', async (c) => {
  const callerDid = getCallerDid(c)
  if (!callerDid) return c.json({ error: 'Auth required' }, 401)

  try {
    const result = await db.select({
      id: spaces.id,
      ownerId: spaces.ownerId,
      encryptedName: spaces.encryptedName,
      nameNonce: spaces.nameNonce,
      createdAt: spaces.createdAt,
      updatedAt: spaces.updatedAt,
      role: spaceMembers.role,
      joinedAt: spaceMembers.joinedAt,
    })
      .from(spaceMembers)
      .innerJoin(spaces, eq(spaceMembers.spaceId, spaces.id))
      .where(eq(spaceMembers.did, callerDid))

    return c.json(result)
  } catch (error) {
    console.error('List spaces error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})
```

**Step 4: Rewrite remaining UCAN-Auth endpoints**

Apply the same pattern to all other space endpoints:

- `GET /:spaceId` → `requireCapability(c, spaceId, 'space/read')`
- `PATCH /:spaceId` → `requireCapability(c, spaceId, 'space/admin')`
- `DELETE /:spaceId` → `requireCapability(c, spaceId, 'space/admin')`
- `POST /:spaceId/members` → `requireCapability(c, spaceId, 'space/invite')`
- `DELETE /:spaceId/members/:key` → `requireCapability(c, spaceId, 'space/admin')` or self-leave check
- `GET /:spaceId/key-grants` → REMOVE (key grants replaced by MLS)
- `POST /:spaceId/tokens` → REMOVE (space tokens replaced by UCAN)
- `GET /:spaceId/tokens` → REMOVE
- `DELETE /:spaceId/tokens/:id` → REMOVE
- `POST /:spaceId/transfer-admin` → `requireCapability(c, spaceId, 'space/admin')`
- `DELETE /my-admin-spaces` → Use caller DID from UCAN

Each endpoint follows this pattern:

```typescript
spacesRouter.get('/:spaceId', async (c) => {
  const spaceId = c.req.param('spaceId')
  if (!isValidUuid(spaceId)) return c.json({ error: 'Invalid space ID format' }, 400)

  const error = requireCapability(c, spaceId, 'space/read')
  if (error) return error

  // ... existing logic, but using DID instead of userId ...
})
```

For `resolveCallerPublicKey` calls: replace with the public key from the UCAN issuer DID (available in `c.get('ucan')!.issuerDid`), resolved via `resolveDidIdentity()` if needed.

**Step 5: Remove space access token endpoints and imports**

Remove all imports/references to `spaceAccessTokens` and `spaceKeyGrants` from this file. Remove the token CRUD endpoints and key-grants endpoint.

**Step 6: Commit**

```bash
git add src/routes/spaces.ts
git commit -m "refactor: migrate space routes to UCAN + DID-Auth"
```

---

## Task 7: Refactor MLS routes

**Files:**
- Modify: `src/routes/mls.ts`

**Step 1: Replace middleware**

```typescript
import { authDispatcher } from '../middleware/authDispatcher'
import { requireCapability } from '../middleware/ucanAuth'
import { resolveDidIdentity } from '../middleware/didAuth'

const mlsRouter = new Hono()

mlsRouter.use('/*', authDispatcher)

/** Get caller's DID from UCAN or DID-Auth context */
function getCallerDid(c: any): string | null {
  const ucan = c.get('ucan')
  if (ucan) return ucan.issuerDid
  const didAuth = c.get('didAuth')
  if (didAuth) return didAuth.did
  return null
}
```

**Step 2: Update each endpoint**

| Endpoint | Auth | Capability |
|----------|------|-----------|
| `POST /:spaceId/invites` | UCAN | `space/invite` |
| `GET /:spaceId/invites` | UCAN | `space/read` |
| `POST /:spaceId/invites/:id/accept` | DID-Auth | action: `accept-invite` |
| `POST /:spaceId/invites/:id/decline` | UCAN or DID | check invitee DID matches |
| `DELETE /:spaceId/invites/:id` | UCAN | `space/invite` |
| `POST /:spaceId/mls/key-packages` | UCAN | `space/read` |
| `GET /:spaceId/mls/key-packages/:did` | UCAN | `space/invite` |
| `POST /:spaceId/mls/messages` | UCAN | `space/write` |
| `GET /:spaceId/mls/messages` | UCAN | `space/read` |
| `POST /:spaceId/mls/welcome` | UCAN | `space/invite` |
| `GET /:spaceId/mls/welcome` | UCAN | `space/read` |

For invite accept (DID-Auth):

```typescript
mlsRouter.post('/:spaceId/invites/:inviteId/accept', zValidator('json', acceptInviteSchema), async (c) => {
  const didAuth = c.get('didAuth')
  if (!didAuth) return c.json({ error: 'Invite accept requires DID-Auth' }, 401)

  const spaceId = c.req.param('spaceId')
  const inviteId = c.req.param('inviteId')
  const body = c.req.valid('json')

  const identity = await resolveDidIdentity(didAuth.did)
  if (!identity) return c.json({ error: 'Identity not found' }, 404)

  const [invite] = await db.select().from(spaceInvites)
    .where(and(
      eq(spaceInvites.id, inviteId),
      eq(spaceInvites.spaceId, spaceId),
      eq(spaceInvites.inviteeDid, identity.did),
      eq(spaceInvites.status, 'pending'),
    ))
    .limit(1)

  if (!invite) return c.json({ error: 'Invite not found or already responded' }, 404)

  await db.transaction(async (tx) => {
    await tx.update(spaceInvites)
      .set({ status: 'accepted', respondedAt: new Date() })
      .where(eq(spaceInvites.id, inviteId))

    const values = body.keyPackages.map((kp) => ({
      spaceId,
      identityPublicKey: identity.publicKey,
      keyPackage: Buffer.from(kp, 'base64'),
    }))
    await tx.insert(mlsKeyPackages).values(values)
  })

  return c.json({ success: true })
})
```

For UCAN endpoints, replace `resolveCallerIdentity(user.userId)` with:

```typescript
const callerDid = getCallerDid(c)
if (!callerDid) return c.json({ error: 'Auth required' }, 401)

const identity = await resolveDidIdentity(callerDid)
if (!identity) return c.json({ error: 'Identity not found' }, 404)
```

And add `requireCapability()` calls before the logic.

**Step 3: Commit**

```bash
git add src/routes/mls.ts
git commit -m "refactor: migrate MLS routes to UCAN + DID-Auth"
```

---

## Task 8: Refactor sync routes

**Files:**
- Modify: `src/routes/sync.ts`
- Modify: `src/routes/sync.helpers.ts`
- Modify: `src/routes/sync.vaults.ts`

**Step 1: Update sync.ts**

Replace middleware chain:

```typescript
import { authDispatcher } from '../middleware/authDispatcher'
import { requireCapability } from '../middleware/ucanAuth'
import { resolveDidIdentity } from '../middleware/didAuth'

const sync = new Hono()

// All sync routes require auth
sync.use('/*', authDispatcher)
```

Remove `spaceTokenAuthMiddleware` import and usage.

For `POST /push`:
- Shared space: require UCAN with `space/write`
- Personal vault: require DID-Auth (owner check via identity lookup)
- Remove all `spaceToken` handling (challenge verification, etc.)

For `GET /pull`:
- Shared space: require UCAN with `space/read`
- Personal vault: require DID-Auth
- Remove all `spaceToken` handling

For `POST /pull-columns`:
- Same pattern as pull

**Step 2: Update sync.helpers.ts**

Remove `getUserPublicKey` and `getCallerRoleByUserId` (no longer needed — role comes from UCAN capability, publicKey from DID).

Keep `getSpaceType` and `validateSpacePush` but update `validateSpacePush` to accept DID instead of resolving via userId.

**Step 3: Update sync.vaults.ts**

Vault-key routes are personal vault operations. Replace `c.get('user')` with DID-Auth identity lookup:

```typescript
// In each endpoint:
const didAuth = c.get('didAuth')
if (!didAuth) return c.json({ error: 'Vault operations require DID-Auth' }, 401)

const identity = await resolveDidIdentity(didAuth.did)
if (!identity?.supabaseUserId) return c.json({ error: 'Identity not found' }, 404)

// Use identity.supabaseUserId where user.userId was used
```

Remove all `spaceToken` checks (they guarded against space tokens being used for vault ops).

**Step 4: Commit**

```bash
git add src/routes/sync.ts src/routes/sync.helpers.ts src/routes/sync.vaults.ts
git commit -m "refactor: migrate sync routes to UCAN + DID-Auth"
```

---

## Task 9: Move storage-credentials + update identity-auth

**Files:**
- Modify: `src/routes/identity-auth.ts`
- Modify: `src/routes/auth.ts`
- Modify: `index.ts`

**Step 1: Move storage-credentials to identity-auth**

In `src/routes/identity-auth.ts`, add the storage credentials endpoint (requires DID-Auth):

```typescript
import { authDispatcher } from '../middleware/authDispatcher'
import { resolveDidIdentity } from '../middleware/didAuth'
import { getOrCreateStorageCredentials } from '../services/storageCredentials'
import { getUserBucket } from '../services/minioAdmin'

// Add at the end, before export:
app.get('/storage-credentials', authDispatcher, async (c) => {
  const didAuth = c.get('didAuth')
  if (!didAuth) return c.json({ error: 'DID-Auth required' }, 401)

  const identity = await resolveDidIdentity(didAuth.did)
  if (!identity?.supabaseUserId) return c.json({ error: 'Identity not found' }, 404)

  const serverUrl = new URL(c.req.url).origin
  const credentials = await getOrCreateStorageCredentials(identity.supabaseUserId)

  return c.json({
    endpoint: `${serverUrl.replace(/\/$/, '')}/storage/s3`,
    bucket: getUserBucket(identity.supabaseUserId),
    region: 'auto',
    accessKeyId: credentials.accessKeyId,
    secretAccessKey: credentials.secretAccessKey,
  })
})
```

**Step 2: Update identity-auth/verify to return UCAN-relevant info**

The `/identity-auth/verify` endpoint still returns a Supabase session (for Realtime). No changes needed — it remains the login endpoint. The session is only used for Supabase Realtime, not for API auth.

**Step 3: Update identity-auth/update-recovery to use DID-Auth**

Replace `authMiddleware` with `authDispatcher`:

```typescript
app.post('/update-recovery', authDispatcher, async (c) => {
  const didAuth = c.get('didAuth')
  if (!didAuth) return c.json({ error: 'DID-Auth required' }, 401)

  // ... rest uses didAuth.did instead of user.userId
  const result = await db.update(identities)
    .set({ encryptedPrivateKey, privateKeyNonce, privateKeySalt, updatedAt: new Date() })
    .where(eq(identities.did, didAuth.did))
    .returning({ id: identities.id })

  // ...
})
```

**Step 4: Simplify auth.ts**

Remove `GET /auth/storage-credentials` (moved to identity-auth). Keep `POST /auth/admin/create-user` (admin-only, service key auth — independent of UCAN).

**Step 5: Update index.ts**

No route path changes needed — `/auth` stays for admin, `/identity-auth` gets the storage-credentials endpoint.

**Step 6: Commit**

```bash
git add src/routes/identity-auth.ts src/routes/auth.ts index.ts
git commit -m "refactor: move storage-credentials to identity-auth, use DID-Auth"
```

---

## Task 10: Cleanup — remove old auth

**Files:**
- Delete: `src/middleware/auth.ts`
- Delete: `src/middleware/spaceTokenAuth.ts`
- Modify: `src/db/schema.ts` (remove `spaceAccessTokens`, `spaceKeyGrants`)
- Modify: `index.ts` (verify no old imports remain)

**Step 1: Delete old middleware files**

```bash
rm src/middleware/auth.ts src/middleware/spaceTokenAuth.ts
```

**Step 2: Remove unused tables from schema**

In `src/db/schema.ts`:
- Remove `spaceAccessTokens` table definition and type exports
- Remove `spaceKeyGrants` table definition and type exports
- Remove `currentKeyGeneration` from `spaces` table (no longer needed without key grants)

**Step 3: Generate migration for removed tables**

```bash
pnpm db:generate
```

**Step 4: Verify no old imports remain**

```bash
cd /home/haex/Projekte/haex-sync-server
grep -r "authMiddleware\|spaceTokenAuth\|spaceAccessTokens\|spaceKeyGrants" src/ index.ts --include="*.ts" | grep -v node_modules
```

Should return no results.

**Step 5: Run all tests**

```bash
bun test
```

**Step 6: TypeScript compile check**

```bash
bunx tsc --noEmit
```

**Step 7: Commit**

```bash
git add -A
git commit -m "refactor: remove Supabase JWT auth, space tokens, and key grants"
```

---

## Task 11: Integration tests

**Files:**
- Create: `tests/integration/spaces.test.ts`
- Create: `tests/integration/helpers.ts`

**Step 1: Create test helpers**

Create `tests/integration/helpers.ts` with reusable identity + UCAN creation helpers:

```typescript
import { createUcan, createWebCryptoSigner, spaceResource } from '@haex-space/ucan'
import type { Capability } from '@haex-space/ucan'

// base58btc encoder, identity generator, DID-Auth header builder, UCAN builder
// (Extract from Task 2/3 test helpers into shared module)
```

**Step 2: Write integration tests**

Test key flows without a database (using Hono's test request):
- Create space with DID-Auth → verify 201
- Create space with UCAN → verify 401 (wrong auth scheme)
- Access space with valid UCAN → verify 200
- Access space with insufficient capability → verify 403
- Accept invite with DID-Auth → verify flow
- Push sync changes with UCAN space/write → verify 200
- Push sync changes with UCAN space/read → verify 403

Note: Full integration tests with database require a running PostgreSQL. These tests validate the auth middleware dispatch and capability checks without DB.

**Step 3: Commit**

```bash
git add tests/
git commit -m "test: add integration tests for UCAN + DID-Auth flows"
```

---

## Dependency Graph

```
Task 1 (dependency + types)
    ↓
Task 2 (DID-Auth middleware)  ─┐
Task 3 (UCAN-Auth middleware) ─┤
    ↓                          ↓
Task 4 (auth dispatcher)
    ↓
Task 5 (DB migration: add did to space_members)
    ↓
Task 6 (refactor spaces) ──┐
Task 7 (refactor MLS)    ──┤── can be parallelized
Task 8 (refactor sync)   ──┤
Task 9 (identity-auth)   ──┘
    ↓
Task 10 (cleanup)
    ↓
Task 11 (integration tests)
```

Tasks 2+3 can run in parallel. Tasks 6-9 can run in parallel after Task 4+5.
