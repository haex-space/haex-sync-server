import { describe, test, expect, mock, beforeEach, afterAll } from 'bun:test'
import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import {
  createUcan,
  createWebCryptoSigner,
  spaceCapabilitySet,
  spaceResource,
  createUcanPopHeader,
  POP_HEADER_NAME,
  POP_ERROR_MESSAGES,
  type Capabilities,
  type SignFn,
} from '@haex-space/ucan'

// The middleware never touches the DB directly, but capabilities.ts (imported
// transitively) does. Mock it so the tests stay hermetic.
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

import { ucanAuthMiddleware, MAX_UCAN_ROUTE_BODY_BYTES } from '../../src/middleware/ucanAuth'
import { destroyPopJtiCache } from '../../src/middleware/popJtiCache'

// ============================================
// Test helpers
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
  for (const byte of bytes) {
    if (byte === 0) digits.push(0)
    else break
  }
  return digits.reverse().map(d => BASE58_ALPHABET[d]).join('')
}

interface Identity {
  did: string
  sign: SignFn
  privateKey: CryptoKey
}

async function makeIdentity(): Promise<Identity> {
  const keyPair = (await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify'],
  )) as unknown as CryptoKeyPair

  const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey))

  const multicodec = new Uint8Array(2 + rawPublicKey.length)
  multicodec[0] = 0xed
  multicodec[1] = 0x01
  multicodec.set(rawPublicKey, 2)

  const did = `did:key:z${base58btcEncode(multicodec)}`

  return {
    did,
    sign: createWebCryptoSigner(keyPair.privateKey),
    privateKey: keyPair.privateKey,
  }
}

async function makeToken(
  issuer: Identity,
  audience: string,
  capabilities: Capabilities,
  options?: { exp?: number; proofs?: string[] },
): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  return createUcan(
    {
      issuer: issuer.did,
      audience,
      capabilities,
      expiration: options?.exp ?? now + 3600,
      proofs: options?.proofs ?? [],
    },
    issuer.sign,
  )
}

function createApp() {
  const app = new Hono()
  app.use('*', ucanAuthMiddleware)

  app.get('/read', (c) => c.json({ ok: true }))
  app.delete('/delete/:id', (c) => c.json({ ok: true, id: c.req.param('id') }))

  const postSchema = z.object({ name: z.string() })
  app.post('/write', zValidator('json', postSchema), (c) => {
    // Pins that the middleware body-buffer is compatible with zValidator:
    // if the middleware bypassed the cache, this handler would 400 on empty
    // body instead of returning the parsed payload.
    const body = c.req.valid('json')
    return c.json({ ok: true, echoed: body.name })
  })

  return app
}

async function selfIssuedUcan(identity: Identity): Promise<string> {
  const spaceId = crypto.randomUUID()
  return makeToken(identity, identity.did, {
    [spaceResource(spaceId)]: spaceCapabilitySet()
      .read(true).write(true).invite(true).admin(true).build(),
  })
}

beforeEach(() => {
  mockSpaceOwnerDid = UNRELATED_OWNER
  destroyPopJtiCache()
})

afterAll(() => {
  destroyPopJtiCache()
})

// ============================================
// §B.3 tests
// ============================================

describe('ucanAuthMiddleware — X-UCAN-PoP required', () => {
  test('1. X-UCAN-PoP absent on a UCAN-authed request → 401 with PoP-required reason', async () => {
    const identity = await makeIdentity()
    const ucan = await selfIssuedUcan(identity)

    const res = await createApp().request('/read', {
      headers: { Authorization: `UCAN ${ucan}` },
    })
    expect(res.status).toBe(401)
    const body = await res.json() as { error: string }
    expect(body.error).toBe('UCAN requests must present X-UCAN-PoP')
  })

  test('2. PoP signed by the wrong key → 401 PoP signature invalid', async () => {
    const holder = await makeIdentity()
    const attacker = await makeIdentity()
    const ucan = await selfIssuedUcan(holder)

    // Sign PoP with a key that does NOT match the UCAN's aud (holder).
    const popHeader = await createUcanPopHeader({
      privateKey: attacker.privateKey,
      ucanAud: holder.did,
      method: 'GET',
      path: '/read',
      rawQuery: '',
      body: '',
    })

    const res = await createApp().request('/read', {
      headers: {
        Authorization: `UCAN ${ucan}`,
        [POP_HEADER_NAME]: popHeader,
      },
    })
    expect(res.status).toBe(401)
    const body = await res.json() as { error: string }
    expect(body.error).toBe(POP_ERROR_MESSAGES.SIGNATURE_INVALID)
  })

  test('3. PoP request-hash mismatch on body → 401 PoP request mismatch', async () => {
    const holder = await makeIdentity()
    const ucan = await selfIssuedUcan(holder)

    const originalBody = JSON.stringify({ name: 'expected' })
    const tamperedBody = JSON.stringify({ name: 'tampered' })

    const popHeader = await createUcanPopHeader({
      privateKey: holder.privateKey,
      ucanAud: holder.did,
      method: 'POST',
      path: '/write',
      rawQuery: '',
      body: originalBody,
    })

    const res = await createApp().request('/write', {
      method: 'POST',
      headers: {
        Authorization: `UCAN ${ucan}`,
        [POP_HEADER_NAME]: popHeader,
        'Content-Type': 'application/json',
        'Content-Length': String(new TextEncoder().encode(tamperedBody).length),
      },
      body: tamperedBody,
    })
    expect(res.status).toBe(401)
    const body = await res.json() as { error: string }
    expect(body.error).toBe(POP_ERROR_MESSAGES.REQUEST_MISMATCH)
  })

  test('4. PoP request-hash mismatch on URL target → 401 PoP request mismatch', async () => {
    const holder = await makeIdentity()
    const ucan = await selfIssuedUcan(holder)

    // Sign PoP for delete of T1, replay against T2 — same UCAN, same aud,
    // empty body, different path. Closes URL-target-swap replay.
    const popHeader = await createUcanPopHeader({
      privateKey: holder.privateKey,
      ucanAud: holder.did,
      method: 'DELETE',
      path: '/delete/T1',
      rawQuery: '',
      body: '',
    })

    const res = await createApp().request('/delete/T2', {
      method: 'DELETE',
      headers: {
        Authorization: `UCAN ${ucan}`,
        [POP_HEADER_NAME]: popHeader,
      },
    })
    expect(res.status).toBe(401)
    const body = await res.json() as { error: string }
    expect(body.error).toBe(POP_ERROR_MESSAGES.REQUEST_MISMATCH)
  })

  test('4b. PoP request-hash mismatch on raw query → 401 PoP request mismatch', async () => {
    const holder = await makeIdentity()
    const ucan = await selfIssuedUcan(holder)

    // Path unchanged; sign one raw query, request a different one. Pins that
    // the middleware forwards `rawQuery` into `verifyUcanPop` so a regression
    // that drops query-string binding cannot ship silently.
    const popHeader = await createUcanPopHeader({
      privateKey: holder.privateKey,
      ucanAud: holder.did,
      method: 'GET',
      path: '/read',
      rawQuery: 'action=read',
      body: '',
    })

    const res = await createApp().request('/read?action=write', {
      headers: {
        Authorization: `UCAN ${ucan}`,
        [POP_HEADER_NAME]: popHeader,
      },
    })
    expect(res.status).toBe(401)
    const body = await res.json() as { error: string }
    expect(body.error).toBe(POP_ERROR_MESSAGES.REQUEST_MISMATCH)
  })

  test('5. PoP replay of same jti within window → first 200, second 401 PoP replay detected', async () => {
    const holder = await makeIdentity()
    const ucan = await selfIssuedUcan(holder)

    const popHeader = await createUcanPopHeader({
      privateKey: holder.privateKey,
      ucanAud: holder.did,
      method: 'GET',
      path: '/read',
      rawQuery: '',
      body: '',
    })

    const app = createApp()

    const first = await app.request('/read', {
      headers: {
        Authorization: `UCAN ${ucan}`,
        [POP_HEADER_NAME]: popHeader,
      },
    })
    expect(first.status).toBe(200)

    const second = await app.request('/read', {
      headers: {
        Authorization: `UCAN ${ucan}`,
        [POP_HEADER_NAME]: popHeader,
      },
    })
    expect(second.status).toBe(401)
    const body = await second.json() as { error: string }
    expect(body.error).toBe(POP_ERROR_MESSAGES.REPLAY)
  })

  test('6. Body-size guard: Content-Length > MAX → 413 before buffering', async () => {
    const holder = await makeIdentity()
    const ucan = await selfIssuedUcan(holder)

    // A well-formed PoP header — the middleware must reject BEFORE reading
    // the body, so no request-hash agreement is needed to reach the 413.
    const popHeader = await createUcanPopHeader({
      privateKey: holder.privateKey,
      ucanAud: holder.did,
      method: 'POST',
      path: '/write',
      rawQuery: '',
      body: '',
    })

    const oversized = String(MAX_UCAN_ROUTE_BODY_BYTES + 1)

    const res = await createApp().request('/write', {
      method: 'POST',
      headers: {
        Authorization: `UCAN ${ucan}`,
        [POP_HEADER_NAME]: popHeader,
        'Content-Type': 'application/json',
        'Content-Length': oversized,
      },
      body: '{}',
    })
    expect(res.status).toBe(413)
  })

  test('7. Missing Content-Length on POST → 411', async () => {
    const holder = await makeIdentity()
    const ucan = await selfIssuedUcan(holder)

    const res = await createApp().request('/write', {
      method: 'POST',
      headers: {
        Authorization: `UCAN ${ucan}`,
        // No PoP header on purpose — Content-Length is checked first for
        // body-bearing methods, and this test pins that behaviour.
        'Content-Type': 'application/json',
      },
      body: '{"name":"x"}',
    })
    // Hono's fetch-request adapter auto-sets Content-Length for string bodies
    // sent through app.request. Simulate a chunked/streamed request by passing
    // a ReadableStream — request adapters won't materialize a Content-Length.
    if (res.status !== 411) {
      // Fallback: explicitly delete the header via a Request object.
      const req = new Request('http://x/write', {
        method: 'POST',
        headers: {
          Authorization: `UCAN ${ucan}`,
          'Content-Type': 'application/json',
        },
        body: '{"name":"x"}',
      })
      req.headers.delete('Content-Length')
      const res2 = await createApp().fetch(req)
      expect(res2.status).toBe(411)
      return
    }
    expect(res.status).toBe(411)
  })

  test('7b. Malformed Content-Length (non-integer) → 400 before buffering', async () => {
    const holder = await makeIdentity()
    const ucan = await selfIssuedUcan(holder)

    // `Number("invalid")` is NaN, which trivially fails both `> MAX` and the
    // `bodyBearingMethod && !hasContentLengthHeader` guards. Without an
    // explicit safe-integer check, a body-bearing request could reach body
    // buffering with a lying declared length.
    const req = new Request('http://x/write', {
      method: 'POST',
      headers: {
        Authorization: `UCAN ${ucan}`,
        'Content-Type': 'application/json',
        'Content-Length': 'not-a-number',
      },
      body: '{"name":"x"}',
    })
    // Fetch's Request constructor normalizes Content-Length on string bodies;
    // force the malformed value back onto the headers before dispatch.
    req.headers.set('Content-Length', 'not-a-number')

    const res = await createApp().fetch(req)
    expect(res.status).toBe(400)
    const body = await res.json() as { error: string }
    expect(body.error).toBe('Invalid Content-Length header')
  })

  test('8. zod-validator downstream reads the buffered body (Hono cache)', async () => {
    const holder = await makeIdentity()
    const ucan = await selfIssuedUcan(holder)

    const bodyStr = JSON.stringify({ name: 'echo' })

    const popHeader = await createUcanPopHeader({
      privateKey: holder.privateKey,
      ucanAud: holder.did,
      method: 'POST',
      path: '/write',
      rawQuery: '',
      body: bodyStr,
    })

    const res = await createApp().request('/write', {
      method: 'POST',
      headers: {
        Authorization: `UCAN ${ucan}`,
        [POP_HEADER_NAME]: popHeader,
        'Content-Type': 'application/json',
        'Content-Length': String(new TextEncoder().encode(bodyStr).length),
      },
      body: bodyStr,
    })
    expect(res.status).toBe(200)
    const body = await res.json() as { ok: true; echoed: string }
    expect(body.echoed).toBe('echo')
  })
})
