import type { Context, Next } from 'hono'
import {
  base64urlDecode,
  createJtiTtlCache,
  didToRawPublicKey,
  verifySignedAuthHeader,
} from '@haex-space/ucan'
import { eq } from 'drizzle-orm'
import { db } from '../db'
import { identities } from '../db/schema'
import type { DidContext } from './types'

const didAuthJtiCache = createJtiTtlCache({ ttlMs: 60_000 })

export interface DidAuthRequestTarget {
  method: string
  path: string
  rawQuery: string
  body: string
}

type DidAuthVerification =
  | { ok: true; did: string; publicKey: Uint8Array }
  | { ok: false; error: string }

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

function unverifiedDid(headerValue: string): string | null {
  const payloadEncoded = headerValue.split('.')[0]
  if (!payloadEncoded) return null

  try {
    const payload = JSON.parse(new TextDecoder().decode(base64urlDecode(payloadEncoded))) as { did?: unknown }
    return typeof payload.did === 'string' ? payload.did : null
  } catch {
    return null
  }
}

/** Verify a DID-signed HTTP request through the shared PoP primitive. */
export async function verifyDidAuthHeader(
  headerValue: string,
  request: DidAuthRequestTarget,
): Promise<DidAuthVerification> {
  const did = unverifiedDid(headerValue)
  if (!did) return { ok: false, error: 'Invalid payload encoding' }

  const result = await verifySignedAuthHeader({
    headerValue,
    expectedDid: did,
    ...request,
    seenJtis: didAuthJtiCache,
  })
  if (!result.ok) return { ok: false, error: result.reason }

  try {
    return {
      ok: true,
      did: result.payload.did,
      publicKey: didToRawPublicKey(result.payload.did),
    }
  } catch {
    return { ok: false, error: 'Invalid DID format' }
  }
}

/**
 * DID-Auth middleware for `Authorization: DID <payload>.<signature>`.
 * Request-line and body binding, expiration, and replay protection are
 * inherited from `@haex-space/ucan`.
 */
export const didAuthMiddleware = async (c: Context, next: Next) => {
  const authHeader = c.req.header('Authorization')

  if (!authHeader) return c.json({ error: 'Missing Authorization header' }, 401)
  if (!authHeader.startsWith('DID ')) return c.json({ error: 'Invalid auth scheme — expected DID' }, 401)

  const url = new URL(c.req.url)
  const verified = await verifyDidAuthHeader(authHeader.slice(4), {
    method: c.req.method,
    path: url.pathname,
    rawQuery: url.search.slice(1),
    body: await c.req.text(),
  })
  if (!verified.ok) return c.json({ error: verified.error }, 401)

  const didContext: DidContext = {
    did: verified.did,
    publicKey: bytesToHex(verified.publicKey),
    userId: '',
    tier: '',
  }
  c.set('didAuth', didContext)

  await next()
}

/** Resolves a DID to an identity record after DID-Auth verification. */
export async function resolveDidIdentity(did: string) {
  const [identity] = await db
    .select()
    .from(identities)
    .where(eq(identities.did, did))
    .limit(1)

  return identity ?? null
}
