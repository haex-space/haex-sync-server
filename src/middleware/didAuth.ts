import type { Context, Next } from 'hono'
import { didToPublicKey } from '@haex-space/ucan'
import { eq } from 'drizzle-orm'
import { db } from '../db'
import { identities } from '../db/schema'
import type { DidContext } from './types'

const TIMESTAMP_TOLERANCE_MS = 30_000

function base64urlDecode(str: string): Uint8Array {
  // Restore standard base64
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/')
  // Add padding
  while (base64.length % 4 !== 0) {
    base64 += '='
  }
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

function base64urlEncode(bytes: Uint8Array): string {
  const binary = String.fromCharCode(...bytes)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

/**
 * DID-Auth Middleware
 *
 * Verifies Ed25519-signed requests using the Authorization header format:
 *   Authorization: DID <base64url(json-payload)>.<base64url(ed25519-signature)>
 *
 * Payload JSON: { did, action, timestamp, bodyHash }
 *
 * This is a pure crypto verification layer — no DB lookups.
 * Route handlers are responsible for resolving identity via resolveDidIdentity().
 */
export const didAuthMiddleware = async (c: Context, next: Next) => {
  const authHeader = c.req.header('Authorization')

  if (!authHeader) {
    return c.json({ error: 'Missing Authorization header' }, 401)
  }

  if (!authHeader.startsWith('DID ')) {
    return c.json({ error: 'Invalid auth scheme — expected DID' }, 401)
  }

  const token = authHeader.slice(4) // Remove "DID "
  const dotIndex = token.indexOf('.')
  if (dotIndex === -1) {
    return c.json({ error: 'Malformed DID auth token' }, 401)
  }

  const payloadEncoded = token.slice(0, dotIndex)
  const signatureEncoded = token.slice(dotIndex + 1)

  // Decode and parse payload
  let payload: { did: string; action: string; timestamp: number; bodyHash: string }
  try {
    const payloadBytes = base64urlDecode(payloadEncoded)
    const payloadJson = new TextDecoder().decode(payloadBytes)
    payload = JSON.parse(payloadJson)
  } catch {
    return c.json({ error: 'Invalid payload encoding' }, 401)
  }

  // Validate required fields
  if (!payload.did || !payload.action || !payload.timestamp || !payload.bodyHash) {
    return c.json({ error: 'Missing required payload fields' }, 401)
  }

  // Check timestamp within tolerance
  const now = Date.now()
  const diff = Math.abs(now - payload.timestamp)
  if (diff > TIMESTAMP_TOLERANCE_MS) {
    return c.json({ error: 'Request expired — timestamp outside tolerance' }, 401)
  }

  // Verify body hash
  const body = await c.req.text()
  const bodyBytes = new TextEncoder().encode(body)
  const bodyHashBuffer = await crypto.subtle.digest('SHA-256', bodyBytes)
  const bodyHash = base64urlEncode(new Uint8Array(bodyHashBuffer))

  if (bodyHash !== payload.bodyHash) {
    return c.json({ error: 'Invalid body hash — request body was tampered' }, 401)
  }

  // Extract public key from DID
  let publicKeyBytes: Uint8Array
  try {
    publicKeyBytes = didToPublicKey(payload.did)
  } catch {
    return c.json({ error: 'Invalid DID format' }, 401)
  }

  // Import the public key for Ed25519 verification
  let publicKey: CryptoKey
  try {
    publicKey = await crypto.subtle.importKey(
      'raw',
      publicKeyBytes,
      { name: 'Ed25519' },
      false,
      ['verify']
    )
  } catch {
    return c.json({ error: 'Failed to import public key' }, 401)
  }

  // Verify signature over the raw base64url-encoded payload bytes
  const payloadBytes = new TextEncoder().encode(payloadEncoded)
  const signatureBytes = base64urlDecode(signatureEncoded)

  let valid: boolean
  try {
    valid = await crypto.subtle.verify('Ed25519', publicKey, signatureBytes, payloadBytes)
  } catch {
    return c.json({ error: 'Signature verification failed' }, 401)
  }

  if (!valid) {
    return c.json({ error: 'Invalid signature — authentication failed' }, 401)
  }

  // Set context — userId and tier resolved later by route handlers
  const didContext: DidContext = {
    did: payload.did,
    publicKey: bytesToHex(publicKeyBytes),
    userId: '',
    tier: '',
    action: payload.action,
  }
  c.set('didAuth', didContext)

  await next()
}

/**
 * Resolves a DID to an identity record from the database.
 * To be called by route handlers after didAuthMiddleware.
 */
export async function resolveDidIdentity(did: string) {
  const [identity] = await db
    .select()
    .from(identities)
    .where(eq(identities.did, did))
    .limit(1)

  return identity ?? null
}
