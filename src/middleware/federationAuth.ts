import type { Context, Next } from 'hono'
import {
  verifyUcan,
  createWebCryptoVerifier,
  decodeUcan,
  multibaseDecode,
  findRootIssuer,
  parseSpaceResource,
  didToPublicKey,
} from '@haex-space/ucan'
import { verifyFederatedAuth } from '@haex-space/federation-sdk'
import { eq, and } from 'drizzle-orm'
import { db, spaceMembers } from '../db'
import { getServerIdentity } from '../services/serverIdentity'
import type { FederationContext } from './types'

const verify = createWebCryptoVerifier()

function base64urlDecode(str: string): Uint8Array {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/')
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
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

/**
 * Resolve a did:web DID to its public key by fetching /.well-known/did.json
 */
async function resolveDidWebPublicKey(did: string): Promise<Uint8Array> {
  // did:web:sync.example.com → https://sync.example.com/.well-known/did.json
  // did:web:sync.example.com%3A8443 → https://sync.example.com:8443/.well-known/did.json
  const domain = did.replace('did:web:', '').replace(/%3A/g, ':')

  // Try HTTPS first (production), fall back to HTTP (development/testing)
  let response: Response
  try {
    response = await fetch(`https://${domain}/.well-known/did.json`, { signal: AbortSignal.timeout(5_000) })
  } catch {
    response = await fetch(`http://${domain}/.well-known/did.json`, { signal: AbortSignal.timeout(5_000) })
  }
  if (!response.ok) {
    throw new Error(`Failed to resolve ${did}: HTTP ${response.status}`)
  }

  const didDocument = await response.json() as { verificationMethod?: { publicKeyMultibase?: string }[] }
  const verificationMethod = didDocument.verificationMethod?.[0]
  if (!verificationMethod?.publicKeyMultibase) {
    throw new Error(`No publicKeyMultibase in DID document for ${did}`)
  }

  // publicKeyMultibase format: z<base58btc(0xed 0x01 <32-byte-key>)>
  const decoded = multibaseDecode(verificationMethod.publicKeyMultibase as string)
  // Skip the 2-byte multicodec prefix (0xed, 0x01 for Ed25519)
  if (decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error('Expected Ed25519 multicodec prefix (0xed01)')
  }
  return decoded.slice(2)
}

/**
 * Federation Auth Middleware
 *
 * Verifies server-to-server requests using the Authorization header format:
 *   Authorization: FEDERATION <base64url(json-payload)>.<base64url(ed25519-signature)>
 *
 * Payload JSON: { did, action, timestamp, bodyHash, ucan }
 *
 * Verification:
 * 1. Ed25519 signature proves server identity (did:web)
 * 2. UCAN proves a space member delegated server/relay to this server
 * 3. UCAN audience must match the signing server's DID
 */
export const federationAuthMiddleware = async (c: Context, next: Next) => {
  const authHeader = c.req.header('Authorization')

  if (!authHeader || !authHeader.startsWith('FEDERATION ')) {
    return c.json({ error: 'Invalid auth scheme — expected FEDERATION' }, 401)
  }

  const token = authHeader.slice(11) // Remove "FEDERATION "
  const dotIndex = token.indexOf('.')
  if (dotIndex === -1) {
    return c.json({ error: 'Malformed federation auth token' }, 401)
  }

  const payloadEncoded = token.slice(0, dotIndex)
  const signatureEncoded = token.slice(dotIndex + 1)

  // Decode and parse payload
  let payload: {
    did: string
    action: string
    timestamp: number
    expiresAt: number
    bodyHash: string
    ucan: string
    userAuthorization?: string
  }
  try {
    const payloadBytes = base64urlDecode(payloadEncoded)
    const payloadJson = new TextDecoder().decode(payloadBytes)
    payload = JSON.parse(payloadJson)
  } catch {
    return c.json({ error: 'Invalid payload encoding' }, 401)
  }

  // Validate required fields
  if (!payload.did || !payload.action || !payload.timestamp || !payload.expiresAt || !payload.bodyHash || !payload.ucan) {
    return c.json({ error: 'Missing required payload fields (did, action, timestamp, expiresAt, bodyHash, ucan)' }, 401)
  }

  // Must be a did:web
  if (!payload.did.startsWith('did:web:')) {
    return c.json({ error: 'Federation requires did:web server identity' }, 401)
  }

  // Check expiry
  const now = Date.now()
  if (now > payload.expiresAt) {
    return c.json({ error: 'Federation request expired' }, 401)
  }

  // Verify body hash
  const body = await c.req.text()
  const bodyBytes = new TextEncoder().encode(body)
  const bodyHashBuffer = await crypto.subtle.digest('SHA-256', bodyBytes)
  const bodyHash = base64urlEncode(new Uint8Array(bodyHashBuffer))

  if (bodyHash !== payload.bodyHash) {
    return c.json({ error: 'Invalid body hash — request body was tampered' }, 401)
  }

  // Resolve server public key from did:web
  let publicKeyBytes: Uint8Array
  try {
    publicKeyBytes = await resolveDidWebPublicKey(payload.did)
  } catch (error) {
    console.error(`[Federation] Failed to resolve ${payload.did}:`, error)
    return c.json({ error: `Failed to resolve server DID: ${payload.did}` }, 401)
  }

  // Import the public key for Ed25519 verification
  let publicKey: CryptoKey
  try {
    publicKey = await crypto.subtle.importKey(
      'raw',
      publicKeyBytes,
      { name: 'Ed25519' },
      false,
      ['verify'],
    )
  } catch {
    return c.json({ error: 'Failed to import server public key' }, 401)
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
    return c.json({ error: 'Invalid signature — server authentication failed' }, 401)
  }

  // Verify the UCAN token
  let ucanPayload: { iss: string; aud: string; cap: Record<string, string>; exp: number; iat: number }
  try {
    const decoded = decodeUcan(payload.ucan)
    ucanPayload = decoded.payload

    // Check expiry
    const nowSeconds = Math.floor(now / 1000)
    if (ucanPayload.exp <= nowSeconds) {
      return c.json({ error: 'UCAN token expired' }, 401)
    }

    // Check not-before
    if (ucanPayload.iat > nowSeconds + 30) {
      return c.json({ error: 'UCAN token not yet valid' }, 401)
    }

    // The UCAN audience must be the signing server's DID (proof-of-possession)
    if (ucanPayload.aud !== payload.did) {
      return c.json({
        error: `UCAN audience mismatch — token was issued for ${ucanPayload.aud}, but request signed by ${payload.did}`,
      }, 403)
    }

    // Full cryptographic verification (signature + proof chain)
    const verified = await verifyUcan(payload.ucan, verify)

    // Find the root issuer of the UCAN chain — the original authority
    const rootIssuerDid = findRootIssuer(verified)

    // Extract space IDs from capabilities to verify root issuer membership
    const capEntries = Object.entries(ucanPayload.cap)
    if (capEntries.length === 0) {
      return c.json({ error: 'UCAN has no capabilities' }, 403)
    }

    const relayEntry = capEntries.find(([, capability]) => capability === 'server/relay')
    if (!relayEntry) {
      return c.json({ error: 'UCAN does not grant server/relay capability' }, 403)
    }

    // Extract space ID from resource (e.g., "space:<uuid>" → "<uuid>")
    const spaceId = parseSpaceResource(relayEntry[0])
    if (!spaceId) {
      return c.json({ error: 'server/relay capability must be scoped to a space resource' }, 403)
    }

    // CRITICAL: Verify the root issuer is actually a member of this space.
    // Without this, anyone can forge a self-signed UCAN chain and gain relay access.
    const [member] = await db
      .select({ did: spaceMembers.did })
      .from(spaceMembers)
      .where(and(
        eq(spaceMembers.spaceId, spaceId),
        eq(spaceMembers.did, rootIssuerDid),
      ))
      .limit(1)

    if (!member) {
      console.warn(`[Federation] Rejected: root issuer ${rootIssuerDid} is not a member of space ${spaceId}`)
      return c.json({ error: 'UCAN root issuer is not a member of the target space' }, 403)
    }
  } catch (error) {
    console.error('[Federation] UCAN verification failed:', error)
    return c.json({ error: 'Invalid UCAN token' }, 401)
  }

  const federationContext: FederationContext = {
    serverDid: payload.did,
    serverPublicKey: publicKeyBytes,
    issuerDid: ucanPayload.iss,
    ucanToken: payload.ucan,
    ucanCapabilities: ucanPayload.cap,
    action: payload.action,
    userAuth: null,
  }

  // Verify embedded user auth if present
  if (payload.userAuthorization) {
    const serverIdentity = getServerIdentity()
    if (!serverIdentity) {
      return c.json({ error: 'Server identity not configured' }, 500)
    }

    const requestQuery = new URL(c.req.url).search.slice(1)
    const userResult = await verifyFederatedAuth({
      authHeader: payload.userAuthorization,
      verify: async (publicKey, signature, data) => {
        const key = await crypto.subtle.importKey('raw', publicKey, { name: 'Ed25519' }, false, ['verify'])
        return crypto.subtle.verify('Ed25519', key, signature, data)
      },
      didToPublicKey,
      requestBody: body,
      requestQueryString: requestQuery,
    })

    if ('error' in userResult) {
      return c.json({ error: `Federated user auth invalid: ${userResult.error}` }, 401)
    }

    // Verify serverDid matches this server
    if (userResult.serverDid !== serverIdentity.did) {
      return c.json({ error: `Request not intended for this server (expected ${serverIdentity.did}, got ${userResult.serverDid})` }, 403)
    }

    // Verify user is a member of the space
    const [member] = await db
      .select({ did: spaceMembers.did })
      .from(spaceMembers)
      .where(and(
        eq(spaceMembers.spaceId, userResult.spaceId),
        eq(spaceMembers.did, userResult.did),
      ))
      .limit(1)

    if (!member) {
      return c.json({ error: `User ${userResult.did} is not a member of space ${userResult.spaceId}` }, 403)
    }

    federationContext.userAuth = userResult
  }

  c.set('federation', federationContext)

  await next()
}

/**
 * Require that the federation context has server/relay capability for a specific space.
 * Returns a 403 Response if insufficient, or undefined if satisfied.
 */
export function requireFederationRelay(c: Context, spaceId: string): Response | undefined {
  const federation = c.get('federation') as FederationContext | null
  if (!federation) {
    return c.json({ error: 'Federation auth required' }, 401)
  }

  // Check for server/relay on either space:<spaceId> or server:<did> resource
  // Canonical form is space:<spaceId> — it scopes relay access per space
  const spaceRes = `space:${spaceId}`
  const hasRelay = federation.ucanCapabilities[spaceRes] === 'server/relay'
    || Object.values(federation.ucanCapabilities).some(cap => cap === 'server/relay')

  if (!hasRelay) {
    return c.json({
      error: `Forbidden — no server/relay capability for space ${spaceId}`,
    }, 403)
  }

  return undefined
}
