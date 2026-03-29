import type { Context, Next } from 'hono'
import {
  verifyUcan,
  createWebCryptoVerifier,
  decodeUcan,
  satisfies,
  spaceResource,
  type Capability,
} from '@haex-space/ucan'
import type { UcanContext } from './types'

const verify = createWebCryptoVerifier()

/**
 * UCAN Authentication Middleware
 *
 * Extracts and verifies UCAN tokens from the Authorization header.
 * Format: Authorization: UCAN <jwt-token>
 */
export const ucanAuthMiddleware = async (c: Context, next: Next) => {
  const authHeader = c.req.header('Authorization')

  if (!authHeader || !authHeader.startsWith('UCAN ')) {
    return c.json({ error: 'Unauthorized - Missing or invalid UCAN token' }, 401)
  }

  const token = authHeader.substring(5) // Remove 'UCAN ' prefix

  try {
    // Decode first for expiry/iat checks before full verification
    const decoded = decodeUcan(token)
    const now = Math.floor(Date.now() / 1000)

    // Check expiry
    if (decoded.payload.exp <= now) {
      return c.json({ error: 'Unauthorized - UCAN token expired' }, 401)
    }

    // Check not-before (iat with 30s clock skew tolerance)
    if (decoded.payload.iat > now + 30) {
      return c.json({ error: 'Unauthorized - UCAN token not yet valid' }, 401)
    }

    // Full cryptographic verification (signature + proof chain)
    const verified = await verifyUcan(token, verify)

    c.set('ucan', {
      issuerDid: verified.payload.iss,
      publicKey: verified.payload.iss,
      capabilities: verified.payload.cap,
      verifiedUcan: verified,
    } satisfies UcanContext)

    await next()
  } catch (error) {
    console.error('UCAN verification error:', error)
    return c.json({ error: 'Unauthorized - Invalid UCAN token' }, 401)
  }
}

/**
 * Check if the authenticated UCAN has a sufficient capability for a space.
 *
 * @returns A 403 Response if insufficient, or null if the capability is satisfied.
 *
 * Usage in route handlers:
 * ```ts
 * const error = requireCapability(c, spaceId, 'space/write')
 * if (error) return error
 * ```
 */
export function requireCapability(
  c: Context,
  spaceId: string,
  required: Capability,
): Response | null {
  const ucan = c.get('ucan') as UcanContext | null

  if (!ucan) {
    return c.json({ error: 'Forbidden - No UCAN context' }, 403)
  }

  const resource = spaceResource(spaceId)
  const held = ucan.capabilities[resource]

  if (!held || !satisfies(held, required)) {
    return c.json(
      { error: `Forbidden - Insufficient capability for ${resource}, requires ${required}` },
      403,
    )
  }

  return null
}
