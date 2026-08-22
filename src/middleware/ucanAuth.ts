import type { Context, Next } from 'hono'
import {
  verifyUcan,
  createWebCryptoVerifier,
  decodeUcan,
  verifyUcanPop,
  POP_HEADER_NAME,
  POP_ERROR_MESSAGES,
  type SpaceCap,
} from '@haex-space/ucan'
import type { UcanContext } from './types'
import { requireCapabilityWithAuthority } from './capabilities'
import { getPopJtiCache } from './popJtiCache'

const verify = createWebCryptoVerifier()

/**
 * Hard ceiling on request bodies to UCAN-authed routes. UCAN traffic carries
 * structured DB rows (see ADR 0001 — CRDT batch cap). Larger payloads use
 * the file-sync transport, which is out of the UCAN-PoP scope. The Bun
 * runtime enforces the same cap in `index.ts` — the two together defend
 * against a lying `Content-Length` header.
 */
export const MAX_UCAN_ROUTE_BODY_BYTES = 100 * 1024 * 1024

/**
 * Server-pinned upper bound on `exp - timestamp` in an accepted PoP proof.
 * Kept explicit rather than defaulted — the server MUST pin the limit; letting
 * the client float it would let a captured proof stay replay-eligible for
 * hours and pin the jti-cache into a memory-DoS shape via unique jtis.
 */
const POP_MAX_LIFETIME_MS = 60_000

/**
 * UCAN Authentication Middleware
 *
 * Extracts and verifies UCAN tokens from the Authorization header.
 * Format: Authorization: UCAN <jwt-token>
 *
 * After the UCAN chain verifies, the companion `X-UCAN-PoP` header is
 * required and verified against the request line + body. The PoP payload's
 * `did` MUST equal the UCAN's `aud` — this converts UCAN from a bearer
 * token into a proof-of-possession credential and closes the URL-target-swap
 * replay class (`requestHash` covers method + path + query + body).
 */
export const ucanAuthMiddleware = async (c: Context, next: Next) => {
  // Idempotency: two routers (`spacesRouter` and `mlsRouter`) share the
  // `/spaces` mount prefix. Every request under `/spaces/*` therefore enters
  // this middleware TWICE — first via `spacesRouter.use('/*', authDispatcher)`,
  // then via `mlsRouter.use('/*', authDispatcher)` when the request falls
  // through to the second router. The second invocation would re-add the PoP
  // `jti` to the seen-cache, see it as a duplicate, and 401 the request as a
  // replay. Detect the prior admission via the `popVerified` marker on
  // `UcanContext` and pass through untouched.
  const existing = c.get('ucan') as UcanContext | null | undefined
  if (existing?.popVerified) {
    await next()
    return
  }

  const authHeader = c.req.header('Authorization')

  if (!authHeader || !authHeader.startsWith('UCAN ')) {
    return c.json({ error: 'Unauthorized - Missing or invalid UCAN token' }, 401)
  }

  const token = authHeader.substring(5) // Remove 'UCAN ' prefix

  let verified: Awaited<ReturnType<typeof verifyUcan>>
  try {
    // Decode first for expiry/iat checks before full verification
    const decoded = decodeUcan(token)
    const now = Math.floor(Date.now() / 1000)

    if (decoded.payload.exp <= now) {
      return c.json({ error: 'Unauthorized - UCAN token expired' }, 401)
    }
    if (decoded.payload.iat > now + 30) {
      return c.json({ error: 'Unauthorized - UCAN token not yet valid' }, 401)
    }

    verified = await verifyUcan(token, verify)
  } catch (error) {
    console.error('UCAN verification error:', error)
    return c.json({ error: 'Unauthorized - Invalid UCAN token' }, 401)
  }

  const audienceDid = verified.payload.aud

  // Body-size enforcement — reject BEFORE buffering the body.
  const method = c.req.method
  const contentLengthHeader = c.req.header('Content-Length')
  const hasContentLengthHeader = contentLengthHeader !== undefined
  const contentLength = hasContentLengthHeader ? Number(contentLengthHeader) : 0
  const bodyBearingMethod = method !== 'GET' && method !== 'DELETE' && method !== 'HEAD'

  // A present Content-Length must parse to a non-negative safe integer, else
  // both size guards below trivially pass on NaN and a body-bearing request
  // could reach buffering with a lying declared length.
  if (hasContentLengthHeader && (!Number.isSafeInteger(contentLength) || contentLength < 0)) {
    return c.json({ error: 'Invalid Content-Length header' }, 400)
  }
  if (contentLength > MAX_UCAN_ROUTE_BODY_BYTES) {
    return c.json({ error: 'Request body exceeds size limit' }, 413)
  }
  if (bodyBearingMethod && !hasContentLengthHeader) {
    // Chunked / no Content-Length on a body-bearing method: refuse. UCAN
    // routes require a declared length so the size guard is a real ceiling.
    return c.json({ error: 'Content-Length header required on UCAN-authed request' }, 411)
  }

  // Safe to buffer now. Hono caches this on the Context, so a downstream
  // zValidator('json') sees the cached string without re-consuming the stream.
  const body = await c.req.text()

  const url = new URL(c.req.url)
  const rawQuery = url.search.startsWith('?') ? url.search.slice(1) : url.search

  const popHeaderValue = c.req.header(POP_HEADER_NAME)
  if (!popHeaderValue) {
    return c.json({ error: 'UCAN requests must present X-UCAN-PoP' }, 401)
  }

  const popResult = await verifyUcanPop({
    headerValue: popHeaderValue,
    expectedUcanAud: audienceDid,
    method,
    path: url.pathname,
    rawQuery,
    body,
    seenJtis: getPopJtiCache(),
    maxLifetimeMs: POP_MAX_LIFETIME_MS,
  })

  if (!popResult.ok) {
    return c.json({ error: popResult.reason }, 401)
  }

  // A UCAN says "iss grants capabilities to aud" — the bearer is aud.
  // Historically `issuerDid` was used as the caller identity, which
  // attributed delegated-leaf calls to the delegator and misfiled
  // KeyPackages, invites and MLS messages under the wrong principal.
  // Callers should read `audienceDid`; `issuerDid` remains available
  // for code that genuinely needs to know who granted the capability.
  c.set('ucan', {
    issuerDid: verified.payload.iss,
    audienceDid,
    publicKey: verified.payload.iss,
    capabilities: verified.payload.cap,
    verifiedUcan: verified,
    popVerified: true,
  } satisfies UcanContext)

  await next()
}

/**
 * Check if the authenticated UCAN has a sufficient capability for a space.
 *
 * @returns A 403 Response if insufficient, or undefined if the capability is satisfied.
 *
 * Usage in route handlers:
 * ```ts
 * const error = requireCapability(c, spaceId, 'write')
 * if (error) return error
 * ```
 */
export async function requireCapability(
  c: Context,
  spaceId: string,
  required: SpaceCap,
): Promise<Response | undefined> {
  const authorized = await requireCapabilityWithAuthority(c, spaceId, required)
  return authorized.ok ? undefined : authorized.response
}

export { POP_ERROR_MESSAGES }
