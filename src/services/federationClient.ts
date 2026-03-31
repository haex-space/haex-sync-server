/**
 * Federation Client
 *
 * Builds and sends authenticated requests to remote home servers.
 * Used by the relay server to forward push/pull requests.
 */

import { getServerIdentity, signWithServerKeyAsync } from './serverIdentity'
import { db, federationLinks, federationServers } from '../db'
import { eq } from 'drizzle-orm'

function base64urlEncode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

export interface FederationLink {
  homeServerUrl: string
  ucanToken: string
}

// ── In-Memory Cache ───────────────────────────────────────────────
// Avoids a DB query on every request. Loaded once at startup,
// updated when federation links are established or removed.

const federationLinkCache = new Map<string, FederationLink>()
let cacheInitialized = false

/**
 * Load all relay federation links from DB into memory.
 * Call once at server startup.
 */
export async function initFederationLinkCache(): Promise<void> {
  const results = await db
    .select({
      spaceId: federationLinks.spaceId,
      url: federationServers.url,
      ucanToken: federationLinks.ucanToken,
    })
    .from(federationLinks)
    .innerJoin(federationServers, eq(federationLinks.serverId, federationServers.id))
    .where(eq(federationLinks.role, 'relay'))

  federationLinkCache.clear()
  for (const row of results) {
    federationLinkCache.set(row.spaceId, {
      homeServerUrl: row.url,
      ucanToken: row.ucanToken,
    })
  }
  cacheInitialized = true
  console.log(`[Federation] Link cache loaded: ${federationLinkCache.size} relay link(s)`)
}

/**
 * Update the federation link cache when a link is established or removed.
 */
export function updateFederationLinkCache(spaceId: string, link: FederationLink | null): void {
  if (link) {
    federationLinkCache.set(spaceId, link)
  } else {
    federationLinkCache.delete(spaceId)
  }
}

/**
 * Look up the federation link for a space on this (relay) server.
 * Returns the home server URL and UCAN token, or null if the space is not federated.
 * Uses in-memory cache — no DB query per request.
 */
export function getFederationLinkForSpace(spaceId: string): FederationLink | null {
  if (!cacheInitialized) {
    console.warn('[Federation] Link cache not initialized, returning null')
    return null
  }
  return federationLinkCache.get(spaceId) ?? null
}

/**
 * Get all cached federation links. Used by the WS client to connect on startup.
 */
export function getAllFederationLinks(): Map<string, FederationLink> {
  return federationLinkCache
}

/**
 * Build the FEDERATION Authorization header for a request to a home server.
 *
 * Format: FEDERATION <base64url(payload)>.<base64url(signature)>
 */
/**
 * Build a FEDERATION auth header that includes the original user's Authorization.
 * The user auth is embedded in the signed payload so the home server can verify
 * both the relay's identity AND the end user's identity/capabilities.
 */
export async function buildFederationAuthHeader(
  action: string,
  body: string,
  ucanToken: string,
  userAuthorization: string,
): Promise<string> {
  const identity = getServerIdentity()
  if (!identity) {
    throw new Error('Server identity not initialized')
  }

  // Hash the request body
  const bodyBytes = new TextEncoder().encode(body)
  const bodyHashBuffer = await crypto.subtle.digest('SHA-256', bodyBytes)
  const bodyHash = base64urlEncode(new Uint8Array(bodyHashBuffer))

  const payload = {
    did: identity.did,
    action,
    timestamp: Date.now(),
    bodyHash,
    ucan: ucanToken,
    userAuthorization,
  }

  const payloadJson = JSON.stringify(payload)
  const payloadEncoded = base64urlEncode(new TextEncoder().encode(payloadJson))

  // Sign the payload
  const payloadBytes = new TextEncoder().encode(payloadEncoded)
  const signature = await signWithServerKeyAsync(payloadBytes)
  const signatureEncoded = base64urlEncode(signature)

  return `FEDERATION ${payloadEncoded}.${signatureEncoded}`
}

/**
 * Generic federation proxy — forwards an arbitrary request to the home server.
 * Used for MLS and space operations that need relay.
 */
export async function federatedProxyAsync(
  link: FederationLink,
  method: string,
  path: string,
  userAuthorization: string,
  body?: string,
  query?: string,
): Promise<{ ok: boolean; status: number; data: unknown }> {
  const url = `${link.homeServerUrl}${path}${query ? `?${query}` : ''}`
  const action = `federation-proxy-${method.toLowerCase()}`

  const authHeader = await buildFederationAuthHeader(action, body ?? '', link.ucanToken, userAuthorization)

  const response = await fetch(url, {
    method,
    headers: {
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      'Authorization': authHeader,
    },
    ...(body ? { body } : {}),
    signal: AbortSignal.timeout(30_000),
  })

  const data = await response.json()
  return { ok: response.ok, status: response.status, data }
}

/**
 * Forward a push request to the home server.
 * Returns the home server's response.
 */
export async function federatedPushAsync(
  link: FederationLink,
  spaceId: string,
  changes: unknown[],
  userAuthorization: string,
): Promise<{ ok: boolean; status: number; data: unknown }> {
  const body = JSON.stringify({ spaceId, changes })

  const authHeader = await buildFederationAuthHeader('federation-push', body, link.ucanToken, userAuthorization)

  const response = await fetch(`${link.homeServerUrl}/federation/push`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': authHeader,
    },
    body,
    signal: AbortSignal.timeout(30_000),
  })

  const data = await response.json()
  return { ok: response.ok, status: response.status, data }
}

/**
 * Forward a pull request to the home server.
 * Returns the home server's response.
 */
export async function federatedPullAsync(
  link: FederationLink,
  params: Record<string, string>,
  userAuthorization: string,
): Promise<{ ok: boolean; status: number; data: unknown }> {
  // Build query string
  const queryString = new URLSearchParams(params).toString()
  const url = `${link.homeServerUrl}/federation/pull?${queryString}`

  // For GET requests, body is empty
  const authHeader = await buildFederationAuthHeader('federation-pull', '', link.ucanToken, userAuthorization)

  const response = await fetch(url, {
    method: 'GET',
    headers: {
      'Authorization': authHeader,
    },
    signal: AbortSignal.timeout(30_000),
  })

  const data = await response.json()
  return { ok: response.ok, status: response.status, data }
}
