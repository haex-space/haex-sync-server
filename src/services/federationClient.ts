/**
 * Federation Client
 *
 * Builds and sends authenticated requests to remote origin servers.
 * Used by the relay server to forward push/pull requests.
 */

import { getServerIdentity } from './serverIdentity'
import { buildFederationAuthHeader as sdkBuildFederationAuthHeader } from '@haex-space/federation-sdk'
import { db, federationLinks, federationServers } from '../db'
import { eq } from 'drizzle-orm'

export interface FederationLink {
  originServerUrl: string
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
      originServerUrl: row.url,
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
 * Returns the origin server URL and UCAN token, or null if the space is not federated.
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
 * Build a FEDERATION auth header that includes the original user's Authorization.
 * Delegates to @haex-space/federation-sdk.
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

  return sdkBuildFederationAuthHeader({
    serverDid: identity.did,
    privateKeyPkcs8Base64: identity.privateKeyPkcs8Base64,
    action,
    body,
    ucanToken,
    userAuthorization,
  })
}

/**
 * Generic federation proxy — forwards an arbitrary request to the origin server.
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
  const url = `${link.originServerUrl}${path}${query ? `?${query}` : ''}`
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
 * Forward a push request to the origin server.
 * Returns the origin server's response.
 */
export async function federatedPushAsync(
  link: FederationLink,
  spaceId: string,
  changes: unknown[],
  userAuthorization: string,
): Promise<{ ok: boolean; status: number; data: unknown }> {
  const body = JSON.stringify({ spaceId, changes })

  const authHeader = await buildFederationAuthHeader('federation-push', body, link.ucanToken, userAuthorization)

  const response = await fetch(`${link.originServerUrl}/federation/push`, {
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
 * Forward a pull request to the origin server.
 * Returns the origin server's response.
 */
export async function federatedPullAsync(
  link: FederationLink,
  params: Record<string, string>,
  userAuthorization: string,
): Promise<{ ok: boolean; status: number; data: unknown }> {
  // Build query string
  const queryString = new URLSearchParams(params).toString()
  const url = `${link.originServerUrl}/federation/pull?${queryString}`

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
