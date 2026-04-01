/**
 * Federation WebSocket — Server-to-Server Push Notifications
 *
 * Maintains WebSocket connections from federated relay servers.
 * When changes occur in a federated space, broadcasts events to all
 * connected relay servers so they can notify their local users.
 *
 * Architecture mirrors ws.ts (user WebSocket) but scoped to server identities:
 * - Auth: FEDERATION token (server DID + UCAN) instead of DID-Auth
 * - Scope: federation_links instead of space_members
 * - Push-only: Origin server sends, relay servers receive
 */

import { Hono } from 'hono'
import { createBunWebSocket } from 'hono/bun'
import type { WSContext } from 'hono/ws'
import { eq } from 'drizzle-orm'
import { db, federationServers, federationLinks } from '../db'
import { isFederationEnabled } from '../services/serverIdentity'
import { verifyUcan, createWebCryptoVerifier, decodeUcan } from '@haex-space/ucan'

const { upgradeWebSocket, websocket: federationWebsocket } = createBunWebSocket()

const federationWsApp = new Hono()

// ── Helpers ────────────────────────────────────────────────────────

const TIMESTAMP_TOLERANCE_MS = 30_000

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

const ucanVerify = createWebCryptoVerifier()

// ── Connection state ───────────────────────────────────────────────

/** Active WebSocket connections per server DID */
const serverConnections = new Map<string, WSContext>()

/** Cached federation links per server DID: set of spaceIds this server relays */
const federatedSpacesCache = new Map<string, Set<string>>()

// ── Auth verification ──────────────────────────────────────────────

/**
 * Verify a federation WebSocket token.
 *
 * Token format: <base64url(payload)>.<base64url(signature)>
 * Payload: { did, action: "federation-ws-connect", timestamp, bodyHash, ucan }
 *
 * Returns the server DID on success, null on failure.
 */
async function verifyFederationWsToken(token: string): Promise<string | null> {
  const dotIndex = token.indexOf('.')
  if (dotIndex === -1) return null

  const payloadEncoded = token.slice(0, dotIndex)
  const signatureEncoded = token.slice(dotIndex + 1)

  let payload: {
    did: string
    action: string
    timestamp: number
    bodyHash: string
    ucan: string
  }
  try {
    const payloadBytes = base64urlDecode(payloadEncoded)
    const payloadJson = new TextDecoder().decode(payloadBytes)
    payload = JSON.parse(payloadJson)
  } catch {
    return null
  }

  // Validate fields
  if (!payload.did || payload.action !== 'federation-ws-connect' || !payload.timestamp || !payload.ucan) {
    return null
  }

  // Must be did:web
  if (!payload.did.startsWith('did:web:')) {
    return null
  }

  // Check timestamp
  const diff = Math.abs(Date.now() - payload.timestamp)
  if (diff > TIMESTAMP_TOLERANCE_MS) {
    return null
  }

  // Resolve server public key — check our federation_servers table first (cached)
  const [server] = await db
    .select({ publicKey: federationServers.publicKey })
    .from(federationServers)
    .where(eq(federationServers.did, payload.did))
    .limit(1)

  if (!server) {
    console.warn(`[Federation WS] Unknown server DID: ${payload.did}`)
    return null
  }

  // Import public key from hex
  const publicKeyBytes = new Uint8Array(
    server.publicKey.match(/.{2}/g)!.map(byte => parseInt(byte, 16))
  )

  try {
    const publicKey = await crypto.subtle.importKey(
      'raw',
      publicKeyBytes,
      { name: 'Ed25519' },
      false,
      ['verify'],
    )

    const payloadBytes = new TextEncoder().encode(payloadEncoded)
    const signatureBytes = base64urlDecode(signatureEncoded)

    const valid = await crypto.subtle.verify('Ed25519', publicKey, signatureBytes, payloadBytes)
    if (!valid) return null
  } catch {
    return null
  }

  // Verify the UCAN token
  try {
    const decoded = decodeUcan(payload.ucan)
    const now = Math.floor(Date.now() / 1000)

    if (decoded.payload.exp <= now) return null
    if (decoded.payload.aud !== payload.did) return null

    // Check for server/relay capability
    const hasRelay = Object.values(decoded.payload.cap).some(cap => cap === 'server/relay')
    if (!hasRelay) return null

    await verifyUcan(payload.ucan, ucanVerify)
  } catch {
    return null
  }

  return payload.did
}

/** Load all space IDs that a server has federation links for */
async function loadFederatedSpaces(serverDid: string): Promise<Set<string>> {
  const rows = await db
    .select({ spaceId: federationLinks.spaceId })
    .from(federationLinks)
    .innerJoin(federationServers, eq(federationLinks.serverId, federationServers.id))
    .where(eq(federationServers.did, serverDid))

  return new Set(rows.map(r => r.spaceId))
}

// ── WebSocket endpoint ─────────────────────────────────────────────

federationWsApp.get(
  '/federation/ws',
  upgradeWebSocket(async (c) => {
    if (!isFederationEnabled()) {
      return {
        onOpen(_event: Event, ws: WSContext) {
          ws.close(4003, 'Federation not enabled')
        },
      }
    }

    const token = c.req.query('token')
    const serverDid = token ? await verifyFederationWsToken(token) : null

    return {
      onOpen(_event: Event, ws: WSContext) {
        if (!serverDid) {
          ws.close(4001, 'Authentication failed')
          return
        }

        // Only one connection per server (replace existing)
        const existing = serverConnections.get(serverDid)
        if (existing) {
          try { existing.close(4002, 'Replaced by new connection') } catch {}
        }

        serverConnections.set(serverDid, ws)

        // Load federation links in background
        loadFederatedSpaces(serverDid).then((spaceIds) => {
          federatedSpacesCache.set(serverDid, spaceIds)
        })

        console.log(`[Federation WS] Server connected: ${serverDid}`)
      },

      onClose(_event: Event) {
        if (!serverDid) return

        serverConnections.delete(serverDid)
        federatedSpacesCache.delete(serverDid)

        console.log(`[Federation WS] Server disconnected: ${serverDid}`)
      },

      onMessage() {
        // Push-only — origin server sends, relay servers receive
      },
    }
  }),
)

// ── Broadcasting functions ─────────────────────────────────────────

interface FederationWsEvent {
  type: string
  [key: string]: unknown
}

/**
 * Broadcast an event to all federated servers that have a link to this space.
 * Optionally excludes one server (typically the sender of a push).
 */
export function broadcastToFederatedServers(
  spaceId: string,
  event: FederationWsEvent,
  excludeServerDid?: string,
): void {
  const message = JSON.stringify(event)

  for (const [serverDid, spaceIds] of federatedSpacesCache) {
    if (excludeServerDid && serverDid === excludeServerDid) continue
    if (!spaceIds.has(spaceId)) continue

    const ws = serverConnections.get(serverDid)
    if (!ws) continue

    try {
      ws.send(message)
    } catch {
      // Connection may have been closed — cleanup happens in onClose
    }
  }
}

/** Update the federation cache when a link is established or removed */
export function updateFederatedSpacesCache(serverDid: string, spaceId: string, action: 'add' | 'remove') {
  const spaceIds = federatedSpacesCache.get(serverDid)
  if (!spaceIds) return

  if (action === 'add') {
    spaceIds.add(spaceId)
  } else {
    spaceIds.delete(spaceId)
  }
}

export { federationWsApp, federationWebsocket }
