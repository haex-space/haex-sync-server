/**
 * Federation WebSocket Client
 *
 * Maintains outgoing WebSocket connections FROM this relay server TO origin servers.
 * When an origin server sends a real-time event (sync changes, membership updates),
 * this client re-broadcasts it to local clients via broadcastToSpace().
 *
 * Counterpart to federation.ws.ts which handles the origin server (accepting) side.
 */

import { getServerIdentity } from './serverIdentity'
import { getAllFederationLinks } from './federationClient'
import { broadcastToSpace } from '../routes/ws'
import { buildFederationAuthHeader } from '@haex-space/federation-sdk'

// ── Connection State ──────────────────────────────────────────────

/** Active outgoing WebSocket connections keyed by origin server URL */
const activeConnections = new Map<string, WebSocket>()

/** Track intentional disconnections to suppress auto-reconnect */
const intentionalDisconnects = new Set<string>()

/** Reconnect delay per origin server URL (exponential backoff) */
const reconnectDelays = new Map<string, number>()

const MIN_RECONNECT_DELAY_MS = 5_000
const MAX_RECONNECT_DELAY_MS = 60_000

// ── Auth Token ────────────────────────────────────────────────────

/**
 * Build a federation WS auth token.
 *
 * The token is the shared signed-auth envelope, bound to `GET /federation/ws`.
 * It is carried as a WebSocket subprotocol so the request's raw query remains
 * part of the canonical (empty-query) request target.
 */
async function buildFederationWsToken(ucanToken: string): Promise<string> {
  const identity = getServerIdentity()
  if (!identity) {
    throw new Error('Server identity not initialized')
  }

  const header = await buildFederationAuthHeader({
    serverDid: identity.did,
    privateKeyPkcs8Base64: identity.privateKeyPkcs8Base64,
    method: 'GET',
    path: '/federation/ws',
    rawQuery: '',
    body: '',
    ucanToken,
  })
  return header.slice('FEDERATION '.length)
}

// ── Connect / Disconnect ──────────────────────────────────────────

/**
 * Connect to an origin server's /federation/ws endpoint.
 * On message, re-broadcasts events to local clients via broadcastToSpace().
 * Auto-reconnects on disconnect with exponential backoff.
 * Skips if already connected to this URL.
 */
export async function connectToOriginFederationWs(originServerUrl: string, ucanToken: string): Promise<void> {
  // Skip if already connected
  if (activeConnections.has(originServerUrl)) {
    return
  }

  // Remove from intentional disconnect set (in case we're re-connecting)
  intentionalDisconnects.delete(originServerUrl)

  const token = await buildFederationWsToken(ucanToken)

  // Build WebSocket URL: https:// → wss://, http:// → ws://
  const wsUrl = originServerUrl
    .replace(/^https:\/\//, 'wss://')
    .replace(/^http:\/\//, 'ws://')

  const url = `${wsUrl}/federation/ws`

  const ws = new WebSocket(url, ['federation', token])

  ws.onopen = () => {
    console.log(`[Federation WS Client] Connected to ${originServerUrl}`)
    activeConnections.set(originServerUrl, ws)
    // Reset backoff on successful connection
    reconnectDelays.delete(originServerUrl)
  }

  ws.onmessage = (event) => {
    try {
      const data = typeof event.data === 'string' ? JSON.parse(event.data) : null
      if (data && data.spaceId) {
        broadcastToSpace(data.spaceId, data)
      }
    } catch (error) {
      console.warn('[Federation WS Client] Failed to parse message:', error)
    }
  }

  ws.onerror = (error) => {
    console.error(`[Federation WS Client] Error for ${originServerUrl}:`, error)
    // Let onclose handle reconnection
  }

  ws.onclose = () => {
    activeConnections.delete(originServerUrl)

    if (intentionalDisconnects.has(originServerUrl)) {
      intentionalDisconnects.delete(originServerUrl)
      reconnectDelays.delete(originServerUrl)
      console.log(`[Federation WS Client] Disconnected from ${originServerUrl} (intentional)`)
      return
    }

    // Auto-reconnect with exponential backoff
    const currentDelay = reconnectDelays.get(originServerUrl) ?? MIN_RECONNECT_DELAY_MS
    const nextDelay = Math.min(currentDelay * 2, MAX_RECONNECT_DELAY_MS)
    reconnectDelays.set(originServerUrl, nextDelay)

    console.log(`[Federation WS Client] Disconnected from ${originServerUrl}, reconnecting in ${currentDelay}ms`)

    setTimeout(() => {
      if (!intentionalDisconnects.has(originServerUrl)) {
        connectToOriginFederationWs(originServerUrl, ucanToken).catch(error => {
          console.error(`[Federation WS Client] Reconnect failed for ${originServerUrl}:`, error)
        })
      }
    }, currentDelay)
  }
}

/**
 * Intentionally disconnect from a specific origin server.
 * Suppresses auto-reconnect.
 */
export function disconnectFederationWs(originServerUrl: string): void {
  intentionalDisconnects.add(originServerUrl)

  const ws = activeConnections.get(originServerUrl)
  if (ws) {
    ws.close()
    activeConnections.delete(originServerUrl)
  }
}

// ── Init ──────────────────────────────────────────────────────────

/**
 * On startup, connect to all origin servers that this relay has federation links to.
 * Must be called AFTER initFederationLinkCache() has completed.
 */
export async function initFederationWsConnections(): Promise<void> {
  const identity = getServerIdentity()
  if (!identity) {
    console.log('[Federation WS Client] Server identity not configured — skipping WS connections')
    return
  }

  const allLinks = getAllFederationLinks()
  if (allLinks.size === 0) {
    console.log('[Federation WS Client] No federation links — no WS connections to establish')
    return
  }

  // Deduplicate by origin server URL (multiple spaces may point to the same server)
  const serverTokens = new Map<string, string>()
  for (const link of allLinks.values()) {
    // Use the first UCAN we find for each server (they should all be valid)
    if (!serverTokens.has(link.originServerUrl)) {
      serverTokens.set(link.originServerUrl, link.ucanToken)
    }
  }

  console.log(`[Federation WS Client] Connecting to ${serverTokens.size} origin server(s)`)

  const connectionPromises: Promise<void>[] = []
  for (const [originServerUrl, ucanToken] of serverTokens) {
    connectionPromises.push(
      connectToOriginFederationWs(originServerUrl, ucanToken).catch(error => {
        console.error(`[Federation WS Client] Failed to connect to ${originServerUrl}:`, error)
      })
    )
  }

  await Promise.allSettled(connectionPromises)
}
