/**
 * Federation WebSocket Client
 *
 * Maintains outgoing WebSocket connections FROM this relay server TO home servers.
 * When a home server sends a real-time event (sync changes, membership updates),
 * this client re-broadcasts it to local clients via broadcastToSpace().
 *
 * Counterpart to federation.ws.ts which handles the home server (accepting) side.
 */

import { getServerIdentity, signWithServerKeyAsync } from './serverIdentity'
import { getAllFederationLinks } from './federationClient'
import { broadcastToSpace } from '../routes/ws'

function base64urlEncode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

// ── Connection State ──────────────────────────────────────────────

/** Active outgoing WebSocket connections keyed by home server URL */
const activeConnections = new Map<string, WebSocket>()

/** Track intentional disconnections to suppress auto-reconnect */
const intentionalDisconnects = new Set<string>()

/** Reconnect delay per home server URL (exponential backoff) */
const reconnectDelays = new Map<string, number>()

const MIN_RECONNECT_DELAY_MS = 5_000
const MAX_RECONNECT_DELAY_MS = 60_000

// ── Auth Token ────────────────────────────────────────────────────

/**
 * Build a federation WS auth token.
 *
 * Format: <base64url(payload)>.<base64url(signature)>
 * Payload: { did, action: "federation-ws-connect", timestamp, bodyHash, ucan }
 */
async function buildFederationWsToken(ucanToken: string): Promise<string> {
  const identity = getServerIdentity()
  if (!identity) {
    throw new Error('Server identity not initialized')
  }

  // SHA-256 of empty string (no body for WS connect)
  const emptyHash = await crypto.subtle.digest('SHA-256', new Uint8Array(0))
  const bodyHash = base64urlEncode(new Uint8Array(emptyHash))

  const payload = {
    did: identity.did,
    action: 'federation-ws-connect',
    timestamp: Date.now(),
    bodyHash,
    ucan: ucanToken,
  }

  const payloadJson = JSON.stringify(payload)
  const payloadEncoded = base64urlEncode(new TextEncoder().encode(payloadJson))

  const payloadBytes = new TextEncoder().encode(payloadEncoded)
  const signature = await signWithServerKeyAsync(payloadBytes)
  const signatureEncoded = base64urlEncode(signature)

  return `${payloadEncoded}.${signatureEncoded}`
}

// ── Connect / Disconnect ──────────────────────────────────────────

/**
 * Connect to a home server's /federation/ws endpoint.
 * On message, re-broadcasts events to local clients via broadcastToSpace().
 * Auto-reconnects on disconnect with exponential backoff.
 * Skips if already connected to this URL.
 */
export async function connectToHomeFederationWs(homeServerUrl: string, ucanToken: string): Promise<void> {
  // Skip if already connected
  if (activeConnections.has(homeServerUrl)) {
    return
  }

  // Remove from intentional disconnect set (in case we're re-connecting)
  intentionalDisconnects.delete(homeServerUrl)

  const token = await buildFederationWsToken(ucanToken)

  // Build WebSocket URL: https:// → wss://, http:// → ws://
  const wsUrl = homeServerUrl
    .replace(/^https:\/\//, 'wss://')
    .replace(/^http:\/\//, 'ws://')

  const url = `${wsUrl}/federation/ws?token=${encodeURIComponent(token)}`

  const ws = new WebSocket(url)

  ws.onopen = () => {
    console.log(`[Federation WS Client] Connected to ${homeServerUrl}`)
    activeConnections.set(homeServerUrl, ws)
    // Reset backoff on successful connection
    reconnectDelays.delete(homeServerUrl)
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
    console.error(`[Federation WS Client] Error for ${homeServerUrl}:`, error)
    // Let onclose handle reconnection
  }

  ws.onclose = () => {
    activeConnections.delete(homeServerUrl)

    if (intentionalDisconnects.has(homeServerUrl)) {
      intentionalDisconnects.delete(homeServerUrl)
      reconnectDelays.delete(homeServerUrl)
      console.log(`[Federation WS Client] Disconnected from ${homeServerUrl} (intentional)`)
      return
    }

    // Auto-reconnect with exponential backoff
    const currentDelay = reconnectDelays.get(homeServerUrl) ?? MIN_RECONNECT_DELAY_MS
    const nextDelay = Math.min(currentDelay * 2, MAX_RECONNECT_DELAY_MS)
    reconnectDelays.set(homeServerUrl, nextDelay)

    console.log(`[Federation WS Client] Disconnected from ${homeServerUrl}, reconnecting in ${currentDelay}ms`)

    setTimeout(() => {
      if (!intentionalDisconnects.has(homeServerUrl)) {
        connectToHomeFederationWs(homeServerUrl, ucanToken).catch(error => {
          console.error(`[Federation WS Client] Reconnect failed for ${homeServerUrl}:`, error)
        })
      }
    }, currentDelay)
  }
}

/**
 * Intentionally disconnect from a specific home server.
 * Suppresses auto-reconnect.
 */
export function disconnectFederationWs(homeServerUrl: string): void {
  intentionalDisconnects.add(homeServerUrl)

  const ws = activeConnections.get(homeServerUrl)
  if (ws) {
    ws.close()
    activeConnections.delete(homeServerUrl)
  }
}

// ── Init ──────────────────────────────────────────────────────────

/**
 * On startup, connect to all home servers that this relay has federation links to.
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

  // Deduplicate by home server URL (multiple spaces may point to the same server)
  const serverTokens = new Map<string, string>()
  for (const link of allLinks.values()) {
    // Use the first UCAN we find for each server (they should all be valid)
    if (!serverTokens.has(link.homeServerUrl)) {
      serverTokens.set(link.homeServerUrl, link.ucanToken)
    }
  }

  console.log(`[Federation WS Client] Connecting to ${serverTokens.size} home server(s)`)

  const connectionPromises: Promise<void>[] = []
  for (const [homeServerUrl, ucanToken] of serverTokens) {
    connectionPromises.push(
      connectToHomeFederationWs(homeServerUrl, ucanToken).catch(error => {
        console.error(`[Federation WS Client] Failed to connect to ${homeServerUrl}:`, error)
      })
    )
  }

  await Promise.allSettled(connectionPromises)
}
