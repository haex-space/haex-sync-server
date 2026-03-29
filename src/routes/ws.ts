import { Hono } from 'hono'
import { createBunWebSocket } from 'hono/bun'
import type { WSContext } from 'hono/ws'
import { didToPublicKey } from '@haex-space/ucan'
import { eq } from 'drizzle-orm'
import { db } from '../db'
import { identities, spaceMembers } from '../db/schema'

const { upgradeWebSocket, websocket } = createBunWebSocket()

const wsApp = new Hono()

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

// ── Connection state ───────────────────────────────────────────────

/** All active WebSocket connections per DID */
const connections = new Map<string, Set<WSContext>>()

/** Cached space memberships per DID (set of spaceIds) */
const membershipCache = new Map<string, Set<string>>()

// ── Auth verification ──────────────────────────────────────────────

interface WsAuthPayload {
  did: string
  action: string
  timestamp: number
  bodyHash: string
}

async function verifyWsToken(token: string): Promise<string | null> {
  const dotIndex = token.indexOf('.')
  if (dotIndex === -1) return null

  const payloadEncoded = token.slice(0, dotIndex)
  const signatureEncoded = token.slice(dotIndex + 1)

  // Decode and parse payload
  let payload: WsAuthPayload
  try {
    const payloadBytes = base64urlDecode(payloadEncoded)
    const payloadJson = new TextDecoder().decode(payloadBytes)
    payload = JSON.parse(payloadJson)
  } catch {
    return null
  }

  // Validate fields
  if (!payload.did || payload.action !== 'ws-connect' || !payload.timestamp || !payload.bodyHash) {
    return null
  }

  // Check timestamp
  const diff = Math.abs(Date.now() - payload.timestamp)
  if (diff > TIMESTAMP_TOLERANCE_MS) {
    return null
  }

  // Extract public key from DID
  let publicKeyBytes: Uint8Array
  try {
    publicKeyBytes = didToPublicKey(payload.did)
  } catch {
    return null
  }

  // Import and verify Ed25519 signature
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

  // Check identity exists in DB
  const [identity] = await db
    .select({ id: identities.id })
    .from(identities)
    .where(eq(identities.did, payload.did))
    .limit(1)

  if (!identity) return null

  return payload.did
}

async function loadMemberships(did: string): Promise<Set<string>> {
  const rows = await db
    .select({ spaceId: spaceMembers.spaceId })
    .from(spaceMembers)
    .where(eq(spaceMembers.did, did))

  return new Set(rows.map((r) => r.spaceId))
}

// ── WebSocket endpoint ─────────────────────────────────────────────

wsApp.get(
  '/ws',
  upgradeWebSocket(async (c) => {
    const token = c.req.query('token')
    const did = token ? await verifyWsToken(token) : null

    return {
      onOpen(_event: Event, ws: WSContext) {
        if (!did) {
          ws.close(4001, 'Authentication failed')
          return
        }

        // Register connection
        if (!connections.has(did)) {
          connections.set(did, new Set())
        }
        connections.get(did)!.add(ws)

        // Load memberships in background
        loadMemberships(did).then((spaceIds) => {
          membershipCache.set(did, spaceIds)
        })
      },

      onClose(_event: Event, ws: WSContext) {
        if (!did) return

        const didConns = connections.get(did)
        if (didConns) {
          didConns.delete(ws)
          if (didConns.size === 0) {
            connections.delete(did)
            membershipCache.delete(did)
          }
        }
      },

      onMessage(event: MessageEvent) {
        // Server does not process incoming messages — push-only
      },
    }
  }),
)

// ── Broadcasting functions ─────────────────────────────────────────

export interface WsEvent {
  type: string
  [key: string]: unknown
}

/** Send an event to all connected members of a space, optionally excluding one DID */
export function broadcastToSpace(spaceId: string, event: WsEvent, excludeDid?: string) {
  const message = JSON.stringify(event)

  for (const [did, spaceIds] of membershipCache) {
    if (excludeDid && did === excludeDid) continue
    if (!spaceIds.has(spaceId)) continue

    const didConns = connections.get(did)
    if (!didConns) continue

    for (const ws of didConns) {
      try {
        ws.send(message)
      } catch {
        // Connection may have been closed — cleanup will happen in onClose
      }
    }
  }
}

/** Send an event to a specific DID (all their connected devices) */
export function sendToDid(did: string, event: WsEvent) {
  const didConns = connections.get(did)
  if (!didConns) return

  const message = JSON.stringify(event)
  for (const ws of didConns) {
    try {
      ws.send(message)
    } catch {
      // Connection may have been closed
    }
  }
}

/** Update the membership cache when a member is added or removed from a space */
export function updateMembershipCache(did: string, spaceId: string, action: 'add' | 'remove') {
  const spaceIds = membershipCache.get(did)
  if (!spaceIds) return

  if (action === 'add') {
    spaceIds.add(spaceId)
  } else {
    spaceIds.delete(spaceId)
  }
}

export { wsApp, websocket }
