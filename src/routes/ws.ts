import { Hono } from 'hono'
import { createBunWebSocket } from 'hono/bun'
import type { WSContext } from 'hono/ws'
import { eq } from 'drizzle-orm'
import { db } from '../db'
import { identities, spaceMembers } from '../db/schema'
import { verifyDidAuthHeader } from '../middleware/didAuth'

const { upgradeWebSocket, websocket } = createBunWebSocket()

const wsApp = new Hono()

// ── Helpers ────────────────────────────────────────────────────────

// ── Connection state ───────────────────────────────────────────────

/** All active WebSocket connections per DID */
const connections = new Map<string, Set<WSContext>>()

/** Cached space memberships per DID (set of spaceIds) */
const membershipCache = new Map<string, Set<string>>()

// ── Auth verification ──────────────────────────────────────────────

async function verifyWsToken(token: string): Promise<string | null> {
  const verified = await verifyDidAuthHeader(token, {
    method: 'GET',
    path: '/ws',
    // `token` itself is query data, so including it would make the signature
    // self-referential. The route is nevertheless bound by this fixed target.
    rawQuery: '',
    body: '',
  })
  if (!verified.ok) return null

  // Check identity exists in DB
  const [identity] = await db
    .select({ id: identities.id })
    .from(identities)
    .where(eq(identities.did, verified.did))
    .limit(1)

  if (!identity) return null

  return verified.did
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
