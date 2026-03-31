import { Hono } from 'hono'
import { z } from 'zod'
import { eq, and, ne, sql, max, asc } from 'drizzle-orm'
import { multibaseDecode } from '@haex-space/ucan'
import {
  buildDidDocument,
  isFederationEnabled,
  getServerIdentity,
} from '../services/serverIdentity'
import { federationAuthMiddleware, requireFederationRelay } from '../middleware/federationAuth'
import { authDispatcher } from '../middleware/authDispatcher'
import {
  db,
  federationServers,
  federationLinks,
  federationEvents,
  spaces,
  spaceMembers,
  syncChanges,
  type NewSyncChange,
} from '../db'
import { pushChangesSchema, pullChangesSchema, type PushChange } from './sync.schemas'
import { validateFederationPush, resolveSpaceOwnerUserId } from './federation.helpers'
import { broadcastToSpace, updateMembershipCache } from './ws'
import { broadcastToFederatedServers, updateFederatedSpacesCache } from './federation.ws'
import { buildFederationAuthHeader, updateFederationLinkCache } from '../services/federationClient'
import { connectToHomeFederationWs } from '../services/federationWsClient'
import { didToSpkiPublicKey } from '../utils/didIdentity'
import type { FederationContext } from '../middleware/types'

const federation = new Hono()

function getCallerDid(c: any): string | null {
  const ucan = c.get('ucan')
  if (ucan) return ucan.issuerDid
  const didAuth = c.get('didAuth')
  if (didAuth) return didAuth.did
  return null
}

// ─── Public Endpoints (no auth) ──────────────────────────────────────

/**
 * GET /.well-known/did.json
 * DID Document for this server's federation identity.
 * Standard endpoint for did:web resolution.
 */
federation.get('/.well-known/did.json', (c) => {
  const didDocument = buildDidDocument()

  if (!didDocument) {
    return c.json({ error: 'Federation not configured on this server' }, 404)
  }

  return c.json(didDocument, 200, {
    'Content-Type': 'application/did+json',
    'Cache-Control': 'public, max-age=3600',
  })
})

/**
 * GET /federation/status
 * Public endpoint to check if federation is enabled on this server.
 */
federation.get('/federation/status', (c) => {
  return c.json({
    federation: isFederationEnabled(),
  })
})

/**
 * GET /federation/server-did
 * Returns this server's federation DID.
 * Public endpoint (no auth required).
 */
federation.get('/federation/server-did', (c) => {
  const identity = getServerIdentity()
  if (!identity) {
    return c.json({ error: 'Federation not configured' }, 404)
  }
  return c.json({ did: identity.did })
})

// ─── Client-Authenticated Endpoint (DID-Auth / UCAN) ───────────────

const setupSchema = z.object({
  spaceId: z.string().uuid(),
  homeServerUrl: z.string().url(),
  relayUcan: z.string().min(1),
})

/**
 * POST /federation/setup
 * Called by a CLIENT on their own relay server to initiate federation with a home server.
 * Uses normal user auth (DID-Auth or UCAN), NOT federation auth.
 *
 * Flow:
 * 1. Resolve home server DID document
 * 2. Upsert home server in federation_servers
 * 3. Upsert federation link with the client-provided relay UCAN
 * 4. Call POST {homeServerUrl}/federation/establish with FEDERATION auth
 * 5. Create local space + member entries for WebSocket routing
 */
federation.post('/federation/setup', authDispatcher, async (c) => {
  const body = await parseBody(c, setupSchema)
  if (body instanceof Response) return body

  // 1. Check federation is enabled on this server
  if (!isFederationEnabled()) {
    return c.json({ error: 'Federation not enabled on this server' }, 503)
  }

  const serverIdentity = getServerIdentity()
  if (!serverIdentity) {
    return c.json({ error: 'Server identity not configured' }, 500)
  }

  // Get the caller's DID from auth context
  const callerDid = getCallerDid(c)
  if (!callerDid) {
    return c.json({ error: 'Could not determine caller DID' }, 401)
  }

  try {
    // 2. Resolve home server DID document
    const didDocResponse = await fetch(`${body.homeServerUrl}/.well-known/did.json`, {
      signal: AbortSignal.timeout(10_000),
    })
    if (!didDocResponse.ok) {
      return c.json({ error: `Failed to resolve home server DID document: HTTP ${didDocResponse.status}` }, 502)
    }

    const didDoc = await didDocResponse.json() as {
      id?: string
      verificationMethod?: { publicKeyMultibase?: string }[]
    }

    // 3. Extract home server DID and public key from the DID document
    const homeServerDid = didDoc.id
    if (!homeServerDid) {
      return c.json({ error: 'Home server DID document missing id' }, 502)
    }

    const verificationMethod = didDoc.verificationMethod?.[0]
    if (!verificationMethod?.publicKeyMultibase) {
      return c.json({ error: 'Home server DID document missing publicKeyMultibase' }, 502)
    }

    // Decode multibase (base58btc) to raw public key bytes, then convert to hex
    const decoded = multibaseDecode(verificationMethod.publicKeyMultibase)
    if (decoded[0] !== 0xed || decoded[1] !== 0x01) {
      return c.json({ error: 'Expected Ed25519 multicodec prefix (0xed01)' }, 502)
    }
    const homeServerPublicKeyBytes = decoded.slice(2)
    const homeServerPublicKeyHex = Array.from(homeServerPublicKeyBytes as Uint8Array)
      .map((b: number) => b.toString(16).padStart(2, '0'))
      .join('')

    // 4. Upsert the home server in federation_servers
    const [server] = await db
      .insert(federationServers)
      .values({
        did: homeServerDid,
        url: body.homeServerUrl,
        publicKey: homeServerPublicKeyHex,
      })
      .onConflictDoUpdate({
        target: federationServers.did,
        set: {
          url: body.homeServerUrl,
          publicKey: homeServerPublicKeyHex,
          updatedAt: new Date(),
        },
      })
      .returning({ id: federationServers.id })

    // 5. Upsert the federation link with the client-provided relay UCAN
    const ucanExpiresAt = extractUcanExpiry(body.relayUcan)

    const [link] = await db
      .insert(federationLinks)
      .values({
        spaceId: body.spaceId,
        serverId: server!.id,
        ucanToken: body.relayUcan,
        ucanExpiresAt,
        role: 'relay',
      })
      .onConflictDoUpdate({
        target: [federationLinks.spaceId, federationLinks.serverId],
        set: {
          ucanToken: body.relayUcan,
          ucanExpiresAt,
          updatedAt: new Date(),
        },
      })
      .returning({ id: federationLinks.id })

    // 6. Update the in-memory federation link cache
    updateFederationLinkCache(body.spaceId, {
      homeServerUrl: body.homeServerUrl,
      ucanToken: body.relayUcan,
    })

    // 7. Call POST {homeServerUrl}/federation/establish with FEDERATION auth
    const establishBody = JSON.stringify({
      spaceId: body.spaceId,
      serverUrl: serverIdentity.serverUrl ?? `https://${serverIdentity.did.replace('did:web:', '')}`,
    })

    const authHeader = await buildFederationAuthHeader('federation-establish', establishBody, body.relayUcan)

    const establishResponse = await fetch(`${body.homeServerUrl}/federation/establish`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': authHeader,
      },
      body: establishBody,
      signal: AbortSignal.timeout(30_000),
    })

    if (!establishResponse.ok) {
      const errorData = await establishResponse.json().catch(() => null)
      console.error('[Federation] Establish call failed:', establishResponse.status, errorData)
      return c.json({
        error: 'Failed to establish federation with home server',
        details: errorData,
        status: establishResponse.status,
      }, 502)
    }

    // 8. Create local space + member entries so the relay server can route WebSocket notifications
    await db
      .insert(spaces)
      .values({
        id: body.spaceId,
        type: 'shared',
        ownerId: callerDid,
      })
      .onConflictDoNothing()

    const callerPublicKey = didToSpkiPublicKey(callerDid)
    await db
      .insert(spaceMembers)
      .values({
        spaceId: body.spaceId,
        publicKey: callerPublicKey,
        did: callerDid,
        label: 'Federation member',
        role: 'member',
      })
      .onConflictDoNothing()

    // Update in-memory membership cache for WebSocket routing
    updateMembershipCache(callerDid, body.spaceId, 'add')

    // Connect to home server's federation WebSocket for real-time notifications
    connectToHomeFederationWs(body.homeServerUrl, body.relayUcan).catch(err => {
      console.warn('[Federation] Failed to connect WS to home server:', err)
    })

    console.log(`[Federation] Setup complete: ${callerDid} → space ${body.spaceId} via ${homeServerDid}`)

    return c.json({
      federationLinkId: link!.id,
      homeServerDid,
      spaceId: body.spaceId,
    }, 201)
  } catch (error) {
    console.error('[Federation] Setup error:', error)
    return c.json({ error: 'Federation setup failed' }, 500)
  }
})

// ─── Authenticated Endpoints (FEDERATION auth) ──────────────────────

const federationRouter = new Hono()
federationRouter.use('/*', federationAuthMiddleware)

/**
 * POST /federation/establish
 * Establish or renew a federation link for a space.
 *
 * Called by a remote relay server that wants to participate in a space hosted on this server.
 * The FEDERATION auth header proves the remote server's identity and carries the delegated UCAN.
 *
 * Upsert behavior: If a link already exists for this (space, server), the UCAN is updated.
 */
const establishSchema = z.object({
  spaceId: z.string().uuid(),
  serverUrl: z.string().url(),
  serverName: z.string().optional(),
})

federationRouter.post('/establish', async (c) => {
  const body = await parseBody(c, establishSchema)
  if (body instanceof Response) return body
  const federationContext = c.get('federation') as FederationContext

  // Check that federation is enabled on this server
  if (!isFederationEnabled()) {
    return c.json({ error: 'Federation not enabled on this server' }, 503)
  }

  // Verify the UCAN grants server/relay for the requested space
  const relayError = requireFederationRelay(c, body.spaceId)
  if (relayError) return relayError

  // Verify the space exists on this server
  const [space] = await db
    .select({ id: spaces.id, type: spaces.type })
    .from(spaces)
    .where(eq(spaces.id, body.spaceId))
    .limit(1)

  if (!space) {
    return c.json({ error: 'Space not found on this server' }, 404)
  }

  if (space.type !== 'shared') {
    return c.json({ error: 'Federation only available for shared spaces' }, 400)
  }

  // Extract UCAN expiry for the federation link
  const ucanExpiresAt = extractUcanExpiry(federationContext.ucanToken)

  // Upsert the remote server record
  const publicKeyHex = Array.from(federationContext.serverPublicKey)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')

  const [server] = await db
    .insert(federationServers)
    .values({
      did: federationContext.serverDid,
      url: body.serverUrl,
      publicKey: publicKeyHex,
      name: body.serverName,
    })
    .onConflictDoUpdate({
      target: federationServers.did,
      set: {
        url: body.serverUrl,
        publicKey: publicKeyHex,
        name: body.serverName,
        updatedAt: new Date(),
      },
    })
    .returning({ id: federationServers.id })

  // Upsert the federation link
  const [link] = await db
    .insert(federationLinks)
    .values({
      spaceId: body.spaceId,
      serverId: server!.id,
      ucanToken: federationContext.ucanToken,
      ucanExpiresAt,
      role: 'relay',
    })
    .onConflictDoUpdate({
      target: [federationLinks.spaceId, federationLinks.serverId],
      set: {
        ucanToken: federationContext.ucanToken,
        ucanExpiresAt,
        updatedAt: new Date(),
      },
    })
    .returning({ id: federationLinks.id })

  // Log the event
  await db.insert(federationEvents).values({
    federationLinkId: link!.id,
    eventType: 'established',
    metadata: JSON.stringify({
      serverDid: federationContext.serverDid,
      issuerDid: federationContext.issuerDid,
    }),
  })

  // Update in-memory cache for WebSocket broadcasting
  updateFederatedSpacesCache(federationContext.serverDid, body.spaceId, 'add')

  console.log(`[Federation] Link established: ${federationContext.serverDid} → space ${body.spaceId}`)

  return c.json({
    federationLinkId: link!.id,
    serverId: server!.id,
    serverDid: getServerIdentity()?.did,
  }, 201)
})

/**
 * DELETE /federation/establish
 * Remove a federation link for a space.
 *
 * Called by a remote relay server when it no longer needs to participate in a space.
 */
const removeSchema = z.object({
  spaceId: z.string().uuid(),
})

federationRouter.post('/remove', async (c) => {
  const body = await parseBody(c, removeSchema)
  if (body instanceof Response) return body
  const federationContext = c.get('federation') as FederationContext

  if (!isFederationEnabled()) {
    return c.json({ error: 'Federation not enabled on this server' }, 503)
  }

  // Find the server record
  const [server] = await db
    .select({ id: federationServers.id })
    .from(federationServers)
    .where(eq(federationServers.did, federationContext.serverDid))
    .limit(1)

  if (!server) {
    return c.json({ error: 'Federation server not found' }, 404)
  }

  // Find and delete the link
  const deleted = await db
    .delete(federationLinks)
    .where(
      and(
        eq(federationLinks.spaceId, body.spaceId),
        eq(federationLinks.serverId, server.id),
      )
    )
    .returning({ id: federationLinks.id })

  if (deleted.length === 0) {
    return c.json({ error: 'Federation link not found' }, 404)
  }

  // Update in-memory cache for WebSocket broadcasting
  updateFederatedSpacesCache(federationContext.serverDid, body.spaceId, 'remove')

  console.log(`[Federation] Link removed: ${federationContext.serverDid} → space ${body.spaceId}`)

  return c.json({ removed: true })
})

// ─── Sync Relay Endpoints (on Home Server) ─────────────────────────

/**
 * POST /federation/push
 * Receive CRDT changes from a relay server.
 *
 * The relay server forwards changes from its local users.
 * Changes are billed to the space owner's quota on this (home) server.
 * Signature validation ensures changes are authentically signed by the original author.
 */
federationRouter.post('/push', async (c) => {
  const body = await parseBody(c, pushChangesSchema)
  if (body instanceof Response) return body
  const { spaceId, changes: rawChanges } = body
  const federationContext = c.get('federation') as FederationContext
  const changes = rawChanges as PushChange[]

  try {
    if (!isFederationEnabled()) {
      return c.json({ error: 'Federation not enabled on this server' }, 503)
    }

    // Verify relay capability for this space
    const relayError = requireFederationRelay(c, spaceId)
    if (relayError) return relayError

    // Resolve space owner's userId for billing
    const ownerUserId = await resolveSpaceOwnerUserId(spaceId)
    if (!ownerUserId) {
      return c.json({ error: 'Space not found or owner has no identity on this server' }, 404)
    }

    const CHUNK_SIZE = 5000

    const result = await db.transaction(async (tx) => {
      // Validate federation push (signature + ownership, no signedBy===auth check)
      const validation = await validateFederationPush(changes, spaceId, tx)
      if (!validation.valid) {
        throw new FederationPushValidationError(validation.error ?? 'Federation push validation failed')
      }

      const allInsertedChanges: { id: string; hlcTimestamp: string }[] = []

      for (let i = 0; i < changes.length; i += CHUNK_SIZE) {
        const chunk = changes.slice(i, i + CHUNK_SIZE)

        const insertedChanges = await tx
          .insert(syncChanges)
          .values(
            chunk.map((change) => ({
              userId: ownerUserId,
              spaceId,
              tableName: change.tableName,
              rowPks: change.rowPks,
              columnName: change.columnName,
              hlcTimestamp: change.hlcTimestamp,
              deviceId: change.deviceId,
              encryptedValue: change.encryptedValue,
              nonce: change.nonce,
              epoch: change.epoch ?? null,
              signature: change.signature,
              signedBy: change.signedBy,
              recordOwner: change.recordOwner,
              collaborative: change.collaborative ?? false,
            } as NewSyncChange))
          )
          .onConflictDoUpdate({
            target: [syncChanges.spaceId, syncChanges.tableName, syncChanges.rowPks, syncChanges.columnName],
            set: {
              hlcTimestamp: sql`CASE WHEN EXCLUDED.hlc_timestamp > sync_changes.hlc_timestamp THEN EXCLUDED.hlc_timestamp ELSE sync_changes.hlc_timestamp END`,
              deviceId: sql`CASE WHEN EXCLUDED.hlc_timestamp > sync_changes.hlc_timestamp THEN EXCLUDED.device_id ELSE sync_changes.device_id END`,
              encryptedValue: sql`CASE WHEN EXCLUDED.hlc_timestamp > sync_changes.hlc_timestamp THEN EXCLUDED.encrypted_value ELSE sync_changes.encrypted_value END`,
              nonce: sql`CASE WHEN EXCLUDED.hlc_timestamp > sync_changes.hlc_timestamp THEN EXCLUDED.nonce ELSE sync_changes.nonce END`,
              epoch: sql`CASE WHEN EXCLUDED.hlc_timestamp > sync_changes.hlc_timestamp THEN EXCLUDED.epoch ELSE sync_changes.epoch END`,
              signature: sql`CASE WHEN EXCLUDED.hlc_timestamp > sync_changes.hlc_timestamp THEN EXCLUDED.signature ELSE sync_changes.signature END`,
              signedBy: sql`CASE WHEN EXCLUDED.hlc_timestamp > sync_changes.hlc_timestamp THEN EXCLUDED.signed_by ELSE sync_changes.signed_by END`,
              collaborative: sql`CASE WHEN EXCLUDED.hlc_timestamp > sync_changes.hlc_timestamp THEN EXCLUDED.collaborative ELSE sync_changes.collaborative END`,
              recordOwner: sql`COALESCE(sync_changes.record_owner, EXCLUDED.record_owner)`,
              updatedAt: sql`CASE WHEN EXCLUDED.hlc_timestamp > sync_changes.hlc_timestamp THEN now() ELSE sync_changes.updated_at END`,
            },
          })
          .returning({
            id: syncChanges.id,
            hlcTimestamp: syncChanges.hlcTimestamp,
          })

        allInsertedChanges.push(...insertedChanges)
      }

      return allInsertedChanges
    })

    // Notify local users
    try {
      broadcastToSpace(spaceId, { type: 'sync', spaceId })
    } catch (e) {
      console.warn('[Federation] Local broadcast failed (non-fatal):', e)
    }

    // Notify other federated servers (exclude the sender)
    broadcastToFederatedServers(spaceId, { type: 'sync', spaceId }, federationContext.serverDid)

    return c.json({
      message: 'Changes pushed successfully',
      count: result.length,
      lastHlc: result.length > 0 ? result[result.length - 1]?.hlcTimestamp ?? null : null,
      serverTimestamp: new Date().toISOString(),
    })
  } catch (error) {
    if (error instanceof FederationPushValidationError) {
      return c.json({ error: error.message }, 403)
    }
    console.error('[Federation] Push error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * GET /federation/pull
 * Serve CRDT changes to a relay server.
 *
 * Uses the same cursor-based pagination as /sync/pull.
 * Returns all changes for the space (not scoped to a user).
 */
federationRouter.get('/pull', async (c) => {
  const query = await parseQuery(c, pullChangesSchema)
  if (query instanceof Response) return query
  const { spaceId, excludeDeviceId, afterUpdatedAt, afterTableName, afterRowPks, limit } = query

  try {
    if (!isFederationEnabled()) {
      return c.json({ error: 'Federation not enabled on this server' }, 503)
    }

    // Verify relay capability for this space
    const relayError = requireFederationRelay(c, spaceId)
    if (relayError) return relayError

    // Verify space exists and is shared
    const [space] = await db
      .select({ type: spaces.type })
      .from(spaces)
      .where(eq(spaces.id, spaceId))
      .limit(1)

    if (!space || space.type !== 'shared') {
      return c.json({ error: 'Space not found or not a shared space' }, 404)
    }

    // Step 1: Find modified rows using GROUP BY with cursor pagination
    const modifiedRowsQuery = await db
      .select({
        tableName: syncChanges.tableName,
        rowPks: syncChanges.rowPks,
        maxUpdatedAtIso: sql<string>`to_char(max(${syncChanges.updatedAt}) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`.as('max_updated_at_iso'),
      })
      .from(syncChanges)
      .where(
        and(
          eq(syncChanges.spaceId, spaceId),
          excludeDeviceId !== undefined ? ne(syncChanges.deviceId, excludeDeviceId) : undefined,
        )
      )
      .groupBy(syncChanges.tableName, syncChanges.rowPks)
      .having(
        afterUpdatedAt
          ? afterTableName && afterRowPks
            ? sql`(
                max(${syncChanges.updatedAt}) > ${afterUpdatedAt}::timestamptz
                OR (
                  max(${syncChanges.updatedAt}) = ${afterUpdatedAt}::timestamptz
                  AND (${syncChanges.tableName}, ${syncChanges.rowPks}) > (${afterTableName}, ${afterRowPks})
                )
              )`
            : sql`max(${syncChanges.updatedAt}) > ${afterUpdatedAt}::timestamptz`
          : undefined
      )
      .orderBy(asc(max(syncChanges.updatedAt)), asc(syncChanges.tableName), asc(syncChanges.rowPks))
      .limit(limit)

    if (modifiedRowsQuery.length === 0) {
      return c.json({
        changes: [],
        hasMore: false,
        serverTimestamp: new Date().toISOString(),
      })
    }

    // Step 2: Fetch ALL columns for these rows
    const rowConditions = modifiedRowsQuery.map(
      (row) => and(
        eq(syncChanges.tableName, row.tableName),
        eq(syncChanges.rowPks, row.rowPks),
      )
    )

    const allColumnsForRows = await db.query.syncChanges.findMany({
      where: and(
        eq(syncChanges.spaceId, spaceId),
        sql`(${sql.join(rowConditions, sql` OR `)})`,
      ),
      orderBy: syncChanges.updatedAt,
    })

    const hasMore = modifiedRowsQuery.length >= limit
    const lastRow = modifiedRowsQuery[modifiedRowsQuery.length - 1]
    const serverTimestamp = lastRow?.maxUpdatedAtIso ?? new Date().toISOString()

    return c.json({
      changes: allColumnsForRows.map((change) => ({
        tableName: change.tableName,
        rowPks: change.rowPks,
        columnName: change.columnName,
        hlcTimestamp: change.hlcTimestamp,
        encryptedValue: change.encryptedValue,
        nonce: change.nonce,
        deviceId: change.deviceId,
        epoch: change.epoch,
        updatedAt: change.updatedAt.toISOString(),
        signature: change.signature,
        signedBy: change.signedBy,
        recordOwner: change.recordOwner,
        collaborative: change.collaborative,
      })),
      hasMore,
      serverTimestamp,
      lastTableName: lastRow?.tableName,
      lastRowPks: lastRow?.rowPks,
    })
  } catch (error) {
    console.error('[Federation] Pull error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// Mount the authenticated federation routes
federation.route('/federation', federationRouter)

export default federation

// ─── Validation Helper ───────────────────────────────────────────────

/**
 * Parse and validate JSON body against a Zod schema.
 * Returns parsed data or a 400 Response.
 * Used instead of zValidator to avoid Hono type conflicts with nested routers.
 */
async function parseBody<T>(c: any, schema: z.ZodType<T>): Promise<T | Response> {
  const raw = await c.req.json()
  const parsed = schema.safeParse(raw)
  if (!parsed.success) {
    return c.json({ error: 'Invalid request body', details: parsed.error.issues }, 400)
  }
  return parsed.data
}

async function parseQuery<T>(c: any, schema: z.ZodType<T>): Promise<T | Response> {
  const raw = c.req.query()
  const parsed = schema.safeParse(raw)
  if (!parsed.success) {
    return c.json({ error: 'Invalid query parameters', details: parsed.error.issues }, 400)
  }
  return parsed.data
}

// ─── Error Classes ───────────────────────────────────────────────────

class FederationPushValidationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'FederationPushValidationError'
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────

function extractUcanExpiry(ucanToken: string): Date {
  try {
    // UCAN is a JWT — decode the payload (second segment)
    const parts = ucanToken.split('.')
    if (parts.length !== 3) throw new Error('Invalid JWT format')

    let base64 = parts[1]!.replace(/-/g, '+').replace(/_/g, '/')
    while (base64.length % 4 !== 0) base64 += '='

    const payload = JSON.parse(atob(base64))
    if (typeof payload.exp === 'number') {
      return new Date(payload.exp * 1000)
    }
  } catch {
    // Fall through
  }

  // Default: 30 days from now
  return new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
}
