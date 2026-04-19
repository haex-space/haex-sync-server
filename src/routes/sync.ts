import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { db, syncChanges, spaces, type NewSyncChange } from '../db'
import { authDispatcher } from '../middleware/authDispatcher'
import { requireCapability } from '../middleware/ucanAuth'
import { resolveDidIdentity } from '../middleware/didAuth'
import { eq, and, ne, sql, max, asc, or } from 'drizzle-orm'
import { pushChangesSchema, pullChangesSchema, pullColumnsSchema, SpacePushValidationError, type PushChange } from './sync.schemas'
import { spaceResource, type Capability } from '@haex-space/ucan'
import { getSpaceType, validateSpacePush } from './sync.helpers'
import { getUserQuotaAsync } from '../services/quota'
import { getFederationLinkForSpace, federatedPushAsync, federatedPullAsync } from '../services/federationClient'
import { parseFederatedAuthHeader } from '@haex-space/federation-sdk'
import { getServerIdentity } from '../services/serverIdentity'
import vaultRoutes from './sync.vaults'
import { broadcastToSpace } from './ws'

import { validateBatches } from '../utils/syncUtils'

// Re-export sync utilities
export { validateBatches, type SyncChange, type BatchValidationError } from '../utils/syncUtils'

const sync = new Hono()

// Unified auth dispatcher: resolves UCAN or DID-Auth from request
sync.use('/*', authDispatcher)

// Mount vault routes (vault-key CRUD, vaults list, vault delete)
sync.route('/', vaultRoutes)

function getCallerDid(c: any): string | null {
  const ucan = c.get('ucan')
  if (ucan) return ucan.issuerDid
  const didAuth = c.get('didAuth')
  if (didAuth) return didAuth.did
  return null
}

/**
 * POST /sync/push
 * Push CRDT changes to server with unencrypted metadata for deduplication
 * Uses INSERT ... ON CONFLICT DO UPDATE to keep only latest value per cell
 * Validates batch completeness if batchId/batchSeq/batchTotal are provided
 */
sync.post('/push', zValidator('json', pushChangesSchema), async (c) => {
  const { spaceId, changes: rawChanges } = c.req.valid('json')

  // Cast to mutable type so validateSpacePush can set recordOwner
  const changes = rawChanges as PushChange[]

  try {
    // Federation relay: if this space is federated (we're a relay), forward to origin server
    const federationLink = getFederationLinkForSpace(spaceId)
    if (federationLink) {
      const userAuth = c.req.header('Authorization') ?? ''
      if (!userAuth) return c.json({ error: 'User authentication required' }, 401)

      const parsed = parseFederatedAuthHeader(userAuth)
      if (parsed) {
        const myDid = getServerIdentity()?.did
        if (myDid && parsed.relayDid !== myDid) {
          return c.json({ error: `Request not intended for this relay (expected ${myDid}, got ${parsed.relayDid})` }, 403)
        }
      }

      const result = await federatedPushAsync(federationLink, spaceId, changes, userAuth)
      return c.json(result.data, result.status as any)
    }

    const spaceType = await getSpaceType(spaceId)
    if (!spaceType) {
      return c.json({ error: 'Unknown space' }, 404)
    }

    const isSpaceSync = spaceType === 'shared'

    // Authorization based on space type
    if (spaceType === 'shared') {
      const capError = await requireCapability(c, spaceId, 'space/write')
      if (capError) return capError
    }

    // Resolve caller identity
    const callerDid = getCallerDid(c)!
    const identity = await resolveDidIdentity(callerDid)

    // For personal vaults, verify the user owns this space
    if (spaceType === 'vault') {
      const didAuth = c.get('didAuth')
      if (!didAuth) return c.json({ error: 'Personal vaults require DID-Auth' }, 401)
      const isOwner = await db.select({ id: spaces.id })
        .from(spaces)
        .where(and(eq(spaces.id, spaceId), eq(spaces.ownerId, callerDid)))
        .limit(1)
      if (isOwner.length === 0) {
        return c.json({ error: 'Access denied: not the vault owner' }, 403)
      }
    }

    // Space-scoped push validation
    let spaceAuthenticatedPublicKey: string | undefined
    let spaceCapability: Capability | undefined

    if (isSpaceSync) {
      const authenticatedPublicKey = identity!.publicKey
      if (!authenticatedPublicKey) {
        return c.json({ error: 'User has no registered keypair' }, 400)
      }

      const ucan = c.get('ucan')
      spaceCapability = ucan?.capabilities?.[spaceResource(spaceId)]

      // Owner via DID-Auth gets implicit admin capability (no UCAN needed)
      if (!spaceCapability && c.get('didAuth')) {
        spaceCapability = 'space/admin' as Capability
      }

      if (!spaceCapability) {
        return c.json({ error: 'No capability for this space' }, 403)
      }
      spaceAuthenticatedPublicKey = authenticatedPublicKey
    }

    // Validate batch completeness + duplicate-sequence detection.
    //
    // Delegates to validateBatches() in utils/syncUtils.ts — the previous
    // inline duplicate of this logic checked completeness before duplicates,
    // so a batch like seq=[1,1,3] with batchTotal=3 reported "Incomplete
    // batch (missing 2)" instead of "Duplicate sequence numbers", masking
    // the real client bug. The shared util has the correct check order.
    const batchError = validateBatches(changes)
    if (batchError) {
      return c.json(batchError, 400)
    }

    // All batches are complete - apply changes atomically in a transaction
    // This ensures either ALL changes are applied or NONE (on error/constraint violation)
    //
    // PostgreSQL has a limit of 65534 parameters per query.
    // Each change has ~9 parameters, so we can safely insert ~5000 changes per query.
    const CHUNK_SIZE = 5000

    // Check storage quota before accepting push
    const quota = await getUserQuotaAsync(identity!.supabaseUserId!)
    if (quota.isOverQuota) {
      return c.json({
        error: 'Storage quota exceeded',
        quota: {
          tier: quota.tier,
          maxBytes: quota.maxBytes,
          usedBytes: quota.usedBytes,
        },
      }, 413)
    }

    const result = await db.transaction(async (tx) => {
      // Validate space push inside transaction to prevent TOCTOU races
      if (isSpaceSync) {
        const validation = await validateSpacePush(changes, spaceId, spaceAuthenticatedPublicKey!, spaceCapability!, tx)
        if (!validation.valid) {
          throw new SpacePushValidationError(validation.error ?? 'Space push validation failed')
        }
      }

      const allInsertedChanges: { id: string; hlcTimestamp: string; updatedAtIso: string }[] = []

      // Process changes in chunks to avoid PostgreSQL parameter limit
      for (let i = 0; i < changes.length; i += CHUNK_SIZE) {
        const chunk = changes.slice(i, i + CHUNK_SIZE)

        const insertedChanges = await tx
          .insert(syncChanges)
          .values(
            chunk.map((change) => ({
              userId: identity!.supabaseUserId!,
              spaceId,
              tableName: change.tableName,
              rowPks: change.rowPks,
              columnName: change.columnName,
              hlcTimestamp: change.hlcTimestamp,
              deviceId: change.deviceId,
              encryptedValue: change.encryptedValue,
              nonce: change.nonce,
              epoch: change.epoch ?? null,
              // Space-specific columns
              ...(isSpaceSync ? {
                signature: change.signature,
                signedBy: change.signedBy,
                recordOwner: change.recordOwner,
                collaborative: change.collaborative ?? false,
              } : {}),
            } as NewSyncChange))
          )
          .onConflictDoUpdate({
            target: [syncChanges.spaceId, syncChanges.tableName, syncChanges.rowPks, syncChanges.columnName],
            set: {
              // Use CASE to only update if incoming HLC is newer (Last-Write-Wins)
              hlcTimestamp: sql`CASE WHEN EXCLUDED.hlc_timestamp > sync_changes.hlc_timestamp THEN EXCLUDED.hlc_timestamp ELSE sync_changes.hlc_timestamp END`,
              deviceId: sql`CASE WHEN EXCLUDED.hlc_timestamp > sync_changes.hlc_timestamp THEN EXCLUDED.device_id ELSE sync_changes.device_id END`,
              encryptedValue: sql`CASE WHEN EXCLUDED.hlc_timestamp > sync_changes.hlc_timestamp THEN EXCLUDED.encrypted_value ELSE sync_changes.encrypted_value END`,
              nonce: sql`CASE WHEN EXCLUDED.hlc_timestamp > sync_changes.hlc_timestamp THEN EXCLUDED.nonce ELSE sync_changes.nonce END`,
              epoch: sql`CASE WHEN EXCLUDED.hlc_timestamp > sync_changes.hlc_timestamp THEN EXCLUDED.epoch ELSE sync_changes.epoch END`,
              // Space-specific columns: only include when syncing a space to avoid overwriting with NULLs
              ...(isSpaceSync ? {
                signature: sql`CASE WHEN EXCLUDED.hlc_timestamp > sync_changes.hlc_timestamp THEN EXCLUDED.signature ELSE sync_changes.signature END`,
                signedBy: sql`CASE WHEN EXCLUDED.hlc_timestamp > sync_changes.hlc_timestamp THEN EXCLUDED.signed_by ELSE sync_changes.signed_by END`,
                collaborative: sql`CASE WHEN EXCLUDED.hlc_timestamp > sync_changes.hlc_timestamp THEN EXCLUDED.collaborative ELSE sync_changes.collaborative END`,
                // recordOwner: keep existing value (immutable once set)
                recordOwner: sql`COALESCE(sync_changes.record_owner, EXCLUDED.record_owner)`,
              } : {}),
              // Only update updatedAt if data actually changed (HLC is newer)
              updatedAt: sql`CASE WHEN EXCLUDED.hlc_timestamp > sync_changes.hlc_timestamp THEN now() ELSE sync_changes.updated_at END`,
            },
          })
          .returning({
            id: syncChanges.id,
            hlcTimestamp: syncChanges.hlcTimestamp,
            // Return updated_at formatted identically to the pull handler so
            // push.serverTimestamp and pull.serverTimestamp share clock and
            // precision (microseconds, Postgres server time).
            updatedAtIso: sql<string>`to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`.as('updated_at_iso'),
          })

        allInsertedChanges.push(...insertedChanges)
      }

      return allInsertedChanges
    })

    // Notify connected space members about the new changes
    try {
      broadcastToSpace(spaceId, { type: 'sync', spaceId }, callerDid)
    } catch (e) {
      console.warn('Broadcast failed (non-fatal):', e)
    }

    // Compute serverTimestamp from the Postgres `updated_at` values of the
    // rows we just wrote. ISO strings in this format sort lexicographically
    // the same as chronologically, so plain string comparison gives us max.
    let serverTimestamp: string | null = null
    for (const row of result) {
      if (serverTimestamp === null || row.updatedAtIso > serverTimestamp) {
        serverTimestamp = row.updatedAtIso
      }
    }

    return c.json({
      message: 'Changes pushed successfully',
      count: result.length,
      lastHlc: result.length > 0 ? result[result.length - 1]?.hlcTimestamp ?? null : null,
      serverTimestamp: serverTimestamp ?? new Date().toISOString(),
    })
  } catch (error) {
    if (error instanceof SpacePushValidationError) {
      return c.json({ error: error.message }, 403)
    }
    console.error('Push changes error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * GET /sync/pull
 * Pull CRDT changes from server with unencrypted metadata
 * Client performs conflict resolution locally based on HLC timestamps
 *
 * IMPORTANT: When a row has at least one column updated after afterUpdatedAt,
 * ALL columns of that row are returned. This ensures clients can insert new rows
 * even if they missed earlier syncs (prevents NOT NULL constraint violations).
 */
sync.get('/pull', zValidator('query', pullChangesSchema), async (c) => {
  const { spaceId, excludeDeviceId, afterUpdatedAt, afterTableName, afterRowPks, limit } = c.req.valid('query')

  try {
    // Federation relay: if this space is federated (we're a relay), proxy from origin server
    const federationLink = getFederationLinkForSpace(spaceId)
    if (federationLink) {
      const params: Record<string, string> = { spaceId, limit: String(limit) }
      if (excludeDeviceId) params.excludeDeviceId = excludeDeviceId
      if (afterUpdatedAt) params.afterUpdatedAt = afterUpdatedAt
      if (afterTableName) params.afterTableName = afterTableName
      if (afterRowPks) params.afterRowPks = afterRowPks
      const userAuth = c.req.header('Authorization') ?? ''
      if (!userAuth) return c.json({ error: 'User authentication required' }, 401)

      const parsed = parseFederatedAuthHeader(userAuth)
      if (parsed) {
        const myDid = getServerIdentity()?.did
        if (myDid && parsed.relayDid !== myDid) {
          return c.json({ error: `Request not intended for this relay (expected ${myDid}, got ${parsed.relayDid})` }, 403)
        }
      }

      const result = await federatedPullAsync(federationLink, params, userAuth)
      return c.json(result.data, result.status as any)
    }

    const spaceType = await getSpaceType(spaceId)
    if (!spaceType) {
      return c.json({ error: 'Unknown space' }, 404)
    }

    const isSpaceSync = spaceType === 'shared'

    // Authorization based on space type
    if (spaceType === 'shared') {
      const capError = await requireCapability(c, spaceId, 'space/read')
      if (capError) return capError
    }

    // Resolve caller identity
    const callerDid = getCallerDid(c)!
    const identity = await resolveDidIdentity(callerDid)

    // For personal vaults, verify the user owns this space
    if (spaceType === 'vault') {
      const didAuth = c.get('didAuth')
      if (!didAuth) return c.json({ error: 'Personal vaults require DID-Auth' }, 401)
      const isOwner = await db.select({ id: spaces.id })
        .from(spaces)
        .where(and(eq(spaces.id, spaceId), eq(spaces.ownerId, callerDid)))
        .limit(1)
      if (isOwner.length === 0) {
        return c.json({ error: 'Access denied: not the vault owner' }, 403)
      }
    }

    // For spaces: query by spaceId only (multiple users write to the same space)
    // For personal vaults: query by userId + spaceId (scoped to owner)
    const scopeFilter = isSpaceSync
      ? eq(syncChanges.spaceId, spaceId)
      : and(eq(syncChanges.userId, identity!.supabaseUserId!), eq(syncChanges.spaceId, spaceId))

    // Step 1: Find rows to return using GROUP BY with HAVING for cursor-based pagination
    // Uses (maxUpdatedAt, tableName, rowPks) for stable cursor - works even with bulk imports
    const modifiedRowsQuery = await db
      .select({
        tableName: syncChanges.tableName,
        rowPks: syncChanges.rowPks,
        // Get max timestamp as ISO string with full microsecond precision to avoid cursor drift
        maxUpdatedAtIso: sql<string>`to_char(max(${syncChanges.updatedAt}) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`.as('max_updated_at_iso'),
      })
      .from(syncChanges)
      .where(
        and(
          scopeFilter,
          excludeDeviceId !== undefined ? ne(syncChanges.deviceId, excludeDeviceId) : undefined,
        )
      )
      .groupBy(syncChanges.tableName, syncChanges.rowPks)
      // Use HAVING to filter based on the aggregated MAX(updated_at) for proper cursor pagination
      // Condition: (timestamp > afterTimestamp) OR (timestamp = afterTimestamp AND (tableName, rowPks) > (afterTableName, afterRowPks))
      // Note: Use timestamptz to handle timezone correctly when comparing ISO strings
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
        scopeFilter,
        sql`(${sql.join(rowConditions, sql` OR `)})`,
      ),
      orderBy: syncChanges.updatedAt,
    })

    // Check if there might be more rows
    const hasMore = modifiedRowsQuery.length >= limit

    // Get cursor values from the last row
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
        // Space-specific fields for attribution and ownership verification
        ...(isSpaceSync ? {
          signature: change.signature,
          signedBy: change.signedBy,
          recordOwner: change.recordOwner,
          collaborative: change.collaborative,
        } : {}),
      })),
      hasMore,
      serverTimestamp,
      // Secondary cursor for stable pagination (tableName, rowPks of last row)
      lastTableName: lastRow?.tableName,
      lastRowPks: lastRow?.rowPks,
    })
  } catch (error) {
    console.error('Pull changes error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * POST /sync/pull-columns
 * Pull specific column data for pending columns after schema migration
 *
 * When a device has an older schema version and receives changes with unknown columns,
 * it skips those columns and tracks them in haex_crdt_pending_columns_no_sync.
 * After the app updates and migrations add those columns, this endpoint is called
 * to fetch ALL data for those specific columns.
 *
 * Returns all rows that have data for the requested columns, with their PKs for
 * correct association during insertion.
 */
sync.post('/pull-columns', zValidator('json', pullColumnsSchema), async (c) => {
  const { spaceId, columns, limit, afterRowPks, afterTableName } = c.req.valid('json')

  try {
    const spaceType = await getSpaceType(spaceId)
    if (!spaceType) {
      return c.json({ error: 'Unknown space' }, 404)
    }

    const isSpaceSync = spaceType === 'shared'

    // Authorization based on space type
    if (spaceType === 'shared') {
      const capError = await requireCapability(c, spaceId, 'space/read')
      if (capError) return capError
    }

    // Resolve caller identity
    const callerDid = getCallerDid(c)!
    const identity = await resolveDidIdentity(callerDid)

    // For personal vaults, verify the user owns this space
    if (spaceType === 'vault') {
      const didAuth = c.get('didAuth')
      if (!didAuth) return c.json({ error: 'Personal vaults require DID-Auth' }, 401)
      const isOwner = await db.select({ id: spaces.id })
        .from(spaces)
        .where(and(eq(spaces.id, spaceId), eq(spaces.ownerId, callerDid)))
        .limit(1)
      if (isOwner.length === 0) {
        return c.json({ error: 'Access denied: not the vault owner' }, 403)
      }
    }

    const scopeFilter = isSpaceSync
      ? eq(syncChanges.spaceId, spaceId)
      : and(eq(syncChanges.userId, identity!.supabaseUserId!), eq(syncChanges.spaceId, spaceId))

    // Build conditions for each (tableName, columnName) pair
    const columnConditions = columns.map(
      (col) => and(
        eq(syncChanges.tableName, col.tableName),
        eq(syncChanges.columnName, col.columnName),
      )
    )

    // Query all data for these columns with cursor-based pagination
    const changes = await db.query.syncChanges.findMany({
      where: and(
        scopeFilter,
        or(...columnConditions),
        // Cursor-based pagination using (tableName, rowPks) as compound cursor
        afterTableName && afterRowPks
          ? sql`(${syncChanges.tableName}, ${syncChanges.rowPks}) > (${afterTableName}, ${afterRowPks})`
          : undefined,
      ),
      orderBy: [asc(syncChanges.tableName), asc(syncChanges.rowPks)],
      limit: limit + 1, // Fetch one extra to check if there are more
    })

    const hasMore = changes.length > limit
    const resultChanges = hasMore ? changes.slice(0, limit) : changes

    // Get cursor values from the last item
    const lastChange = resultChanges[resultChanges.length - 1]

    return c.json({
      changes: resultChanges.map((change) => ({
        tableName: change.tableName,
        rowPks: change.rowPks,
        columnName: change.columnName,
        hlcTimestamp: change.hlcTimestamp,
        encryptedValue: change.encryptedValue,
        nonce: change.nonce,
        deviceId: change.deviceId,
        epoch: change.epoch,
        // Space-specific fields
        ...(isSpaceSync ? {
          signature: change.signature,
          signedBy: change.signedBy,
          recordOwner: change.recordOwner,
          collaborative: change.collaborative,
        } : {}),
      })),
      hasMore,
      // Cursor for next page
      lastTableName: lastChange?.tableName,
      lastRowPks: lastChange?.rowPks,
    })
  } catch (error) {
    console.error('Pull columns error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

export default sync
