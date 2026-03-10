import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { db, syncChanges, spaces, identities, type NewSyncChange } from '../db'
import { authMiddleware } from '../middleware/auth'
import { spaceTokenAuthMiddleware } from '../middleware/spaceTokenAuth'
import { verifySpaceChallengeAsync } from '@haex-space/vault-sdk'
import { eq, and, ne, sql, max, asc, or } from 'drizzle-orm'
import { pushChangesSchema, pullChangesSchema, pullColumnsSchema, SpacePushValidationError, type PushChange } from './sync.schemas'
import { isSpacePartition, getUserPublicKey, getCallerRoleByUserId, validateSpacePush } from './sync.helpers'
import vaultRoutes from './sync.vaults'

// Re-export sync utilities
export { validateBatches, type SyncChange, type BatchValidationError } from '../utils/syncUtils'

const sync = new Hono()

// Space token middleware must run BEFORE auth middleware so auth can skip when space token is present
sync.use('/*', spaceTokenAuthMiddleware)
// All sync routes require authentication (skips if space token already validated)
sync.use('/*', authMiddleware)

// Mount vault routes (vault-key CRUD, vaults list, vault delete)
sync.route('/', vaultRoutes)

/**
 * POST /sync/push
 * Push CRDT changes to server with unencrypted metadata for deduplication
 * Uses INSERT ... ON CONFLICT DO UPDATE to keep only latest value per cell
 * Validates batch completeness if batchId/batchSeq/batchTotal are provided
 */
sync.post('/push', zValidator('json', pushChangesSchema), async (c) => {
  const spaceToken = c.get('spaceToken')
  const user = spaceToken ? null : c.get('user')
  const { vaultId, changes: rawChanges } = c.req.valid('json')

  // Cast to mutable type so validateSpacePush can set recordOwner
  const changes = rawChanges as PushChange[]

  try {
    // Validate space token matches target vault
    if (spaceToken && spaceToken.spaceId !== vaultId) {
      return c.json({ error: 'Space token does not match target vault' }, 403)
    }

    // Verify challenge signature for space token auth (proof of private key possession)
    if (spaceToken) {
      const challengeTimestamp = c.req.header('X-Space-Timestamp')
      const challengeSignature = c.req.header('X-Space-Signature')
      if (!challengeTimestamp || !challengeSignature) {
        return c.json({ error: 'Space token requests require X-Space-Timestamp and X-Space-Signature headers' }, 401)
      }

      const challenge = await verifySpaceChallengeAsync(
        vaultId, challengeTimestamp, challengeSignature, spaceToken.publicKey,
      )
      if (!challenge.valid) {
        return c.json({ error: challenge.error }, 401)
      }
    }

    // Space-scoped push validation
    const isSpaceSync = !!spaceToken || await isSpacePartition(vaultId)
    let spaceAuthenticatedPublicKey: string | undefined
    let spaceRole: string | undefined

    if (isSpaceSync) {
      const authenticatedPublicKey = spaceToken
        ? spaceToken.publicKey
        : await getUserPublicKey(user!.userId)
      const role = spaceToken
        ? spaceToken.role
        : await getCallerRoleByUserId(vaultId, user!.userId)

      if (!authenticatedPublicKey) {
        return c.json({ error: 'User has no registered keypair' }, 400)
      }
      if (!role) {
        return c.json({ error: 'Not a member of this space' }, 403)
      }

      spaceAuthenticatedPublicKey = authenticatedPublicKey
      spaceRole = role
    }

    // Validate batch completeness if batch metadata is present
    const batchMap = new Map<string, typeof changes>()

    for (const change of changes) {
      if (change.batchId && change.batchSeq && change.batchTotal) {
        if (!batchMap.has(change.batchId)) {
          batchMap.set(change.batchId, [])
        }
        batchMap.get(change.batchId)!.push(change)
      }
    }

    // Validate each batch is complete
    for (const [batchId, batchChanges] of batchMap.entries()) {
      const batchTotal = batchChanges[0]?.batchTotal
      if (!batchTotal) continue

      // Check we have all sequence numbers from 1 to batchTotal
      const sequences = new Set(batchChanges.map(c => c.batchSeq))
      const missingSeqs: number[] = []

      for (let i = 1; i <= batchTotal; i++) {
        if (!sequences.has(i)) {
          missingSeqs.push(i)
        }
      }

      if (missingSeqs.length > 0) {
        return c.json({
          error: 'Incomplete batch',
          batchId,
          missingSequences: missingSeqs,
          expected: batchTotal,
          received: batchChanges.length,
        }, 400)
      }

      // Check for duplicate sequence numbers
      if (sequences.size !== batchChanges.length) {
        return c.json({
          error: 'Duplicate sequence numbers in batch',
          batchId,
        }, 400)
      }
    }

    // All batches are complete - apply changes atomically in a transaction
    // This ensures either ALL changes are applied or NONE (on error/constraint violation)
    //
    // PostgreSQL has a limit of 65534 parameters per query.
    // Each change has ~9 parameters, so we can safely insert ~5000 changes per query.
    const CHUNK_SIZE = 5000

    // Resolve effective userId
    // For spaces: use actual user's userId for traceability.
    // For space tokens (federated): look up local user by public key,
    // fall back to space owner if no local account exists.
    // True attribution is always cryptographically guaranteed via signedBy + signature.
    let effectiveUserId: string
    if (spaceToken) {
      const [localIdentity] = await db.select({ supabaseUserId: identities.supabaseUserId })
        .from(identities)
        .where(eq(identities.publicKey, spaceToken.publicKey))
        .limit(1)
      if (localIdentity?.supabaseUserId) {
        effectiveUserId = localIdentity.supabaseUserId
      } else {
        // Federated user: no local account
        const space = await db.select({ ownerId: spaces.ownerId })
          .from(spaces)
          .where(eq(spaces.id, vaultId))
          .limit(1)
        if (!space[0]) {
          return c.json({ error: 'Space not found' }, 404)
        }
        effectiveUserId = space[0].ownerId
      }
    } else {
      effectiveUserId = user!.userId
    }

    const result = await db.transaction(async (tx) => {
      // Validate space push inside transaction to prevent TOCTOU races
      if (isSpaceSync) {
        const validation = await validateSpacePush(changes, vaultId, spaceAuthenticatedPublicKey!, spaceRole!, tx)
        if (!validation.valid) {
          throw new SpacePushValidationError(validation.error ?? 'Space push validation failed')
        }
      }

      const allInsertedChanges: { id: string; hlcTimestamp: string }[] = []

      // Process changes in chunks to avoid PostgreSQL parameter limit
      for (let i = 0; i < changes.length; i += CHUNK_SIZE) {
        const chunk = changes.slice(i, i + CHUNK_SIZE)

        const insertedChanges = await tx
          .insert(syncChanges)
          .values(
            chunk.map((change) => ({
              userId: effectiveUserId,
              vaultId,
              tableName: change.tableName,
              rowPks: change.rowPks,
              columnName: change.columnName,
              hlcTimestamp: change.hlcTimestamp,
              deviceId: change.deviceId,
              encryptedValue: change.encryptedValue,
              nonce: change.nonce,
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
            target: [syncChanges.vaultId, syncChanges.tableName, syncChanges.rowPks, syncChanges.columnName],
            set: {
              // Use CASE to only update if incoming HLC is newer (Last-Write-Wins)
              hlcTimestamp: sql`CASE WHEN EXCLUDED.hlc_timestamp > sync_changes.hlc_timestamp THEN EXCLUDED.hlc_timestamp ELSE sync_changes.hlc_timestamp END`,
              deviceId: sql`CASE WHEN EXCLUDED.hlc_timestamp > sync_changes.hlc_timestamp THEN EXCLUDED.device_id ELSE sync_changes.device_id END`,
              encryptedValue: sql`CASE WHEN EXCLUDED.hlc_timestamp > sync_changes.hlc_timestamp THEN EXCLUDED.encrypted_value ELSE sync_changes.encrypted_value END`,
              nonce: sql`CASE WHEN EXCLUDED.hlc_timestamp > sync_changes.hlc_timestamp THEN EXCLUDED.nonce ELSE sync_changes.nonce END`,
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
          })

        allInsertedChanges.push(...insertedChanges)
      }

      return allInsertedChanges
    })

    return c.json({
      message: 'Changes pushed successfully',
      count: result.length,
      lastHlc: result.length > 0 ? result[result.length - 1]?.hlcTimestamp ?? null : null,
      serverTimestamp: new Date().toISOString(),
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
  const spaceToken = c.get('spaceToken')
  const user = spaceToken ? null : c.get('user')
  const { vaultId, excludeDeviceId, afterUpdatedAt, afterTableName, afterRowPks, limit } = c.req.valid('query')

  try {
    // Determine if this is a space sync
    const isSpaceSync = !!spaceToken || await isSpacePartition(vaultId)

    if (spaceToken) {
      // Space token: validate token matches target vault
      if (spaceToken.spaceId !== vaultId) {
        return c.json({ error: 'Space token does not match target vault' }, 403)
      }

      // Verify challenge signature (proof of private key possession)
      const challengeTimestamp = c.req.header('X-Space-Timestamp')
      const challengeSignature = c.req.header('X-Space-Signature')
      if (!challengeTimestamp || !challengeSignature) {
        return c.json({ error: 'Space token pull requires X-Space-Timestamp and X-Space-Signature headers' }, 401)
      }

      const challenge = await verifySpaceChallengeAsync(
        vaultId, challengeTimestamp, challengeSignature, spaceToken.publicKey,
      )
      if (!challenge.valid) {
        return c.json({ error: challenge.error }, 401)
      }
    } else if (isSpaceSync) {
      // JWT user pulling from a space: verify membership
      const role = await getCallerRoleByUserId(vaultId, user!.userId)
      if (!role) {
        return c.json({ error: 'Not a member of this space' }, 403)
      }
    }

    // For spaces: query by vaultId only (multiple users write to the same space)
    // For personal vaults: query by userId + vaultId (scoped to owner)
    const scopeFilter = isSpaceSync
      ? eq(syncChanges.vaultId, vaultId)
      : and(eq(syncChanges.userId, user!.userId), eq(syncChanges.vaultId, vaultId))

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
  const spaceToken = c.get('spaceToken')
  const user = spaceToken ? null : c.get('user')
  const { vaultId, columns, limit, afterRowPks, afterTableName } = c.req.valid('json')

  try {
    const isSpaceSync = !!spaceToken || await isSpacePartition(vaultId)

    if (spaceToken) {
      if (spaceToken.spaceId !== vaultId) {
        return c.json({ error: 'Space token does not match target vault' }, 403)
      }

      // Verify challenge signature (proof of private key possession)
      const challengeTimestamp = c.req.header('X-Space-Timestamp')
      const challengeSignature = c.req.header('X-Space-Signature')
      if (!challengeTimestamp || !challengeSignature) {
        return c.json({ error: 'Space token pull requires X-Space-Timestamp and X-Space-Signature headers' }, 401)
      }

      const challenge = await verifySpaceChallengeAsync(
        vaultId, challengeTimestamp, challengeSignature, spaceToken.publicKey,
      )
      if (!challenge.valid) {
        return c.json({ error: challenge.error }, 401)
      }
    } else if (isSpaceSync) {
      const role = await getCallerRoleByUserId(vaultId, user!.userId)
      if (!role) {
        return c.json({ error: 'Not a member of this space' }, 403)
      }
    }

    const scopeFilter = isSpaceSync
      ? eq(syncChanges.vaultId, vaultId)
      : and(eq(syncChanges.userId, user!.userId), eq(syncChanges.vaultId, vaultId))

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
