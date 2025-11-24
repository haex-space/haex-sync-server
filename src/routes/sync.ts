import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { db, syncChanges, vaultKeys, type NewSyncChange, type NewVaultKey } from '../db'
import { authMiddleware } from '../middleware/auth'
import { eq, and, gt, ne, sql } from 'drizzle-orm'

const sync = new Hono()

// All sync routes require authentication
sync.use('/*', authMiddleware)

// Validation schemas
const vaultKeySchema = z.object({
  vaultId: z.string().uuid(),
  encryptedVaultKey: z.string(),
  encryptedVaultName: z.string(),
  salt: z.string(),
  vaultKeyNonce: z.string(),
  vaultNameNonce: z.string(),
})

const pushChangesSchema = z.object({
  vaultId: z.string(),
  changes: z.array(
    z.object({
      tableName: z.string(),
      rowPks: z.string(), // JSON string
      columnName: z.string().nullable(),
      hlcTimestamp: z.string(),
      deviceId: z.string().optional(),
      encryptedValue: z.string().nullable(),
      nonce: z.string().nullable(),
      batchId: z.string().optional(), // UUID for grouping related changes
      batchSeq: z.number().int().positive().optional(), // 1-based sequence within batch
      batchTotal: z.number().int().positive().optional(), // Total changes in this batch
    })
  ),
})

const pullChangesSchema = z.object({
  vaultId: z.string(),
  excludeDeviceId: z.string().optional(), // Exclude changes from this device ID
  afterUpdatedAt: z.string().optional(), // Pull changes after this server timestamp (ISO 8601)
  limit: z.coerce.number().int().min(1).max(1000).default(100), // Coerce string to number for query params
})

/**
 * POST /sync/vault-key
 * Store encrypted vault key for a user (Hybrid-Ansatz)
 */
sync.post('/vault-key', zValidator('json', vaultKeySchema), async (c) => {
  const user = c.get('user')
  const { vaultId, encryptedVaultKey, encryptedVaultName, salt, vaultKeyNonce, vaultNameNonce } = c.req.valid('json')

  try {
    // Check if vault key already exists
    const existing = await db.query.vaultKeys.findFirst({
      where: and(
        eq(vaultKeys.userId, user.userId),
        eq(vaultKeys.vaultId, vaultId)
      ),
    })

    if (existing) {
      return c.json({ error: 'Vault key already exists for this vault' }, 409)
    }

    // Insert vault key
    const insertedKeys = await db
      .insert(vaultKeys)
      .values({
        userId: user.userId,
        vaultId,
        encryptedVaultKey,
        encryptedVaultName,
        salt,
        vaultKeyNonce,
        vaultNameNonce,
      } as NewVaultKey)
      .returning()

    const newVaultKey = insertedKeys[0]
    if (!newVaultKey) {
      return c.json({ error: 'Failed to insert vault key' }, 500)
    }

    return c.json({
      message: 'Vault key stored successfully',
      vaultKey: {
        id: newVaultKey.id,
        vaultId: newVaultKey.vaultId,
        createdAt: newVaultKey.createdAt,
      },
    }, 201)
  } catch (error) {
    console.error('Store vault key error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * GET /sync/vaults
 * Retrieve all vaults for the authenticated user
 */
sync.get('/vaults', async (c) => {
  const user = c.get('user')

  try {
    const userVaults = await db.query.vaultKeys.findMany({
      where: eq(vaultKeys.userId, user.userId),
      orderBy: vaultKeys.createdAt,
    })

    return c.json({
      vaults: userVaults.map((vault) => ({
        vaultId: vault.vaultId,
        encryptedVaultName: vault.encryptedVaultName,
        vaultNameNonce: vault.vaultNameNonce,
        salt: vault.salt,
        createdAt: vault.createdAt,
      })),
    })
  } catch (error) {
    console.error('Get vaults error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * GET /sync/vault-key/:vaultId
 * Retrieve encrypted vault key for a user
 */
sync.get('/vault-key/:vaultId', async (c) => {
  const user = c.get('user')
  const vaultId = c.req.param('vaultId')

  try {
    const vaultKey = await db.query.vaultKeys.findFirst({
      where: and(
        eq(vaultKeys.userId, user.userId),
        eq(vaultKeys.vaultId, vaultId)
      ),
    })

    if (!vaultKey) {
      return c.json({ error: 'Vault key not found' }, 404)
    }

    return c.json({
      vaultKey: {
        vaultId: vaultKey.vaultId,
        encryptedVaultKey: vaultKey.encryptedVaultKey,
        encryptedVaultName: vaultKey.encryptedVaultName,
        salt: vaultKey.salt,
        vaultKeyNonce: vaultKey.vaultKeyNonce,
        vaultNameNonce: vaultKey.vaultNameNonce,
        createdAt: vaultKey.createdAt,
      },
    })
  } catch (error) {
    console.error('Get vault key error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * POST /sync/push
 * Push CRDT changes to server with unencrypted metadata for deduplication
 * Uses INSERT ... ON CONFLICT DO UPDATE to keep only latest value per cell
 * Validates batch completeness if batchId/batchSeq/batchTotal are provided
 */
sync.post('/push', zValidator('json', pushChangesSchema), async (c) => {
  const user = c.get('user')
  const { vaultId, changes } = c.req.valid('json')

  try {
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
    const result = await db.transaction(async (tx) => {
      const insertedChanges = await tx
        .insert(syncChanges)
        .values(
          changes.map((change) => ({
            userId: user.userId,
            vaultId,
            tableName: change.tableName,
            rowPks: change.rowPks,
            columnName: change.columnName,
            hlcTimestamp: change.hlcTimestamp,
            deviceId: change.deviceId,
            encryptedValue: change.encryptedValue,
            nonce: change.nonce,
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
            // Only update updatedAt if data actually changed (HLC is newer)
            updatedAt: sql`CASE WHEN EXCLUDED.hlc_timestamp > sync_changes.hlc_timestamp THEN now() ELSE sync_changes.updated_at END`,
          },
        })
        .returning({
          id: syncChanges.id,
          hlcTimestamp: syncChanges.hlcTimestamp,
        })

      return insertedChanges
    })

    return c.json({
      message: 'Changes pushed successfully',
      count: result.length,
      lastHlc: result.length > 0 ? result[result.length - 1]?.hlcTimestamp ?? null : null,
    })
  } catch (error) {
    console.error('Push changes error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * GET /sync/pull
 * Pull CRDT changes from server with unencrypted metadata
 * Client performs conflict resolution locally based on HLC timestamps
 */
sync.get('/pull', zValidator('query', pullChangesSchema), async (c) => {
  const user = c.get('user')
  const { vaultId, excludeDeviceId, afterUpdatedAt, limit } = c.req.valid('query')

  try {
    // Build query
    const whereConditions = [
      eq(syncChanges.userId, user.userId),
      eq(syncChanges.vaultId, vaultId),
    ]

    // Exclude changes from specific device (to avoid downloading own changes)
    if (excludeDeviceId !== undefined) {
      whereConditions.push(ne(syncChanges.deviceId, excludeDeviceId))
    }

    // Pull changes updated after the given server timestamp (NOT HLC timestamp!)
    // updatedAt is a PostgreSQL timestamp, afterUpdatedAt is an ISO 8601 string
    if (afterUpdatedAt !== undefined) {
      whereConditions.push(gt(syncChanges.updatedAt, new Date(afterUpdatedAt)))
    }

    // Fetch limit + 1 to check if there are more records
    const changes = await db.query.syncChanges.findMany({
      where: and(...whereConditions),
      orderBy: syncChanges.updatedAt,
      limit: limit + 1,
    })

    // Check if there are more records
    const hasMore = changes.length > limit

    // Return only the requested limit
    const returnChanges = changes.slice(0, limit)

    return c.json({
      changes: returnChanges.map((change) => ({
        tableName: change.tableName,
        rowPks: change.rowPks,
        columnName: change.columnName,
        hlcTimestamp: change.hlcTimestamp,
        encryptedValue: change.encryptedValue,
        nonce: change.nonce,
        deviceId: change.deviceId,
        updatedAt: change.updatedAt.toISOString(),
      })),
      hasMore,
    })
  } catch (error) {
    console.error('Pull changes error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * DELETE /sync/vault/:vaultId
 * Delete a vault and all its associated data from the server
 * This includes:
 * - All CRDT changes (sync_changes table)
 * - Vault key and configuration (vault_keys table)
 */
sync.delete('/vault/:vaultId', async (c) => {
  const user = c.get('user')
  const vaultId = c.req.param('vaultId')

  try {
    // Check if vault belongs to user
    const vaultKey = await db.query.vaultKeys.findFirst({
      where: and(
        eq(vaultKeys.userId, user.userId),
        eq(vaultKeys.vaultId, vaultId)
      ),
    })

    if (!vaultKey) {
      return c.json({ error: 'Vault not found or access denied' }, 404)
    }

    // Delete all sync changes for this vault
    const deletedChanges = await db
      .delete(syncChanges)
      .where(
        and(
          eq(syncChanges.userId, user.userId),
          eq(syncChanges.vaultId, vaultId)
        )
      )
      .returning({ id: syncChanges.id })

    // Delete vault key
    await db
      .delete(vaultKeys)
      .where(
        and(
          eq(vaultKeys.userId, user.userId),
          eq(vaultKeys.vaultId, vaultId)
        )
      )

    return c.json({
      message: 'Vault deleted successfully',
      deletedChangesCount: deletedChanges.length,
      vaultId,
    })
  } catch (error) {
    console.error('Delete vault error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

export default sync
