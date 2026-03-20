import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { db, vaultKeys, syncChanges, type NewVaultKey } from '../db'
import { eq, and, sql } from 'drizzle-orm'
import { vaultKeySchema, updateVaultNameSchema } from './sync.schemas'
import { getPartitionQuotaAsync } from '../services/quota'

const vaultRoutes = new Hono()

/**
 * POST /vault-key
 * Store encrypted vault key for a user (Hybrid-Ansatz)
 */
vaultRoutes.post('/vault-key', zValidator('json', vaultKeySchema), async (c) => {
  const spaceToken = c.get('spaceToken')
  if (spaceToken) {
    return c.json({ error: 'Space tokens can only be used for push/pull operations' }, 403)
  }
  const user = c.get('user')
  const { vaultId, encryptedVaultKey, encryptedVaultName, vaultKeySalt, ephemeralPublicKey, vaultKeyNonce, vaultNameNonce } = c.req.valid('json')

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
        vaultKeySalt,
        ephemeralPublicKey,
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
 * GET /vaults
 * Retrieve all vaults for the authenticated user
 */
vaultRoutes.get('/vaults', async (c) => {
  const spaceToken = c.get('spaceToken')
  if (spaceToken) {
    return c.json({ error: 'Space tokens can only be used for push/pull operations' }, 403)
  }
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
        ephemeralPublicKey: vault.ephemeralPublicKey,
        createdAt: vault.createdAt,
      })),
    })
  } catch (error) {
    console.error('Get vaults error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * PATCH /vault-key/:vaultId
 * Update encrypted vault name for a vault
 */
vaultRoutes.patch('/vault-key/:vaultId', zValidator('json', updateVaultNameSchema), async (c) => {
  const spaceToken = c.get('spaceToken')
  if (spaceToken) {
    return c.json({ error: 'Space tokens can only be used for push/pull operations' }, 403)
  }
  const user = c.get('user')
  const vaultId = c.req.param('vaultId')
  const { encryptedVaultName, vaultNameNonce, ephemeralPublicKey } = c.req.valid('json')

  try {
    // Check if vault key exists and belongs to user
    const existing = await db.query.vaultKeys.findFirst({
      where: and(
        eq(vaultKeys.userId, user.userId),
        eq(vaultKeys.vaultId, vaultId)
      ),
    })

    if (!existing) {
      return c.json({ error: 'Vault key not found' }, 404)
    }

    // Update vault name
    await db
      .update(vaultKeys)
      .set({
        encryptedVaultName,
        vaultNameNonce,
        ephemeralPublicKey,
        updatedAt: new Date(),
      })
      .where(
        and(
          eq(vaultKeys.userId, user.userId),
          eq(vaultKeys.vaultId, vaultId)
        )
      )

    return c.json({
      message: 'Vault name updated successfully',
      vaultId,
    })
  } catch (error) {
    console.error('Update vault name error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * GET /vault-key/:vaultId
 * Retrieve encrypted vault key for a user
 */
vaultRoutes.get('/vault-key/:vaultId', async (c) => {
  const spaceToken = c.get('spaceToken')
  if (spaceToken) {
    return c.json({ error: 'Space tokens can only be used for push/pull operations' }, 403)
  }
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
        vaultKeySalt: vaultKey.vaultKeySalt,
        ephemeralPublicKey: vaultKey.ephemeralPublicKey,
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
 * DELETE /vault/:vaultId
 * Delete a vault and all its associated data from the server
 * This includes:
 * - All CRDT changes (sync_changes table) - via FK CASCADE + partition drop trigger
 * - Vault key and configuration (vault_keys table)
 *
 * With partitioning enabled, deleting the vault_key triggers:
 * 1. FK CASCADE deletes sync_changes (if any in default partition)
 * 2. Trigger drops the vault's partition table (instant, no row-by-row delete)
 */
vaultRoutes.delete('/vault/:vaultId', async (c) => {
  const spaceToken = c.get('spaceToken')
  if (spaceToken) {
    return c.json({ error: 'Space tokens can only be used for push/pull operations' }, 403)
  }
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

    // Delete vault key - this cascades to sync_changes and drops the partition
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
      vaultId,
    })
  } catch (error) {
    console.error('Delete vault error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * DELETE /vaults
 * Delete ALL vault data for the authenticated user.
 * This removes all vault keys and sync changes but keeps the account (identity, spaces, etc.).
 */
vaultRoutes.delete('/vaults', async (c) => {
  const spaceToken = c.get('spaceToken')
  if (spaceToken) {
    return c.json({ error: 'Space tokens can only be used for push/pull operations' }, 403)
  }
  const user = c.get('user')

  try {
    await db.transaction(async (tx) => {
      await tx.delete(vaultKeys).where(eq(vaultKeys.userId, user.userId))
      await tx.delete(syncChanges).where(eq(syncChanges.userId, user.userId))
    })

    return c.json({ message: 'All vault data deleted successfully' })
  } catch (error) {
    console.error('Delete all vaults error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * POST /partitions/create
 * Create a new sync_changes partition with a server-generated UUID.
 * The partition is created and committed before the response is sent,
 * ensuring Supabase Realtime can see it when the client subscribes.
 *
 * Used for both vaults and spaces — each gets its own partition.
 * Respects the user's tier limit for max partitions.
 */
vaultRoutes.post('/partitions/create', async (c) => {
  const spaceToken = c.get('spaceToken')
  if (spaceToken) {
    return c.json({ error: 'Space tokens cannot create partitions' }, 403)
  }
  const user = c.get('user')

  try {
    // Check quota
    const quota = await getPartitionQuotaAsync(user.userId)
    if (!quota.canCreate) {
      return c.json({
        error: 'Partition limit reached',
        tier: quota.tier,
        maxPartitions: quota.maxPartitions,
        usedPartitions: quota.usedPartitions,
      }, 403)
    }

    const partitionId = crypto.randomUUID()
    const partitionName = 'sync_changes_' + partitionId.replace(/-/g, '_')

    // Create partition + RLS + replica identity in one statement
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS ${sql.raw(`public."${partitionName}"`)}
        PARTITION OF public.sync_changes FOR VALUES IN (${partitionId})
    `)
    await db.execute(sql`
      ALTER TABLE ${sql.raw(`public."${partitionName}"`)} ENABLE ROW LEVEL SECURITY
    `)
    await db.execute(sql`
      CREATE POLICY "Users can only access their own sync changes"
        ON ${sql.raw(`public."${partitionName}"`)} FOR SELECT
        USING ((select auth.uid()) = user_id)
    `)
    await db.execute(sql`
      CREATE POLICY "Users can only insert their own sync changes"
        ON ${sql.raw(`public."${partitionName}"`)} FOR INSERT
        WITH CHECK ((select auth.uid()) = user_id)
    `)
    await db.execute(sql`
      ALTER TABLE ${sql.raw(`public."${partitionName}"`)} REPLICA IDENTITY FULL
    `)
    // No need to add partition to publication individually.
    // The parent table sync_changes uses publish_via_partition_root=true.

    console.log(`[Partitions] Created ${partitionName} for user ${user.userId} (${quota.usedPartitions + 1}/${quota.maxPartitions})`)

    return c.json({ partitionId }, 201)
  } catch (error: any) {
    if (error?.message?.includes('already exists')) {
      return c.json({ error: 'Partition already exists' }, 409)
    }
    console.error('Create partition error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

export default vaultRoutes
