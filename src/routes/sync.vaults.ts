import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { db, vaultKeys, type NewVaultKey } from '../db'
import { eq, and } from 'drizzle-orm'
import { vaultKeySchema, updateVaultNameSchema } from './sync.schemas'

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
  const { vaultId, encryptedVaultKey, encryptedVaultName, vaultKeySalt, vaultNameSalt, vaultKeyNonce, vaultNameNonce } = c.req.valid('json')

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
        vaultNameSalt,
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
        vaultNameSalt: vault.vaultNameSalt, // Salt for server password decryption
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
  const { encryptedVaultName, vaultNameNonce } = c.req.valid('json')

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
        vaultKeySalt: vaultKey.vaultKeySalt, // Salt for vault password decryption
        vaultNameSalt: vaultKey.vaultNameSalt, // Salt for server password decryption
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

export default vaultRoutes
