import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { db, vaultKeys, spaces, type NewVaultKey } from '../db'
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
  const { spaceId, encryptedVaultKey, encryptedVaultName, vaultKeySalt, ephemeralPublicKey, vaultKeyNonce, vaultNameNonce } = c.req.valid('json')

  try {
    // Check if vault key already exists
    const existing = await db.query.vaultKeys.findFirst({
      where: and(
        eq(vaultKeys.userId, user.userId),
        eq(vaultKeys.spaceId, spaceId)
      ),
    })

    if (existing) {
      return c.json({ error: 'Vault key already exists for this vault' }, 409)
    }

    // Insert space first, then vault key in a transaction
    const result = await db.transaction(async (tx) => {
      await tx.insert(spaces).values({
        id: spaceId,
        type: 'vault',
        ownerId: user.userId,
      })

      const insertedKeys = await tx
        .insert(vaultKeys)
        .values({
          userId: user.userId,
          spaceId,
          encryptedVaultKey,
          encryptedVaultName,
          vaultKeySalt,
          ephemeralPublicKey,
          vaultKeyNonce,
          vaultNameNonce,
        } as NewVaultKey)
        .returning()

      return insertedKeys[0]
    })

    if (!result) {
      return c.json({ error: 'Failed to insert vault key' }, 500)
    }

    return c.json({
      message: 'Vault key stored successfully',
      vaultKey: {
        id: result.id,
        spaceId: result.spaceId,
        createdAt: result.createdAt,
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
    const userVaults = await db.select({
      spaceId: vaultKeys.spaceId,
      encryptedVaultName: vaultKeys.encryptedVaultName,
      vaultNameNonce: vaultKeys.vaultNameNonce,
      ephemeralPublicKey: vaultKeys.ephemeralPublicKey,
      createdAt: vaultKeys.createdAt,
    })
      .from(spaces)
      .innerJoin(vaultKeys, and(
        eq(vaultKeys.spaceId, spaces.id),
        eq(vaultKeys.userId, user.userId),
      ))
      .where(and(
        eq(spaces.type, 'vault'),
        eq(spaces.ownerId, user.userId),
      ))
      .orderBy(vaultKeys.createdAt)

    return c.json({
      vaults: userVaults.map((vault) => ({
        spaceId: vault.spaceId,
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
 * PATCH /vault-key/:spaceId
 * Update encrypted vault name for a vault
 */
vaultRoutes.patch('/vault-key/:spaceId', zValidator('json', updateVaultNameSchema), async (c) => {
  const spaceToken = c.get('spaceToken')
  if (spaceToken) {
    return c.json({ error: 'Space tokens can only be used for push/pull operations' }, 403)
  }
  const user = c.get('user')
  const spaceId = c.req.param('spaceId')
  const { encryptedVaultName, vaultNameNonce, ephemeralPublicKey } = c.req.valid('json')

  try {
    // Check if vault key exists and belongs to user
    const existing = await db.query.vaultKeys.findFirst({
      where: and(
        eq(vaultKeys.userId, user.userId),
        eq(vaultKeys.spaceId, spaceId)
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
          eq(vaultKeys.spaceId, spaceId)
        )
      )

    return c.json({
      message: 'Vault name updated successfully',
      spaceId,
    })
  } catch (error) {
    console.error('Update vault name error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * GET /vault-key/:spaceId
 * Retrieve encrypted vault key for a user
 */
vaultRoutes.get('/vault-key/:spaceId', async (c) => {
  const spaceToken = c.get('spaceToken')
  if (spaceToken) {
    return c.json({ error: 'Space tokens can only be used for push/pull operations' }, 403)
  }
  const user = c.get('user')
  const spaceId = c.req.param('spaceId')

  try {
    const vaultKey = await db.query.vaultKeys.findFirst({
      where: and(
        eq(vaultKeys.userId, user.userId),
        eq(vaultKeys.spaceId, spaceId)
      ),
    })

    if (!vaultKey) {
      return c.json({ error: 'Vault key not found' }, 404)
    }

    return c.json({
      vaultKey: {
        spaceId: vaultKey.spaceId,
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
 * DELETE /vault/:spaceId
 * Delete a vault and all its associated data from the server
 * This includes:
 * - All CRDT changes (sync_changes table) - via FK CASCADE + partition drop trigger
 * - Vault key and configuration (vault_keys table) - via FK CASCADE
 *
 * Deleting from spaces cascades to vault_keys and sync_changes.
 */
vaultRoutes.delete('/vault/:spaceId', async (c) => {
  const spaceToken = c.get('spaceToken')
  if (spaceToken) {
    return c.json({ error: 'Space tokens can only be used for push/pull operations' }, 403)
  }
  const user = c.get('user')
  const spaceId = c.req.param('spaceId')

  try {
    // Check if vault belongs to user
    const space = await db.select({ id: spaces.id })
      .from(spaces)
      .where(and(
        eq(spaces.id, spaceId),
        eq(spaces.ownerId, user.userId),
        eq(spaces.type, 'vault'),
      ))
      .limit(1)

    if (space.length === 0) {
      return c.json({ error: 'Vault not found or access denied' }, 404)
    }

    // Delete from spaces - CASCADE handles vault_keys and sync_changes
    await db
      .delete(spaces)
      .where(
        and(
          eq(spaces.id, spaceId),
          eq(spaces.ownerId, user.userId),
          eq(spaces.type, 'vault'),
        )
      )

    return c.json({
      message: 'Vault deleted successfully',
      spaceId,
    })
  } catch (error) {
    console.error('Delete vault error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * DELETE /vaults
 * Delete ALL vault data for the authenticated user.
 * This removes all vault spaces (cascades to vault_keys and sync_changes) but keeps the account.
 */
vaultRoutes.delete('/vaults', async (c) => {
  const spaceToken = c.get('spaceToken')
  if (spaceToken) {
    return c.json({ error: 'Space tokens can only be used for push/pull operations' }, 403)
  }
  const user = c.get('user')

  try {
    await db.delete(spaces).where(
      and(
        eq(spaces.ownerId, user.userId),
        eq(spaces.type, 'vault'),
      )
    )

    return c.json({ message: 'All vault data deleted successfully' })
  } catch (error) {
    console.error('Delete all vaults error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})


export default vaultRoutes
