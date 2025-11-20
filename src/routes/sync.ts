import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { db, syncChanges, vaultKeys, type NewSyncChange, type NewVaultKey } from '../db'
import { authMiddleware } from '../middleware/auth'
import { eq, and, gt, ne } from 'drizzle-orm'

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
      deviceId: z.string().optional(),
      encryptedData: z.string(),
      nonce: z.string(),
    })
  ),
})

const pullChangesSchema = z.object({
  vaultId: z.string(),
  excludeDeviceId: z.string().optional(), // Exclude changes from this device ID
  afterCreatedAt: z.string().optional(), // Pull changes after this timestamp (ISO 8601)
  limit: z.number().int().min(1).max(1000).default(100),
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
 * Push encrypted CRDT changes to server (Zero-Knowledge)
 * Each change contains fully encrypted CRDT data (metadata + value)
 */
sync.post('/push', zValidator('json', pushChangesSchema), async (c) => {
  const user = c.get('user')
  const { vaultId, changes } = c.req.valid('json')

  try {
    // Insert changes
    const insertedChanges = await db
      .insert(syncChanges)
      .values(
        changes.map((change) => ({
          userId: user.userId,
          vaultId,
          deviceId: change.deviceId,
          encryptedData: change.encryptedData,
          nonce: change.nonce,
        } as NewSyncChange))
      )
      .returning({
        id: syncChanges.id,
        createdAt: syncChanges.createdAt,
      })

    return c.json({
      message: 'Changes pushed successfully',
      count: insertedChanges.length,
      changes: insertedChanges,
    })
  } catch (error) {
    console.error('Push changes error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * POST /sync/pull
 * Pull encrypted CRDT changes from server (Zero-Knowledge)
 * Client performs decryption and conflict resolution locally
 */
sync.post('/pull', zValidator('json', pullChangesSchema), async (c) => {
  const user = c.get('user')
  const { vaultId, excludeDeviceId, afterCreatedAt, limit } = c.req.valid('json')

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

    if (afterCreatedAt !== undefined) {
      whereConditions.push(gt(syncChanges.createdAt, new Date(afterCreatedAt)))
    }

    // Fetch limit + 1 to check if there are more records
    const changes = await db.query.syncChanges.findMany({
      where: and(...whereConditions),
      orderBy: syncChanges.createdAt,
      limit: limit + 1,
    })

    // Check if there are more records
    const hasMore = changes.length > limit

    // Return only the requested limit
    const returnChanges = changes.slice(0, limit)

    return c.json({
      changes: returnChanges.map((change) => ({
        id: change.id,
        encryptedData: change.encryptedData,
        nonce: change.nonce,
        createdAt: change.createdAt,
      })),
      hasMore,
    })
  } catch (error) {
    console.error('Pull changes error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

export default sync
