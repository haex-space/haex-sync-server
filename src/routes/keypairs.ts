import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { db, userKeypairs } from '../db'
import { authMiddleware } from '../middleware/auth'
import { eq } from 'drizzle-orm'

const keypairs = new Hono()

// All keypair routes require authentication
keypairs.use('/*', authMiddleware)

const registerKeypairSchema = z.object({
  publicKey: z.string(),
  encryptedPrivateKey: z.string(),
  privateKeyNonce: z.string(),
  privateKeySalt: z.string(),
})

// Register keypair (one per user, idempotent)
keypairs.post('/', zValidator('json', registerKeypairSchema), async (c) => {
  const user = c.get('user')
  const body = c.req.valid('json')

  const existing = await db.select()
    .from(userKeypairs)
    .where(eq(userKeypairs.userId, user.userId))
    .limit(1)

  if (existing.length > 0) {
    return c.json({ error: 'Keypair already exists' }, 409)
  }

  await db.insert(userKeypairs).values({
    userId: user.userId,
    ...body,
  })

  return c.json({ success: true }, 201)
})

// Get own keypair (includes encrypted private key)
keypairs.get('/me', async (c) => {
  const user = c.get('user')
  const result = await db.select()
    .from(userKeypairs)
    .where(eq(userKeypairs.userId, user.userId))
    .limit(1)

  if (result.length === 0) {
    return c.json({ error: 'No keypair found' }, 404)
  }

  return c.json(result[0])
})

// Get another user's public key (for inviting)
keypairs.get('/public/:userId', async (c) => {
  const targetUserId = c.req.param('userId')
  const result = await db.select({
    userId: userKeypairs.userId,
    publicKey: userKeypairs.publicKey,
  })
    .from(userKeypairs)
    .where(eq(userKeypairs.userId, targetUserId))
    .limit(1)

  if (result.length === 0) {
    return c.json({ error: 'User has no keypair' }, 404)
  }

  return c.json(result[0])
})

export default keypairs
