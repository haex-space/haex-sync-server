import { randomBytes } from 'crypto'
import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { db, spaces, spaceMembers, spaceKeyGrants, spaceAccessTokens } from '../db'
import { authMiddleware } from '../middleware/auth'
import { eq, and, count } from 'drizzle-orm'

const spacesRouter = new Hono()

// All space routes require authentication
spacesRouter.use('/*', authMiddleware)

const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

function isValidUuid(id: string): boolean {
  return uuidRegex.test(id)
}

async function getCallerRole(spaceId: string, userId: string): Promise<string | null> {
  const result = await db.select({ role: spaceMembers.role })
    .from(spaceMembers)
    .where(and(eq(spaceMembers.spaceId, spaceId), eq(spaceMembers.userId, userId)))
    .limit(1)
  return result[0]?.role ?? null
}

// POST / – Create space
const createSpaceSchema = z.object({
  id: z.string().uuid(),
  encryptedName: z.string(),
  nameNonce: z.string(),
  keyGrant: z.object({
    encryptedSpaceKey: z.string(),
    keyNonce: z.string(),
    ephemeralPublicKey: z.string(),
  }),
})

spacesRouter.post('/', zValidator('json', createSpaceSchema), async (c) => {
  const user = c.get('user')
  const body = c.req.valid('json')

  try {
    await db.transaction(async (tx) => {
      await tx.insert(spaces).values({
        id: body.id,
        ownerId: user.userId,
        encryptedName: body.encryptedName,
        nameNonce: body.nameNonce,
      })

      await tx.insert(spaceMembers).values({
        spaceId: body.id,
        userId: user.userId,
        role: 'admin',
        invitedBy: null,
      })

      await tx.insert(spaceKeyGrants).values({
        spaceId: body.id,
        userId: user.userId,
        generation: 1,
        encryptedSpaceKey: body.keyGrant.encryptedSpaceKey,
        keyNonce: body.keyGrant.keyNonce,
        ephemeralPublicKey: body.keyGrant.ephemeralPublicKey,
        grantedBy: user.userId,
      })
    })

    return c.json({ success: true }, 201)
  } catch (error) {
    console.error('Create space error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// GET / – List my spaces
spacesRouter.get('/', async (c) => {
  const user = c.get('user')

  try {
    const result = await db.select({
      id: spaces.id,
      ownerId: spaces.ownerId,
      encryptedName: spaces.encryptedName,
      nameNonce: spaces.nameNonce,
      currentKeyGeneration: spaces.currentKeyGeneration,
      createdAt: spaces.createdAt,
      updatedAt: spaces.updatedAt,
      role: spaceMembers.role,
      joinedAt: spaceMembers.joinedAt,
    })
      .from(spaceMembers)
      .innerJoin(spaces, eq(spaceMembers.spaceId, spaces.id))
      .where(eq(spaceMembers.userId, user.userId))

    return c.json(result)
  } catch (error) {
    console.error('List spaces error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// GET /:spaceId – Get space details
spacesRouter.get('/:spaceId', async (c) => {
  const spaceId = c.req.param('spaceId')
  const user = c.get('user')

  if (!isValidUuid(spaceId)) {
    return c.json({ error: 'Invalid space ID format' }, 400)
  }

  try {
    const spaceResult = await db.select()
      .from(spaces)
      .where(eq(spaces.id, spaceId))
      .limit(1)

    if (spaceResult.length === 0) {
      return c.json({ error: 'Space not found' }, 404)
    }

    const role = await getCallerRole(spaceId, user.userId)
    if (!role) {
      return c.json({ error: 'Not a member of this space' }, 403)
    }

    const members = await db.select({
      userId: spaceMembers.userId,
      role: spaceMembers.role,
      invitedBy: spaceMembers.invitedBy,
      joinedAt: spaceMembers.joinedAt,
    })
      .from(spaceMembers)
      .where(eq(spaceMembers.spaceId, spaceId))

    return c.json({
      ...spaceResult[0],
      members,
    })
  } catch (error) {
    console.error('Get space error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// DELETE /:spaceId – Delete space
spacesRouter.delete('/:spaceId', async (c) => {
  const spaceId = c.req.param('spaceId')
  const user = c.get('user')

  if (!isValidUuid(spaceId)) {
    return c.json({ error: 'Invalid space ID format' }, 400)
  }

  try {
    const spaceResult = await db.select({ id: spaces.id })
      .from(spaces)
      .where(eq(spaces.id, spaceId))
      .limit(1)

    if (spaceResult.length === 0) {
      return c.json({ error: 'Space not found' }, 404)
    }

    const role = await getCallerRole(spaceId, user.userId)
    if (role !== 'admin') {
      return c.json({ error: 'Only admins can delete a space' }, 403)
    }

    await db.delete(spaces).where(eq(spaces.id, spaceId))

    return c.json({ success: true })
  } catch (error) {
    console.error('Delete space error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// POST /:spaceId/members – Invite member
const inviteMemberSchema = z.object({
  userId: z.string().uuid(),
  role: z.enum(['admin', 'member', 'viewer']),
  keyGrant: z.object({
    encryptedSpaceKey: z.string(),
    keyNonce: z.string(),
    ephemeralPublicKey: z.string(),
    generation: z.number().int().positive(),
  }),
})

spacesRouter.post('/:spaceId/members', zValidator('json', inviteMemberSchema), async (c) => {
  const spaceId = c.req.param('spaceId')
  const user = c.get('user')
  const body = c.req.valid('json')

  if (!isValidUuid(spaceId)) {
    return c.json({ error: 'Invalid space ID format' }, 400)
  }

  try {
    const result = await db.transaction(async (tx) => {
      // Check caller is admin (inside transaction to prevent race)
      const callerResult = await tx.select({ role: spaceMembers.role })
        .from(spaceMembers)
        .where(and(eq(spaceMembers.spaceId, spaceId), eq(spaceMembers.userId, user.userId)))
        .limit(1)
      const callerRole = callerResult[0]?.role ?? null

      if (callerRole !== 'admin') {
        return { error: 'Only admins can invite members', status: 403 as const }
      }

      // Validate key generation matches space's current generation
      const spaceResult = await tx.select({ currentKeyGeneration: spaces.currentKeyGeneration })
        .from(spaces)
        .where(eq(spaces.id, spaceId))
        .limit(1)

      if (spaceResult.length === 0) {
        return { error: 'Space not found', status: 404 as const }
      }

      if (body.keyGrant.generation !== spaceResult[0]!.currentKeyGeneration) {
        return { error: 'Key grant generation does not match current space key generation', status: 400 as const }
      }

      // Check if already a member (inside transaction to prevent race)
      const existing = await tx.select({ role: spaceMembers.role })
        .from(spaceMembers)
        .where(and(eq(spaceMembers.spaceId, spaceId), eq(spaceMembers.userId, body.userId)))
        .limit(1)

      if (existing.length > 0) {
        return { error: 'User is already a member of this space', status: 409 as const }
      }

      await tx.insert(spaceMembers).values({
        spaceId,
        userId: body.userId,
        role: body.role,
        invitedBy: user.userId,
      })

      await tx.insert(spaceKeyGrants).values({
        spaceId,
        userId: body.userId,
        generation: body.keyGrant.generation,
        encryptedSpaceKey: body.keyGrant.encryptedSpaceKey,
        keyNonce: body.keyGrant.keyNonce,
        ephemeralPublicKey: body.keyGrant.ephemeralPublicKey,
        grantedBy: user.userId,
      })

      return null
    })

    if (result) {
      return c.json({ error: result.error }, result.status)
    }

    return c.json({ success: true }, 201)
  } catch (error) {
    console.error('Invite member error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// DELETE /:spaceId/members/:userId – Remove member or self-leave
spacesRouter.delete('/:spaceId/members/:userId', async (c) => {
  const spaceId = c.req.param('spaceId')
  const targetUserId = c.req.param('userId')
  const user = c.get('user')

  if (!isValidUuid(spaceId) || !isValidUuid(targetUserId)) {
    return c.json({ error: 'Invalid ID format' }, 400)
  }

  try {
    const isSelf = user.userId === targetUserId

    const result = await db.transaction(async (tx) => {
      // Check caller membership
      const callerResult = await tx.select({ role: spaceMembers.role })
        .from(spaceMembers)
        .where(and(eq(spaceMembers.spaceId, spaceId), eq(spaceMembers.userId, user.userId)))
        .limit(1)
      const callerRole = callerResult[0]?.role ?? null

      if (!callerRole) {
        return { error: 'Not a member of this space', status: 403 as const }
      }

      // Non-admins can only remove themselves
      if (!isSelf && callerRole !== 'admin') {
        return { error: 'Only admins can remove other members', status: 403 as const }
      }

      // Check if target is a member
      let targetRole: string | null
      if (isSelf) {
        targetRole = callerRole
      } else {
        const targetResult = await tx.select({ role: spaceMembers.role })
          .from(spaceMembers)
          .where(and(eq(spaceMembers.spaceId, spaceId), eq(spaceMembers.userId, targetUserId)))
          .limit(1)
        targetRole = targetResult[0]?.role ?? null
      }

      if (!targetRole) {
        return { error: 'Target user is not a member of this space', status: 404 as const }
      }

      // Prevent last admin from leaving
      if (targetRole === 'admin') {
        const adminCount = await tx.select({ value: count() })
          .from(spaceMembers)
          .where(and(eq(spaceMembers.spaceId, spaceId), eq(spaceMembers.role, 'admin')))

        if (adminCount[0]!.value <= 1) {
          return { error: 'Cannot remove the last admin. Transfer admin role to another member first, or delete the space.', status: 400 as const }
        }
      }

      await tx.delete(spaceMembers)
        .where(and(eq(spaceMembers.spaceId, spaceId), eq(spaceMembers.userId, targetUserId)))

      await tx.delete(spaceKeyGrants)
        .where(and(eq(spaceKeyGrants.spaceId, spaceId), eq(spaceKeyGrants.userId, targetUserId)))

      return null
    })

    if (result) {
      return c.json({ error: result.error }, result.status)
    }

    return c.json({ success: true })
  } catch (error) {
    console.error('Remove member error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// GET /:spaceId/key-grants – Get own key grants for a space
spacesRouter.get('/:spaceId/key-grants', async (c) => {
  const spaceId = c.req.param('spaceId')
  const user = c.get('user')

  if (!isValidUuid(spaceId)) {
    return c.json({ error: 'Invalid space ID format' }, 400)
  }

  try {
    const role = await getCallerRole(spaceId, user.userId)
    if (!role) {
      return c.json({ error: 'Not a member of this space' }, 403)
    }

    const grants = await db.select()
      .from(spaceKeyGrants)
      .where(and(eq(spaceKeyGrants.spaceId, spaceId), eq(spaceKeyGrants.userId, user.userId)))

    return c.json(grants)
  } catch (error) {
    console.error('Get key grants error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// ============================================
// SPACE ACCESS TOKENS
// ============================================

// POST /:spaceId/tokens – Create token (admin only)
const createTokenSchema = z.object({
  publicKey: z.string().min(1),
  role: z.enum(['admin', 'member', 'viewer']),
  label: z.string().optional(),
})

spacesRouter.post('/:spaceId/tokens', zValidator('json', createTokenSchema), async (c) => {
  const spaceId = c.req.param('spaceId')
  const user = c.get('user')
  const body = c.req.valid('json')

  if (!isValidUuid(spaceId)) {
    return c.json({ error: 'Invalid space ID format' }, 400)
  }

  try {
    const role = await getCallerRole(spaceId, user.userId)
    if (role !== 'admin') {
      return c.json({ error: 'Only admins can create tokens' }, 403)
    }

    const token = randomBytes(32).toString('hex')

    const [inserted] = await db.insert(spaceAccessTokens).values({
      spaceId,
      token,
      publicKey: body.publicKey,
      role: body.role,
      label: body.label ?? null,
      issuedBy: user.userId,
    }).returning({ id: spaceAccessTokens.id })

    return c.json({ tokenId: inserted.id, token }, 201)
  } catch (error) {
    console.error('Create token error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// GET /:spaceId/tokens – List tokens (admin only)
spacesRouter.get('/:spaceId/tokens', async (c) => {
  const spaceId = c.req.param('spaceId')
  const user = c.get('user')

  if (!isValidUuid(spaceId)) {
    return c.json({ error: 'Invalid space ID format' }, 400)
  }

  try {
    const role = await getCallerRole(spaceId, user.userId)
    if (role !== 'admin') {
      return c.json({ error: 'Only admins can list tokens' }, 403)
    }

    const tokens = await db.select({
      id: spaceAccessTokens.id,
      publicKey: spaceAccessTokens.publicKey,
      role: spaceAccessTokens.role,
      label: spaceAccessTokens.label,
      revoked: spaceAccessTokens.revoked,
      createdAt: spaceAccessTokens.createdAt,
      lastUsedAt: spaceAccessTokens.lastUsedAt,
    })
      .from(spaceAccessTokens)
      .where(eq(spaceAccessTokens.spaceId, spaceId))

    return c.json(tokens)
  } catch (error) {
    console.error('List tokens error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// DELETE /:spaceId/tokens/:tokenId – Revoke token (admin only)
spacesRouter.delete('/:spaceId/tokens/:tokenId', async (c) => {
  const spaceId = c.req.param('spaceId')
  const tokenId = c.req.param('tokenId')
  const user = c.get('user')

  if (!isValidUuid(spaceId) || !isValidUuid(tokenId)) {
    return c.json({ error: 'Invalid ID format' }, 400)
  }

  try {
    const role = await getCallerRole(spaceId, user.userId)
    if (role !== 'admin') {
      return c.json({ error: 'Only admins can revoke tokens' }, 403)
    }

    const existing = await db.select({ id: spaceAccessTokens.id })
      .from(spaceAccessTokens)
      .where(and(
        eq(spaceAccessTokens.id, tokenId),
        eq(spaceAccessTokens.spaceId, spaceId),
      ))
      .limit(1)

    if (existing.length === 0) {
      return c.json({ error: 'Token not found' }, 404)
    }

    await db.update(spaceAccessTokens)
      .set({
        revoked: true,
        revokedAt: new Date(),
        revokedBy: user.userId,
      })
      .where(eq(spaceAccessTokens.id, tokenId))

    return c.json({ success: true })
  } catch (error) {
    console.error('Revoke token error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

export default spacesRouter
