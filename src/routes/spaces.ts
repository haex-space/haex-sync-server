import { randomBytes } from 'crypto'
import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { db, spaces, spaceMembers, spaceKeyGrants, spaceAccessTokens, identities } from '../db'
import { authMiddleware } from '../middleware/auth'
import { eq, and, count } from 'drizzle-orm'

const spacesRouter = new Hono()

// All space routes require authentication
spacesRouter.use('/*', authMiddleware)

const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

function isValidUuid(id: string): boolean {
  return uuidRegex.test(id)
}

/** Resolve the caller's public key from their userId (JWT auth) */
async function resolveCallerPublicKey(userId: string): Promise<string | null> {
  const [identity] = await db.select()
    .from(identities)
    .where(eq(identities.supabaseUserId, userId))
    .limit(1)
  return identity?.publicKey ?? null
}

/** Get caller's membership info for a space */
async function getCallerMembership(spaceId: string, publicKey: string) {
  const result = await db.select({
    role: spaceMembers.role,
    canInvite: spaceMembers.canInvite,
  })
    .from(spaceMembers)
    .where(and(eq(spaceMembers.spaceId, spaceId), eq(spaceMembers.publicKey, publicKey)))
    .limit(1)
  return result[0] ?? null
}

// POST / – Create space
const createSpaceSchema = z.object({
  id: z.string().uuid(),
  encryptedName: z.string(),
  nameNonce: z.string(),
  label: z.string().min(1), // Creator's own label (e.g. "Me" or their name)
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
    const callerPublicKey = await resolveCallerPublicKey(user.userId)
    if (!callerPublicKey) {
      return c.json({ error: 'No keypair registered. Generate a keypair first.' }, 400)
    }

    await db.transaction(async (tx) => {
      await tx.insert(spaces).values({
        id: body.id,
        ownerId: user.userId,
        encryptedName: body.encryptedName,
        nameNonce: body.nameNonce,
      })

      await tx.insert(spaceMembers).values({
        spaceId: body.id,
        publicKey: callerPublicKey,
        label: body.label,
        role: 'admin',
        canInvite: true,
        invitedBy: null,
      })

      await tx.insert(spaceKeyGrants).values({
        spaceId: body.id,
        publicKey: callerPublicKey,
        generation: 1,
        encryptedSpaceKey: body.keyGrant.encryptedSpaceKey,
        keyNonce: body.keyGrant.keyNonce,
        ephemeralPublicKey: body.keyGrant.ephemeralPublicKey,
        grantedBy: null,
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
    const callerPublicKey = await resolveCallerPublicKey(user.userId)
    if (!callerPublicKey) {
      return c.json([])
    }

    const result = await db.select({
      id: spaces.id,
      ownerId: spaces.ownerId,
      encryptedName: spaces.encryptedName,
      nameNonce: spaces.nameNonce,
      currentKeyGeneration: spaces.currentKeyGeneration,
      createdAt: spaces.createdAt,
      updatedAt: spaces.updatedAt,
      role: spaceMembers.role,
      canInvite: spaceMembers.canInvite,
      joinedAt: spaceMembers.joinedAt,
    })
      .from(spaceMembers)
      .innerJoin(spaces, eq(spaceMembers.spaceId, spaces.id))
      .where(eq(spaceMembers.publicKey, callerPublicKey))

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
    const callerPublicKey = await resolveCallerPublicKey(user.userId)
    if (!callerPublicKey) {
      return c.json({ error: 'No keypair registered' }, 400)
    }

    const spaceResult = await db.select()
      .from(spaces)
      .where(eq(spaces.id, spaceId))
      .limit(1)

    if (spaceResult.length === 0) {
      return c.json({ error: 'Space not found' }, 404)
    }

    const membership = await getCallerMembership(spaceId, callerPublicKey)
    if (!membership) {
      return c.json({ error: 'Not a member of this space' }, 403)
    }

    const members = await db.select({
      publicKey: spaceMembers.publicKey,
      label: spaceMembers.label,
      role: spaceMembers.role,
      canInvite: spaceMembers.canInvite,
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

// DELETE /:spaceId – Delete space (admin only)
spacesRouter.delete('/:spaceId', async (c) => {
  const spaceId = c.req.param('spaceId')
  const user = c.get('user')

  if (!isValidUuid(spaceId)) {
    return c.json({ error: 'Invalid space ID format' }, 400)
  }

  try {
    const callerPublicKey = await resolveCallerPublicKey(user.userId)
    if (!callerPublicKey) {
      return c.json({ error: 'No keypair registered' }, 400)
    }

    const membership = await getCallerMembership(spaceId, callerPublicKey)
    if (membership?.role !== 'admin') {
      return c.json({ error: 'Only the admin can delete a space' }, 403)
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
  publicKey: z.string().min(1),
  label: z.string().min(1),
  role: z.enum(['member', 'viewer']), // Only admin can be set during creation, not via invite
  canInvite: z.boolean().default(false),
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
    const callerPublicKey = await resolveCallerPublicKey(user.userId)
    if (!callerPublicKey) {
      return c.json({ error: 'No keypair registered' }, 400)
    }

    const result = await db.transaction(async (tx) => {
      // Check caller has invite permission
      const callerResult = await tx.select({
        role: spaceMembers.role,
        canInvite: spaceMembers.canInvite,
      })
        .from(spaceMembers)
        .where(and(eq(spaceMembers.spaceId, spaceId), eq(spaceMembers.publicKey, callerPublicKey)))
        .limit(1)
      const caller = callerResult[0]

      if (!caller) {
        return { error: 'Not a member of this space', status: 403 as const }
      }

      const isAdmin = caller.role === 'admin'
      if (!isAdmin && !caller.canInvite) {
        return { error: 'You do not have permission to invite members', status: 403 as const }
      }

      // Only admin can grant canInvite permission
      if (body.canInvite && !isAdmin) {
        return { error: 'Only the admin can grant invite permissions', status: 403 as const }
      }

      // Validate key generation
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

      // Check if already a member
      const existing = await tx.select({ role: spaceMembers.role })
        .from(spaceMembers)
        .where(and(eq(spaceMembers.spaceId, spaceId), eq(spaceMembers.publicKey, body.publicKey)))
        .limit(1)

      if (existing.length > 0) {
        return { error: 'This public key is already a member of this space', status: 409 as const }
      }

      await tx.insert(spaceMembers).values({
        spaceId,
        publicKey: body.publicKey,
        label: body.label,
        role: body.role,
        canInvite: body.canInvite,
        invitedBy: callerPublicKey,
      })

      await tx.insert(spaceKeyGrants).values({
        spaceId,
        publicKey: body.publicKey,
        generation: body.keyGrant.generation,
        encryptedSpaceKey: body.keyGrant.encryptedSpaceKey,
        keyNonce: body.keyGrant.keyNonce,
        ephemeralPublicKey: body.keyGrant.ephemeralPublicKey,
        grantedBy: callerPublicKey,
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

// DELETE /:spaceId/members/:publicKey – Remove member or self-leave
spacesRouter.delete('/:spaceId/members/:memberPublicKey', async (c) => {
  const spaceId = c.req.param('spaceId')
  const targetPublicKey = decodeURIComponent(c.req.param('memberPublicKey'))
  const user = c.get('user')

  if (!isValidUuid(spaceId)) {
    return c.json({ error: 'Invalid space ID format' }, 400)
  }

  try {
    const callerPublicKey = await resolveCallerPublicKey(user.userId)
    if (!callerPublicKey) {
      return c.json({ error: 'No keypair registered' }, 400)
    }

    const isSelf = callerPublicKey === targetPublicKey

    const result = await db.transaction(async (tx) => {
      const callerMembership = await tx.select({
        role: spaceMembers.role,
      })
        .from(spaceMembers)
        .where(and(eq(spaceMembers.spaceId, spaceId), eq(spaceMembers.publicKey, callerPublicKey)))
        .limit(1)

      if (!callerMembership[0]) {
        return { error: 'Not a member of this space', status: 403 as const }
      }

      const isAdmin = callerMembership[0].role === 'admin'

      // Non-admins can only remove themselves
      if (!isSelf && !isAdmin) {
        return { error: 'Only the admin can remove other members', status: 403 as const }
      }

      // Admin cannot leave — they must delete the space
      if (isSelf && isAdmin) {
        return { error: 'The admin cannot leave the space. Delete it instead.', status: 400 as const }
      }

      // Check target membership exists
      if (!isSelf) {
        const target = await tx.select({ role: spaceMembers.role })
          .from(spaceMembers)
          .where(and(eq(spaceMembers.spaceId, spaceId), eq(spaceMembers.publicKey, targetPublicKey)))
          .limit(1)

        if (!target[0]) {
          return { error: 'Target is not a member of this space', status: 404 as const }
        }
      }

      await tx.delete(spaceMembers)
        .where(and(eq(spaceMembers.spaceId, spaceId), eq(spaceMembers.publicKey, targetPublicKey)))

      await tx.delete(spaceKeyGrants)
        .where(and(eq(spaceKeyGrants.spaceId, spaceId), eq(spaceKeyGrants.publicKey, targetPublicKey)))

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
    const callerPublicKey = await resolveCallerPublicKey(user.userId)
    if (!callerPublicKey) {
      return c.json({ error: 'No keypair registered' }, 400)
    }

    const membership = await getCallerMembership(spaceId, callerPublicKey)
    if (!membership) {
      return c.json({ error: 'Not a member of this space' }, 403)
    }

    const grants = await db.select()
      .from(spaceKeyGrants)
      .where(and(eq(spaceKeyGrants.spaceId, spaceId), eq(spaceKeyGrants.publicKey, callerPublicKey)))

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
  role: z.enum(['member', 'viewer']),
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
    const callerPublicKey = await resolveCallerPublicKey(user.userId)
    if (!callerPublicKey) {
      return c.json({ error: 'No keypair registered' }, 400)
    }

    const membership = await getCallerMembership(spaceId, callerPublicKey)
    if (membership?.role !== 'admin') {
      return c.json({ error: 'Only the admin can create tokens' }, 403)
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

    return c.json({ tokenId: inserted!.id, token }, 201)
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
    const callerPublicKey = await resolveCallerPublicKey(user.userId)
    if (!callerPublicKey) {
      return c.json({ error: 'No keypair registered' }, 400)
    }

    const membership = await getCallerMembership(spaceId, callerPublicKey)
    if (membership?.role !== 'admin') {
      return c.json({ error: 'Only the admin can list tokens' }, 403)
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
    const callerPublicKey = await resolveCallerPublicKey(user.userId)
    if (!callerPublicKey) {
      return c.json({ error: 'No keypair registered' }, 400)
    }

    const membership = await getCallerMembership(spaceId, callerPublicKey)
    if (membership?.role !== 'admin') {
      return c.json({ error: 'Only the admin can revoke tokens' }, 403)
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
        revokedBy: callerPublicKey,
      })
      .where(eq(spaceAccessTokens.id, tokenId))

    return c.json({ success: true })
  } catch (error) {
    console.error('Revoke token error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

export default spacesRouter
