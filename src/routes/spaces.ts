import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { db, spaces, spaceMembers } from '../db'
import { authDispatcher } from '../middleware/authDispatcher'
import { requireCapability } from '../middleware/ucanAuth'
import { resolveDidIdentity } from '../middleware/didAuth'
import { eq, and } from 'drizzle-orm'
import { broadcastToSpace, updateMembershipCache } from './ws'

const spacesRouter = new Hono()

// All space routes require authentication (UCAN or DID)
spacesRouter.use('/*', authDispatcher)

const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

function isValidUuid(id: string): boolean {
  return uuidRegex.test(id)
}

/** Get caller DID from either UCAN or DID-Auth context */
function getCallerDid(c: any): string | null {
  const ucan = c.get('ucan')
  if (ucan) return ucan.issuerDid
  const didAuth = c.get('didAuth')
  if (didAuth) return didAuth.did
  return null
}

// POST / – Create space (DID-Auth only)
const createSpaceSchema = z.object({
  id: z.string().uuid(),
  encryptedName: z.string(),
  nameNonce: z.string(),
  label: z.string().min(1),
})

spacesRouter.post('/', zValidator('json', createSpaceSchema), async (c) => {
  const didAuth = c.get('didAuth')
  if (!didAuth) {
    return c.json({ error: 'Space creation requires DID-Auth' }, 401)
  }

  const body = c.req.valid('json')

  try {
    const identity = await resolveDidIdentity(didAuth.did)
    if (!identity) {
      return c.json({ error: 'Identity not found for DID. Register a keypair first.' }, 400)
    }

    if (!identity.supabaseUserId) {
      return c.json({ error: 'Identity has no linked Supabase account' }, 400)
    }

    await db.transaction(async (tx) => {
      await tx.insert(spaces).values({
        id: body.id,
        ownerId: didAuth.did,
        encryptedName: body.encryptedName,
        nameNonce: body.nameNonce,
      })

      await tx.insert(spaceMembers).values({
        spaceId: body.id,
        publicKey: identity.publicKey,
        did: didAuth.did,
        label: body.label,
        role: 'admin',
        invitedBy: null,
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
  const callerDid = getCallerDid(c)
  if (!callerDid) {
    return c.json({ error: 'Could not resolve caller DID' }, 401)
  }

  try {
    const result = await db.select({
      id: spaces.id,
      ownerId: spaces.ownerId,
      encryptedName: spaces.encryptedName,
      nameNonce: spaces.nameNonce,
      createdAt: spaces.createdAt,
      updatedAt: spaces.updatedAt,
      role: spaceMembers.role,
      joinedAt: spaceMembers.joinedAt,
    })
      .from(spaceMembers)
      .innerJoin(spaces, eq(spaceMembers.spaceId, spaces.id))
      .where(eq(spaceMembers.did, callerDid))

    return c.json(result)
  } catch (error) {
    console.error('List spaces error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// DELETE /my-admin-spaces – Delete all spaces where the caller is admin
spacesRouter.delete('/my-admin-spaces', async (c) => {
  const callerDid = getCallerDid(c)
  if (!callerDid) {
    return c.json({ error: 'Could not resolve caller DID' }, 401)
  }

  try {
    const adminMemberships = await db.select({
      spaceId: spaceMembers.spaceId,
    })
      .from(spaceMembers)
      .where(and(eq(spaceMembers.did, callerDid), eq(spaceMembers.role, 'admin')))

    const deletedSpaceIds: string[] = []
    for (const membership of adminMemberships) {
      await db.delete(spaces).where(eq(spaces.id, membership.spaceId))
      deletedSpaceIds.push(membership.spaceId)
    }

    return c.json({ success: true, deletedSpaces: deletedSpaceIds.length })
  } catch (error) {
    console.error('Delete my admin spaces error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// GET /:spaceId – Get space details
spacesRouter.get('/:spaceId', async (c) => {
  const spaceId = c.req.param('spaceId')
  if (!isValidUuid(spaceId)) {
    return c.json({ error: 'Invalid space ID format' }, 400)
  }

  const error = await requireCapability(c, spaceId, 'space/read')
  if (error) return error

  try {
    const spaceResult = await db.select()
      .from(spaces)
      .where(eq(spaces.id, spaceId))
      .limit(1)

    if (spaceResult.length === 0) {
      return c.json({ error: 'Space not found' }, 404)
    }

    const members = await db.select({
      publicKey: spaceMembers.publicKey,
      did: spaceMembers.did,
      label: spaceMembers.label,
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

// PATCH /:spaceId – Update space name (admin only)
const updateSpaceSchema = z.object({
  encryptedName: z.string(),
  nameNonce: z.string(),
})

spacesRouter.patch('/:spaceId', zValidator('json', updateSpaceSchema), async (c) => {
  const spaceId = c.req.param('spaceId')
  const body = c.req.valid('json')

  if (!isValidUuid(spaceId)) {
    return c.json({ error: 'Invalid space ID format' }, 400)
  }

  const error = await requireCapability(c, spaceId, 'space/admin')
  if (error) return error

  try {
    await db.update(spaces)
      .set({
        encryptedName: body.encryptedName,
        nameNonce: body.nameNonce,
      })
      .where(eq(spaces.id, spaceId))

    return c.json({ success: true })
  } catch (error) {
    console.error('Update space error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// DELETE /:spaceId – Delete space (admin only)
spacesRouter.delete('/:spaceId', async (c) => {
  const spaceId = c.req.param('spaceId')

  if (!isValidUuid(spaceId)) {
    return c.json({ error: 'Invalid space ID format' }, 400)
  }

  const error = await requireCapability(c, spaceId, 'space/admin')
  if (error) return error

  try {
    await db.delete(spaces).where(eq(spaces.id, spaceId))

    return c.json({ success: true })
  } catch (error) {
    console.error('Delete space error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// POST /:spaceId/members – Invite member
const inviteMemberSchema = z.object({
  did: z.string().min(1),
  label: z.string().min(1),
  role: z.enum(['owner', 'member', 'reader']),
})

spacesRouter.post('/:spaceId/members', zValidator('json', inviteMemberSchema), async (c) => {
  const spaceId = c.req.param('spaceId')
  const body = c.req.valid('json')

  if (!isValidUuid(spaceId)) {
    return c.json({ error: 'Invalid space ID format' }, 400)
  }

  const capError = await requireCapability(c, spaceId, 'space/invite')
  if (capError) return capError

  const callerDid = getCallerDid(c)
  if (!callerDid) {
    return c.json({ error: 'Could not resolve caller DID' }, 401)
  }

  try {
    const inviteeIdentity = await resolveDidIdentity(body.did)
    if (!inviteeIdentity) {
      return c.json({ error: 'Identity not found for DID' }, 404)
    }

    // Check if already a member
    const existing = await db.select({ role: spaceMembers.role })
      .from(spaceMembers)
      .where(and(eq(spaceMembers.spaceId, spaceId), eq(spaceMembers.did, body.did)))
      .limit(1)

    if (existing.length > 0) {
      return c.json({ error: 'This DID is already a member of this space' }, 409)
    }

    await db.insert(spaceMembers).values({
      spaceId,
      publicKey: inviteeIdentity.publicKey,
      did: body.did,
      label: body.label,
      role: body.role,
      invitedBy: callerDid,
    })

    return c.json({ success: true }, 201)
  } catch (error) {
    console.error('Invite member error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// DELETE /:spaceId/members/:memberDid – Remove member or self-leave
spacesRouter.delete('/:spaceId/members/:memberDid', async (c) => {
  const spaceId = c.req.param('spaceId')
  const targetDid = decodeURIComponent(c.req.param('memberDid'))

  if (!isValidUuid(spaceId)) {
    return c.json({ error: 'Invalid space ID format' }, 400)
  }

  const callerDid = getCallerDid(c)
  if (!callerDid) {
    return c.json({ error: 'Could not resolve caller DID' }, 401)
  }

  const isSelf = callerDid === targetDid

  // If not self-leave, require admin capability
  if (!isSelf) {
    const capError = await requireCapability(c, spaceId, 'space/admin')
    if (capError) return capError
  }

  try {
    const result = await db.transaction(async (tx) => {
      if (isSelf) {
        // Check caller membership to prevent admin from leaving
        const callerMembership = await tx.select({ role: spaceMembers.role })
          .from(spaceMembers)
          .where(and(eq(spaceMembers.spaceId, spaceId), eq(spaceMembers.did, callerDid)))
          .limit(1)

        if (!callerMembership[0]) {
          return { error: 'Not a member of this space', status: 403 as const }
        }

        if (callerMembership[0].role === 'admin') {
          return { error: 'The admin cannot leave the space. Transfer admin or delete it instead.', status: 400 as const }
        }
      } else {
        // Verify target exists
        const target = await tx.select({ role: spaceMembers.role })
          .from(spaceMembers)
          .where(and(eq(spaceMembers.spaceId, spaceId), eq(spaceMembers.did, targetDid)))
          .limit(1)

        if (!target[0]) {
          return { error: 'Target is not a member of this space', status: 404 as const }
        }

        if (target[0].role === 'admin') {
          return { error: 'Cannot kick the admin', status: 403 as const }
        }
      }

      await tx.delete(spaceMembers)
        .where(and(eq(spaceMembers.spaceId, spaceId), eq(spaceMembers.did, targetDid)))

      return null
    })

    if (result) {
      return c.json({ error: result.error }, result.status)
    }

    // Notify space members about the membership change
    broadcastToSpace(spaceId, { type: 'membership', spaceId })
    updateMembershipCache(targetDid, spaceId, 'remove')

    return c.json({ success: true })
  } catch (error) {
    console.error('Remove member error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// POST /:spaceId/transfer-admin – Transfer admin role to another member
const transferAdminSchema = z.object({
  targetDid: z.string().min(1),
})

spacesRouter.post('/:spaceId/transfer-admin', zValidator('json', transferAdminSchema), async (c) => {
  const spaceId = c.req.param('spaceId')
  const body = c.req.valid('json')

  if (!isValidUuid(spaceId)) {
    return c.json({ error: 'Invalid space ID format' }, 400)
  }

  const capError = await requireCapability(c, spaceId, 'space/admin')
  if (capError) return capError

  const callerDid = getCallerDid(c)
  if (!callerDid) {
    return c.json({ error: 'Could not resolve caller DID' }, 401)
  }

  try {
    const result = await db.transaction(async (tx) => {
      // Verify target is a member of the space
      const targetResult = await tx.select({ role: spaceMembers.role })
        .from(spaceMembers)
        .where(and(eq(spaceMembers.spaceId, spaceId), eq(spaceMembers.did, body.targetDid)))
        .limit(1)

      if (!targetResult[0]) {
        return { error: 'Target is not a member of this space', status: 404 as const }
      }

      // Promote target to admin
      await tx.update(spaceMembers)
        .set({ role: 'admin' })
        .where(and(eq(spaceMembers.spaceId, spaceId), eq(spaceMembers.did, body.targetDid)))

      // Demote caller to owner
      await tx.update(spaceMembers)
        .set({ role: 'owner' })
        .where(and(eq(spaceMembers.spaceId, spaceId), eq(spaceMembers.did, callerDid)))

      return null
    })

    if (result) {
      return c.json({ error: result.error }, result.status)
    }

    return c.json({ success: true })
  } catch (error) {
    console.error('Transfer admin error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

export default spacesRouter
