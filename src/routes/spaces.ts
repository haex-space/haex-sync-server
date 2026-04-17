import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { db, spaces, spaceMembers } from '../db'
import { authDispatcher } from '../middleware/authDispatcher'
import { requireCapability } from '../middleware/ucanAuth'
import { resolveDidIdentity } from '../middleware/didAuth'
import { eq, and } from 'drizzle-orm'
import { SpaceCapabilities } from '@haex-space/ucan'
import { broadcastToSpace, updateMembershipCache } from './ws'
import { getFederationLinkForSpace, federatedProxyAsync } from '../services/federationClient'
import { parseFederatedAuthHeader } from '@haex-space/federation-sdk'
import { getServerIdentity } from '../services/serverIdentity'

const spacesRouter = new Hono()

// All space routes require authentication (UCAN or DID)
spacesRouter.use('/*', authDispatcher)

/**
 * Check if a space is federated and proxy the request to the origin server.
 */
async function federationRelay(c: any, spaceId: string): Promise<Response | null> {
  const link = getFederationLinkForSpace(spaceId)
  if (!link) return null

  const userAuth = c.req.header('Authorization') ?? ''
  if (!userAuth) return c.json({ error: 'User authentication required for federated requests' }, 401)

  const parsed = parseFederatedAuthHeader(userAuth)
  if (parsed) {
    const myDid = getServerIdentity()?.did
    if (myDid && parsed.relayDid !== myDid) {
      return c.json({ error: `Request not intended for this relay (expected ${myDid}, got ${parsed.relayDid})` }, 403)
    }
  }

  const method = c.req.method
  const path = c.req.path
  const query = new URL(c.req.url).search.slice(1)
  const body = method !== 'GET' && method !== 'DELETE' ? await c.req.text() : undefined

  const result = await federatedProxyAsync(link, method, path, userAuth, body || undefined, query || undefined)
  return c.json(result.data, result.status as any)
}

export { isValidUuid } from '../utils/uuid'
import { isValidUuid } from '../utils/uuid'

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
        capability: 'space/admin',
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
      capability: spaceMembers.capability,
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
      .where(and(eq(spaceMembers.did, callerDid), eq(spaceMembers.capability, SpaceCapabilities.ADMIN)))

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

  const relayResponse = await federationRelay(c, spaceId)
  if (relayResponse) return relayResponse

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
      capability: spaceMembers.capability,
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

  const relayResponse = await federationRelay(c, spaceId)
  if (relayResponse) return relayResponse

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

  const relayResponse = await federationRelay(c, spaceId)
  if (relayResponse) return relayResponse

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
  capability: z.enum([SpaceCapabilities.WRITE, SpaceCapabilities.READ]),
})

spacesRouter.post('/:spaceId/members', zValidator('json', inviteMemberSchema), async (c) => {
  const spaceId = c.req.param('spaceId')
  const body = c.req.valid('json')

  if (!isValidUuid(spaceId)) {
    return c.json({ error: 'Invalid space ID format' }, 400)
  }

  const relayResponse = await federationRelay(c, spaceId)
  if (relayResponse) return relayResponse

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
    const existing = await db.select({ did: spaceMembers.did })
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
      capability: body.capability,
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

  const relayResponse = await federationRelay(c, spaceId)
  if (relayResponse) return relayResponse

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
        // Prevent space owner from leaving
        const [space] = await tx.select({ ownerId: spaces.ownerId })
          .from(spaces)
          .where(eq(spaces.id, spaceId))
          .limit(1)

        if (space && space.ownerId === callerDid) {
          return { error: 'The owner cannot leave the space. Transfer ownership or delete it instead.', status: 400 as const }
        }

        // Verify caller is actually a member
        const [membership] = await tx.select({ did: spaceMembers.did })
          .from(spaceMembers)
          .where(and(eq(spaceMembers.spaceId, spaceId), eq(spaceMembers.did, callerDid)))
          .limit(1)

        if (!membership) {
          return { error: 'Not a member of this space', status: 403 as const }
        }
      } else {
        // Verify target exists and is not the owner
        const [space] = await tx.select({ ownerId: spaces.ownerId })
          .from(spaces)
          .where(eq(spaces.id, spaceId))
          .limit(1)

        const [target] = await tx.select({ did: spaceMembers.did })
          .from(spaceMembers)
          .where(and(eq(spaceMembers.spaceId, spaceId), eq(spaceMembers.did, targetDid)))
          .limit(1)

        if (!target) {
          return { error: 'Target is not a member of this space', status: 404 as const }
        }

        if (space && space.ownerId === targetDid) {
          return { error: 'Cannot kick the space owner', status: 403 as const }
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

// POST /:spaceId/transfer-ownership – Transfer space ownership to another member
const transferOwnershipSchema = z.object({
  targetDid: z.string().min(1),
})

spacesRouter.post('/:spaceId/transfer-ownership', zValidator('json', transferOwnershipSchema), async (c) => {
  const spaceId = c.req.param('spaceId')
  const body = c.req.valid('json')

  if (!isValidUuid(spaceId)) {
    return c.json({ error: 'Invalid space ID format' }, 400)
  }

  const relayResponse = await federationRelay(c, spaceId)
  if (relayResponse) return relayResponse

  const capError = await requireCapability(c, spaceId, 'space/admin')
  if (capError) return capError

  const callerDid = getCallerDid(c)
  if (!callerDid) {
    return c.json({ error: 'Could not resolve caller DID' }, 401)
  }

  try {
    const result = await db.transaction(async (tx) => {
      // Verify target is a member of the space
      const [target] = await tx.select({ did: spaceMembers.did })
        .from(spaceMembers)
        .where(and(eq(spaceMembers.spaceId, spaceId), eq(spaceMembers.did, body.targetDid)))
        .limit(1)

      if (!target) {
        return { error: 'Target is not a member of this space', status: 404 as const }
      }

      // Transfer ownership: update spaces.ownerId
      await tx.update(spaces)
        .set({ ownerId: body.targetDid })
        .where(eq(spaces.id, spaceId))

      // Promote target to admin capability
      await tx.update(spaceMembers)
        .set({ capability: SpaceCapabilities.ADMIN })
        .where(and(eq(spaceMembers.spaceId, spaceId), eq(spaceMembers.did, body.targetDid)))

      // Demote caller to write capability
      await tx.update(spaceMembers)
        .set({ capability: SpaceCapabilities.WRITE })
        .where(and(eq(spaceMembers.spaceId, spaceId), eq(spaceMembers.did, callerDid)))

      return null
    })

    if (result) {
      return c.json({ error: result.error }, result.status)
    }

    return c.json({ success: true })
  } catch (error) {
    console.error('Transfer ownership error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

export default spacesRouter
