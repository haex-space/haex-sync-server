import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { db, spaceMembers, identities, mlsKeyPackages, mlsMessages, mlsWelcomeMessages, spaceInvites } from '../db'
import { authMiddleware } from '../middleware/auth'
import { eq, and, gt } from 'drizzle-orm'

const mlsRouter = new Hono()

mlsRouter.use('/*', authMiddleware)

async function resolveCallerIdentity(userId: string) {
  const [identity] = await db.select()
    .from(identities)
    .where(eq(identities.supabaseUserId, userId))
    .limit(1)
  return identity ?? null
}

async function requireMembership(spaceId: string, publicKey: string) {
  const [member] = await db.select({ role: spaceMembers.role })
    .from(spaceMembers)
    .where(and(eq(spaceMembers.spaceId, spaceId), eq(spaceMembers.publicKey, publicKey)))
    .limit(1)
  return member ?? null
}

// ============================================
// INVITES (2-Step: Invite → Accept → MLS Add)
// ============================================

// POST /:spaceId/invites — Create pending invite
const createInviteSchema = z.object({
  inviteeDid: z.string().min(1),
  includeHistory: z.boolean().optional().default(false),
})

mlsRouter.post('/:spaceId/invites', zValidator('json', createInviteSchema), async (c) => {
  const user = c.get('user')
  const spaceId = c.req.param('spaceId')
  const body = c.req.valid('json')

  try {
    const caller = await resolveCallerIdentity(user.userId)
    if (!caller) return c.json({ error: 'No keypair registered' }, 400)

    const membership = await requireMembership(spaceId, caller.publicKey)
    if (!membership || !['admin', 'owner'].includes(membership.role)) {
      return c.json({ error: 'Only admin or owner can invite members' }, 403)
    }

    const [invite] = await db.insert(spaceInvites).values({
      spaceId,
      inviterPublicKey: caller.publicKey,
      inviteeDid: body.inviteeDid,
      includeHistory: body.includeHistory,
    }).onConflictDoNothing().returning()

    if (!invite) {
      return c.json({ error: 'Invite already exists for this user' }, 409)
    }

    return c.json({ success: true, invite: { id: invite.id, status: invite.status } }, 201)
  } catch (error) {
    console.error('Create invite error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// GET /:spaceId/invites — List invites (for space members: all invites; for non-members: own invites)
mlsRouter.get('/:spaceId/invites', async (c) => {
  const user = c.get('user')
  const spaceId = c.req.param('spaceId')

  try {
    const caller = await resolveCallerIdentity(user.userId)
    if (!caller) return c.json({ error: 'No keypair registered' }, 400)

    const membership = await requireMembership(spaceId, caller.publicKey)

    let invites
    if (membership) {
      // Space members see all invites
      invites = await db.select().from(spaceInvites)
        .where(eq(spaceInvites.spaceId, spaceId))
    } else {
      // Non-members see only their own invites
      invites = await db.select().from(spaceInvites)
        .where(and(eq(spaceInvites.spaceId, spaceId), eq(spaceInvites.inviteeDid, caller.did)))
    }

    return c.json({
      invites: invites.map((i) => ({
        id: i.id,
        inviterPublicKey: i.inviterPublicKey,
        inviteeDid: i.inviteeDid,
        status: i.status,
        includeHistory: i.includeHistory,
        createdAt: i.createdAt.toISOString(),
        respondedAt: i.respondedAt?.toISOString() ?? null,
      })),
    })
  } catch (error) {
    console.error('List invites error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// POST /:spaceId/invites/:inviteId/accept — Accept invite + upload KeyPackages
const acceptInviteSchema = z.object({
  keyPackages: z.array(z.string()).min(1).max(20),
})

mlsRouter.post('/:spaceId/invites/:inviteId/accept', zValidator('json', acceptInviteSchema), async (c) => {
  const user = c.get('user')
  const spaceId = c.req.param('spaceId')
  const inviteId = c.req.param('inviteId')
  const body = c.req.valid('json')

  try {
    const caller = await resolveCallerIdentity(user.userId)
    if (!caller) return c.json({ error: 'No keypair registered' }, 400)

    const [invite] = await db.select().from(spaceInvites)
      .where(and(
        eq(spaceInvites.id, inviteId),
        eq(spaceInvites.spaceId, spaceId),
        eq(spaceInvites.inviteeDid, caller.did),
        eq(spaceInvites.status, 'pending'),
      ))
      .limit(1)

    if (!invite) return c.json({ error: 'Invite not found or already responded' }, 404)

    await db.transaction(async (tx) => {
      // Mark invite as accepted
      await tx.update(spaceInvites)
        .set({ status: 'accepted', respondedAt: new Date() })
        .where(eq(spaceInvites.id, inviteId))

      // Upload KeyPackages in the same transaction
      const values = body.keyPackages.map((kp) => ({
        spaceId,
        identityPublicKey: caller.publicKey,
        keyPackage: Buffer.from(kp, 'base64'),
      }))
      await tx.insert(mlsKeyPackages).values(values)
    })

    return c.json({ success: true })
  } catch (error) {
    console.error('Accept invite error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// POST /:spaceId/invites/:inviteId/decline — Decline invite
mlsRouter.post('/:spaceId/invites/:inviteId/decline', async (c) => {
  const user = c.get('user')
  const spaceId = c.req.param('spaceId')
  const inviteId = c.req.param('inviteId')

  try {
    const caller = await resolveCallerIdentity(user.userId)
    if (!caller) return c.json({ error: 'No keypair registered' }, 400)

    const [invite] = await db.select().from(spaceInvites)
      .where(and(
        eq(spaceInvites.id, inviteId),
        eq(spaceInvites.spaceId, spaceId),
        eq(spaceInvites.inviteeDid, caller.did),
        eq(spaceInvites.status, 'pending'),
      ))
      .limit(1)

    if (!invite) return c.json({ error: 'Invite not found or already responded' }, 404)

    await db.update(spaceInvites)
      .set({ status: 'declined', respondedAt: new Date() })
      .where(eq(spaceInvites.id, inviteId))

    return c.json({ success: true })
  } catch (error) {
    console.error('Decline invite error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// DELETE /:spaceId/invites/:inviteId — Withdraw invite (by inviter/admin)
mlsRouter.delete('/:spaceId/invites/:inviteId', async (c) => {
  const user = c.get('user')
  const spaceId = c.req.param('spaceId')
  const inviteId = c.req.param('inviteId')

  try {
    const caller = await resolveCallerIdentity(user.userId)
    if (!caller) return c.json({ error: 'No keypair registered' }, 400)

    const membership = await requireMembership(spaceId, caller.publicKey)
    if (!membership || !['admin', 'owner'].includes(membership.role)) {
      return c.json({ error: 'Only admin or owner can withdraw invites' }, 403)
    }

    const [deleted] = await db.delete(spaceInvites)
      .where(and(eq(spaceInvites.id, inviteId), eq(spaceInvites.spaceId, spaceId)))
      .returning()

    if (!deleted) return c.json({ error: 'Invite not found' }, 404)

    return c.json({ success: true })
  } catch (error) {
    console.error('Delete invite error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// ============================================
// KEY PACKAGES
// ============================================

// POST /:spaceId/mls/key-packages — Upload KeyPackages (batch, for existing members)
const uploadKeyPackagesSchema = z.object({
  keyPackages: z.array(z.string()).min(1).max(100),
})

mlsRouter.post('/:spaceId/mls/key-packages', zValidator('json', uploadKeyPackagesSchema), async (c) => {
  const user = c.get('user')
  const spaceId = c.req.param('spaceId')
  const body = c.req.valid('json')

  try {
    const caller = await resolveCallerIdentity(user.userId)
    if (!caller) return c.json({ error: 'No keypair registered' }, 400)

    // Allow upload if member OR if accepted invite exists (pre-join upload)
    const membership = await requireMembership(spaceId, caller.publicKey)
    if (!membership) {
      const [acceptedInvite] = await db.select().from(spaceInvites)
        .where(and(
          eq(spaceInvites.spaceId, spaceId),
          eq(spaceInvites.inviteeDid, caller.did),
          eq(spaceInvites.status, 'accepted'),
        ))
        .limit(1)
      if (!acceptedInvite) return c.json({ error: 'Not a member and no accepted invite' }, 403)
    }

    const values = body.keyPackages.map((kp) => ({
      spaceId,
      identityPublicKey: caller.publicKey,
      keyPackage: Buffer.from(kp, 'base64'),
    }))

    await db.insert(mlsKeyPackages).values(values)

    return c.json({ success: true, count: values.length }, 201)
  } catch (error) {
    console.error('Upload key packages error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// GET /:spaceId/mls/key-packages/:did — Get one unconsumed KeyPackage (protected by accepted invite)
mlsRouter.get('/:spaceId/mls/key-packages/:did', async (c) => {
  const user = c.get('user')
  const spaceId = c.req.param('spaceId')
  const targetDid = decodeURIComponent(c.req.param('did'))

  try {
    const caller = await resolveCallerIdentity(user.userId)
    if (!caller) return c.json({ error: 'No keypair registered' }, 400)

    const membership = await requireMembership(spaceId, caller.publicKey)
    if (!membership || !['admin', 'owner'].includes(membership.role)) {
      return c.json({ error: 'Only admin or owner can fetch key packages' }, 403)
    }

    // Verify accepted invite exists for the target DID
    const [acceptedInvite] = await db.select().from(spaceInvites)
      .where(and(
        eq(spaceInvites.spaceId, spaceId),
        eq(spaceInvites.inviteeDid, targetDid),
        eq(spaceInvites.status, 'accepted'),
      ))
      .limit(1)

    if (!acceptedInvite) {
      return c.json({ error: 'No accepted invite for this user. Invite must be accepted first.' }, 403)
    }

    // Resolve target DID to public key
    const [targetIdentity] = await db.select().from(identities)
      .where(eq(identities.did, targetDid))
      .limit(1)

    if (!targetIdentity) return c.json({ error: 'Identity not found for this DID' }, 404)

    const [keyPackage] = await db.select()
      .from(mlsKeyPackages)
      .where(and(
        eq(mlsKeyPackages.spaceId, spaceId),
        eq(mlsKeyPackages.identityPublicKey, targetIdentity.publicKey),
        eq(mlsKeyPackages.consumed, false),
      ))
      .limit(1)

    if (!keyPackage) return c.json({ error: 'No key packages available. User needs to upload more.' }, 404)

    await db.update(mlsKeyPackages)
      .set({ consumed: true })
      .where(eq(mlsKeyPackages.id, keyPackage.id))

    return c.json({
      keyPackage: keyPackage.keyPackage.toString('base64'),
      includeHistory: acceptedInvite.includeHistory,
    })
  } catch (error) {
    console.error('Fetch key package error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// ============================================
// MLS MESSAGES
// ============================================

// POST /:spaceId/mls/messages — Send MLS message (commit or application)
const sendMessageSchema = z.object({
  payload: z.string(),
  messageType: z.enum(['commit', 'application']),
  epoch: z.number().optional(),
})

mlsRouter.post('/:spaceId/mls/messages', zValidator('json', sendMessageSchema), async (c) => {
  const user = c.get('user')
  const spaceId = c.req.param('spaceId')
  const body = c.req.valid('json')

  try {
    const caller = await resolveCallerIdentity(user.userId)
    if (!caller) return c.json({ error: 'No keypair registered' }, 400)

    const membership = await requireMembership(spaceId, caller.publicKey)
    if (!membership) return c.json({ error: 'Not a member of this space' }, 403)

    const rows = await db.insert(mlsMessages).values({
      spaceId,
      senderPublicKey: caller.publicKey,
      messageType: body.messageType,
      payload: Buffer.from(body.payload, 'base64'),
      epoch: body.epoch ?? null,
    }).returning({ id: mlsMessages.id })

    return c.json({ success: true, messageId: rows[0]!.id }, 201)
  } catch (error) {
    console.error('Send MLS message error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// GET /:spaceId/mls/messages — Fetch ordered messages (polling)
mlsRouter.get('/:spaceId/mls/messages', async (c) => {
  const user = c.get('user')
  const spaceId = c.req.param('spaceId')
  const after = parseInt(c.req.query('after') ?? '0')
  const limit = Math.min(parseInt(c.req.query('limit') ?? '100'), 1000)

  try {
    const caller = await resolveCallerIdentity(user.userId)
    if (!caller) return c.json({ error: 'No keypair registered' }, 400)

    const membership = await requireMembership(spaceId, caller.publicKey)
    if (!membership) return c.json({ error: 'Not a member of this space' }, 403)

    const messages = await db.select()
      .from(mlsMessages)
      .where(and(
        eq(mlsMessages.spaceId, spaceId),
        gt(mlsMessages.id, after),
      ))
      .orderBy(mlsMessages.id)
      .limit(limit)

    return c.json({
      messages: messages.map((m) => ({
        id: m.id,
        senderPublicKey: m.senderPublicKey,
        messageType: m.messageType,
        payload: m.payload.toString('base64'),
        epoch: m.epoch,
        createdAt: m.createdAt.toISOString(),
      })),
    })
  } catch (error) {
    console.error('Fetch MLS messages error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// ============================================
// WELCOME MESSAGES
// ============================================

// POST /:spaceId/mls/welcome — Send Welcome to specific recipient
const sendWelcomeSchema = z.object({
  recipientDid: z.string(),
  payload: z.string(),
})

mlsRouter.post('/:spaceId/mls/welcome', zValidator('json', sendWelcomeSchema), async (c) => {
  const user = c.get('user')
  const spaceId = c.req.param('spaceId')
  const body = c.req.valid('json')

  try {
    const caller = await resolveCallerIdentity(user.userId)
    if (!caller) return c.json({ error: 'No keypair registered' }, 400)

    const membership = await requireMembership(spaceId, caller.publicKey)
    if (!membership || !['admin', 'owner'].includes(membership.role)) {
      return c.json({ error: 'Only admin or owner can send welcomes' }, 403)
    }

    // Resolve recipient DID to public key
    const [recipient] = await db.select().from(identities)
      .where(eq(identities.did, body.recipientDid))
      .limit(1)

    if (!recipient) return c.json({ error: 'Recipient identity not found' }, 404)

    await db.insert(mlsWelcomeMessages).values({
      spaceId,
      recipientPublicKey: recipient.publicKey,
      payload: Buffer.from(body.payload, 'base64'),
    })

    return c.json({ success: true }, 201)
  } catch (error) {
    console.error('Send welcome error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// GET /:spaceId/mls/welcome — Fetch own unconsumed Welcome messages
mlsRouter.get('/:spaceId/mls/welcome', async (c) => {
  const user = c.get('user')
  const spaceId = c.req.param('spaceId')

  try {
    const caller = await resolveCallerIdentity(user.userId)
    if (!caller) return c.json({ error: 'No keypair registered' }, 400)

    const welcomes = await db.select()
      .from(mlsWelcomeMessages)
      .where(and(
        eq(mlsWelcomeMessages.spaceId, spaceId),
        eq(mlsWelcomeMessages.recipientPublicKey, caller.publicKey),
        eq(mlsWelcomeMessages.consumed, false),
      ))

    if (welcomes.length > 0) {
      for (const w of welcomes) {
        await db.update(mlsWelcomeMessages)
          .set({ consumed: true })
          .where(eq(mlsWelcomeMessages.id, w.id))
      }
    }

    return c.json({
      welcomes: welcomes.map((w) => ({
        id: w.id,
        payload: w.payload.toString('base64'),
        createdAt: w.createdAt.toISOString(),
      })),
    })
  } catch (error) {
    console.error('Fetch welcomes error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

export default mlsRouter
