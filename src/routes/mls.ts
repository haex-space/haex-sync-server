import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { db, spaceMembers, identities, mlsKeyPackages, mlsMessages, mlsWelcomeMessages, spaceInvites, spaceInviteTokens } from '../db'
import { authDispatcher } from '../middleware/authDispatcher'
import { requireCapability } from '../middleware/ucanAuth'
import { resolveDidIdentity } from '../middleware/didAuth'
import { eq, and, gt, sql } from 'drizzle-orm'
import { broadcastToSpace, sendToDid } from './ws'

const mlsRouter = new Hono()

mlsRouter.use('/*', authDispatcher)

function getCallerDid(c: any): string | null {
  const ucan = c.get('ucan')
  if (ucan) return ucan.issuerDid
  const didAuth = c.get('didAuth')
  if (didAuth) return didAuth.did
  return null
}

// ============================================
// INVITES (2-Step: Invite → Accept → MLS Add)
// ============================================

// POST /:spaceId/invites — Create pending invite (direct, DID known)
const createInviteSchema = z.object({
  inviteeDid: z.string().min(1),
  includeHistory: z.boolean().optional().default(false),
  expiresInSeconds: z.number().int().min(60).max(60 * 60 * 24 * 90).optional().default(60 * 60 * 24 * 7), // default 7 days
})

mlsRouter.post('/:spaceId/invites', zValidator('json', createInviteSchema), async (c) => {
  const spaceId = c.req.param('spaceId')
  const body = c.req.valid('json')

  const error = await requireCapability(c, spaceId, 'space/invite')
  if (error) return error

  try {
    const callerDid = getCallerDid(c)!
    const identity = await resolveDidIdentity(callerDid)
    if (!identity) return c.json({ error: 'Identity not found' }, 404)

    const expiresAt = new Date(Date.now() + body.expiresInSeconds * 1000)

    const [invite] = await db.insert(spaceInvites).values({
      spaceId,
      inviterPublicKey: identity.publicKey,
      inviteeDid: body.inviteeDid,
      includeHistory: body.includeHistory,
      expiresAt,
    }).onConflictDoNothing().returning()

    if (!invite) {
      return c.json({ error: 'Invite already exists for this user' }, 409)
    }

    // Notify the invitee about the new invite
    sendToDid(body.inviteeDid, { type: 'invite', spaceId, inviteId: invite.id })

    return c.json({ success: true, invite: { id: invite.id, status: invite.status } }, 201)
  } catch (error) {
    console.error('Create invite error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// GET /:spaceId/invites — List invites (for space members: all invites; for non-members: own invites)
mlsRouter.get('/:spaceId/invites', async (c) => {
  const spaceId = c.req.param('spaceId')

  const capError = await requireCapability(c, spaceId, 'space/read')
  if (capError) return capError

  try {
    const callerDid = getCallerDid(c)!
    const identity = await resolveDidIdentity(callerDid)
    if (!identity) return c.json({ error: 'Identity not found' }, 404)

    const [membership] = await db.select({ role: spaceMembers.role })
      .from(spaceMembers)
      .where(and(eq(spaceMembers.spaceId, spaceId), eq(spaceMembers.publicKey, identity.publicKey)))
      .limit(1)

    let invites
    if (membership) {
      // Space members see all invites
      invites = await db.select().from(spaceInvites)
        .where(eq(spaceInvites.spaceId, spaceId))
    } else {
      // Non-members see only their own invites
      invites = await db.select().from(spaceInvites)
        .where(and(eq(spaceInvites.spaceId, spaceId), eq(spaceInvites.inviteeDid, identity.did)))
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
  const spaceId = c.req.param('spaceId')
  const inviteId = c.req.param('inviteId')
  const body = c.req.valid('json')

  const didAuth = c.get('didAuth')
  if (!didAuth) return c.json({ error: 'Invite accept requires DID-Auth' }, 401)

  try {
    const identity = await resolveDidIdentity(didAuth.did)
    if (!identity) return c.json({ error: 'Identity not found' }, 404)

    const [invite] = await db.select().from(spaceInvites)
      .where(and(
        eq(spaceInvites.id, inviteId),
        eq(spaceInvites.spaceId, spaceId),
        eq(spaceInvites.inviteeDid, identity.did),
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
        identityPublicKey: identity.publicKey,
        keyPackage: Buffer.from(kp, 'base64'),
      }))
      await tx.insert(mlsKeyPackages).values(values)
    })

    // Notify space members about the new membership
    broadcastToSpace(spaceId, { type: 'membership', spaceId })

    return c.json({ success: true })
  } catch (error) {
    console.error('Accept invite error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// POST /:spaceId/invites/:inviteId/decline — Decline invite
mlsRouter.post('/:spaceId/invites/:inviteId/decline', async (c) => {
  const spaceId = c.req.param('spaceId')
  const inviteId = c.req.param('inviteId')

  const callerDid = getCallerDid(c)
  if (!callerDid) return c.json({ error: 'Auth required' }, 401)

  try {
    const identity = await resolveDidIdentity(callerDid)
    if (!identity) return c.json({ error: 'Identity not found' }, 404)

    const [invite] = await db.select().from(spaceInvites)
      .where(and(
        eq(spaceInvites.id, inviteId),
        eq(spaceInvites.spaceId, spaceId),
        eq(spaceInvites.inviteeDid, identity.did),
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
  const spaceId = c.req.param('spaceId')
  const inviteId = c.req.param('inviteId')

  const capError = await requireCapability(c, spaceId, 'space/invite')
  if (capError) return capError

  try {
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
  const spaceId = c.req.param('spaceId')
  const body = c.req.valid('json')

  const capError = await requireCapability(c, spaceId, 'space/read')
  if (capError) return capError

  try {
    const callerDid = getCallerDid(c)!
    const identity = await resolveDidIdentity(callerDid)
    if (!identity) return c.json({ error: 'Identity not found' }, 404)

    const values = body.keyPackages.map((kp) => ({
      spaceId,
      identityPublicKey: identity.publicKey,
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
  const spaceId = c.req.param('spaceId')
  const targetDid = decodeURIComponent(c.req.param('did'))

  const capError = await requireCapability(c, spaceId, 'space/invite')
  if (capError) return capError

  try {
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
  const spaceId = c.req.param('spaceId')
  const body = c.req.valid('json')

  const capError = await requireCapability(c, spaceId, 'space/write')
  if (capError) return capError

  try {
    const callerDid = getCallerDid(c)!
    const identity = await resolveDidIdentity(callerDid)
    if (!identity) return c.json({ error: 'Identity not found' }, 404)

    const rows = await db.insert(mlsMessages).values({
      spaceId,
      senderPublicKey: identity.publicKey,
      messageType: body.messageType,
      payload: Buffer.from(body.payload, 'base64'),
      epoch: body.epoch ?? null,
    }).returning({ id: mlsMessages.id })

    // Notify space members about the new MLS message
    broadcastToSpace(spaceId, { type: 'mls', spaceId }, callerDid)

    return c.json({ success: true, messageId: rows[0]!.id }, 201)
  } catch (error) {
    console.error('Send MLS message error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// GET /:spaceId/mls/messages — Fetch ordered messages (polling)
mlsRouter.get('/:spaceId/mls/messages', async (c) => {
  const spaceId = c.req.param('spaceId')
  const after = parseInt(c.req.query('after') ?? '0')
  const limit = Math.min(parseInt(c.req.query('limit') ?? '100'), 1000)

  const capError = await requireCapability(c, spaceId, 'space/read')
  if (capError) return capError

  try {
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
  const spaceId = c.req.param('spaceId')
  const body = c.req.valid('json')

  const capError = await requireCapability(c, spaceId, 'space/invite')
  if (capError) return capError

  try {
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
  const spaceId = c.req.param('spaceId')

  const capError = await requireCapability(c, spaceId, 'space/read')
  if (capError) return capError

  try {
    const callerDid = getCallerDid(c)!
    const identity = await resolveDidIdentity(callerDid)
    if (!identity) return c.json({ error: 'Identity not found' }, 404)

    const welcomes = await db.select()
      .from(mlsWelcomeMessages)
      .where(and(
        eq(mlsWelcomeMessages.spaceId, spaceId),
        eq(mlsWelcomeMessages.recipientPublicKey, identity.publicKey),
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

// ============================================
// INVITE TOKENS (link/QR code invites)
// ============================================

// POST /:spaceId/invite-tokens — Create an invite token (link or QR code)
const createTokenSchema = z.object({
  capability: z.enum(['space/admin', 'space/write', 'space/read']).default('space/write'),
  maxUses: z.number().int().min(1).max(1000).default(1),
  expiresInSeconds: z.number().int().min(60).max(60 * 60 * 24 * 90), // 1 min to 90 days
  label: z.string().max(200).optional(),
})

mlsRouter.post('/:spaceId/invite-tokens', zValidator('json', createTokenSchema), async (c) => {
  const spaceId = c.req.param('spaceId')
  const body = c.req.valid('json')

  const capError = await requireCapability(c, spaceId, 'space/invite')
  if (capError) return capError

  try {
    const callerDid = getCallerDid(c)!
    const expiresAt = new Date(Date.now() + body.expiresInSeconds * 1000)

    const [token] = await db.insert(spaceInviteTokens).values({
      spaceId,
      createdByDid: callerDid,
      capability: body.capability,
      maxUses: body.maxUses,
      label: body.label,
      expiresAt,
    }).returning()

    return c.json({
      token: {
        id: token!.id,
        capability: token!.capability,
        maxUses: token!.maxUses,
        expiresAt: token!.expiresAt.toISOString(),
        label: token!.label,
      },
    }, 201)
  } catch (error) {
    console.error('Create invite token error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// GET /:spaceId/invite-tokens — List active tokens for this space
mlsRouter.get('/:spaceId/invite-tokens', async (c) => {
  const spaceId = c.req.param('spaceId')

  const capError = await requireCapability(c, spaceId, 'space/invite')
  if (capError) return capError

  try {
    const tokens = await db.select().from(spaceInviteTokens)
      .where(and(
        eq(spaceInviteTokens.spaceId, spaceId),
        gt(spaceInviteTokens.expiresAt, new Date()),
      ))

    return c.json({
      tokens: tokens.map((t) => ({
        id: t.id,
        capability: t.capability,
        maxUses: t.maxUses,
        usedCount: t.usedCount,
        label: t.label,
        expiresAt: t.expiresAt.toISOString(),
        createdAt: t.createdAt.toISOString(),
      })),
    })
  } catch (error) {
    console.error('List invite tokens error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// DELETE /:spaceId/invite-tokens/:tokenId — Revoke a token
mlsRouter.delete('/:spaceId/invite-tokens/:tokenId', async (c) => {
  const spaceId = c.req.param('spaceId')
  const tokenId = c.req.param('tokenId')

  const capError = await requireCapability(c, spaceId, 'space/invite')
  if (capError) return capError

  try {
    const [deleted] = await db.delete(spaceInviteTokens)
      .where(and(eq(spaceInviteTokens.id, tokenId), eq(spaceInviteTokens.spaceId, spaceId)))
      .returning()

    if (!deleted) return c.json({ error: 'Token not found' }, 404)
    return c.json({ success: true })
  } catch (error) {
    console.error('Delete invite token error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// POST /:spaceId/invite-tokens/:tokenId/claim — Claim a token (no auth required, token IS the auth)
const claimTokenSchema = z.object({
  keyPackages: z.array(z.string()).min(1).max(20),
})

mlsRouter.post('/:spaceId/invite-tokens/:tokenId/claim', zValidator('json', claimTokenSchema), async (c) => {
  const spaceId = c.req.param('spaceId')
  const tokenId = c.req.param('tokenId')
  const body = c.req.valid('json')

  // Claim requires DID-Auth (we need to know who's claiming)
  const didAuth = c.get('didAuth')
  if (!didAuth) return c.json({ error: 'Token claim requires DID-Auth' }, 401)

  try {
    const identity = await resolveDidIdentity(didAuth.did)
    if (!identity) return c.json({ error: 'Identity not found' }, 404)

    // Validate token: exists, not expired, not exhausted
    const [token] = await db.select().from(spaceInviteTokens)
      .where(and(
        eq(spaceInviteTokens.id, tokenId),
        eq(spaceInviteTokens.spaceId, spaceId),
        gt(spaceInviteTokens.expiresAt, new Date()),
      ))
      .limit(1)

    if (!token) return c.json({ error: 'Invalid or expired invite token' }, 404)
    if (token.usedCount >= token.maxUses) return c.json({ error: 'Invite token has been fully used' }, 410)

    await db.transaction(async (tx) => {
      // Increment usage counter
      await tx.update(spaceInviteTokens)
        .set({ usedCount: sql`${spaceInviteTokens.usedCount} + 1` })
        .where(eq(spaceInviteTokens.id, tokenId))

      // Create accepted invite (skip pending state — token is pre-authorization)
      await tx.insert(spaceInvites).values({
        spaceId,
        inviterPublicKey: token.createdByDid,
        inviteeDid: identity.did,
        status: 'accepted',
        tokenId,
        expiresAt: token.expiresAt,
        respondedAt: new Date(),
      }).onConflictDoNothing()

      // Upload KeyPackages
      const values = body.keyPackages.map((kp) => ({
        spaceId,
        identityPublicKey: identity.publicKey,
        keyPackage: Buffer.from(kp, 'base64'),
      }))
      await tx.insert(mlsKeyPackages).values(values)
    })

    // Notify space members
    broadcastToSpace(spaceId, { type: 'membership', spaceId })

    return c.json({ success: true, capability: token.capability })
  } catch (error) {
    console.error('Claim invite token error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

export default mlsRouter
