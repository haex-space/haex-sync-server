import { createMiddleware } from 'hono/factory'
import { db, spaceAccessTokens } from '../db'
import { eq, and } from 'drizzle-orm'

export interface SpaceTokenContext {
  spaceId: string
  tokenId: string
  publicKey: string
  role: string
  isSpaceToken: true
}

declare module 'hono' {
  interface ContextVariableMap {
    spaceToken: SpaceTokenContext | null
  }
}

export const spaceTokenAuthMiddleware = createMiddleware(async (c, next) => {
  const spaceToken = c.req.header('X-Space-Token')

  if (!spaceToken) {
    c.set('spaceToken', null)
    return next()
  }

  const result = await db.select()
    .from(spaceAccessTokens)
    .where(and(
      eq(spaceAccessTokens.token, spaceToken),
      eq(spaceAccessTokens.revoked, false),
    ))
    .limit(1)

  if (result.length === 0) {
    return c.json({ error: 'Invalid or revoked space token' }, 401)
  }

  const tokenRecord = result[0]!

  // Update lastUsedAt (fire-and-forget, don't block the request)
  db.update(spaceAccessTokens)
    .set({ lastUsedAt: new Date() })
    .where(eq(spaceAccessTokens.id, tokenRecord.id))
    .catch(() => {})

  c.set('spaceToken', {
    spaceId: tokenRecord.spaceId,
    tokenId: tokenRecord.id,
    publicKey: tokenRecord.publicKey,
    role: tokenRecord.role,
    isSpaceToken: true,
  })

  return next()
})
