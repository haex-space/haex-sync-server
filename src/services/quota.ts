import { db } from '../db'
import { identities, spaceMembers, syncChanges, tiers } from '../db/schema'
import { eq, and, sql } from 'drizzle-orm'

export interface QuotaInfo {
  tier: string
  maxBytes: number
  usedBytes: number
  remainingBytes: number
  isOverQuota: boolean
}

/**
 * Calculate storage usage for a user across all spaces they admin.
 * Only space admins carry the quota burden.
 */
export async function getUserQuotaAsync(supabaseUserId: string): Promise<QuotaInfo> {
  // 1. Get user's identity and tier
  const [identity] = await db.select()
    .from(identities)
    .where(eq(identities.supabaseUserId, supabaseUserId))
    .limit(1)

  if (!identity) {
    throw new Error('Identity not found')
  }

  // 2. Get tier limits
  const [tier] = await db.select()
    .from(tiers)
    .where(eq(tiers.name, identity.tier))
    .limit(1)

  const maxBytes = tier ? parseInt(tier.maxStorageBytes) : 0

  // 3. Find all spaces where user is admin
  const adminSpaces = await db.select({ spaceId: spaceMembers.spaceId })
    .from(spaceMembers)
    .where(and(
      eq(spaceMembers.publicKey, identity.publicKey),
      eq(spaceMembers.role, 'admin'),
    ))

  if (adminSpaces.length === 0) {
    return { tier: identity.tier, maxBytes, usedBytes: 0, remainingBytes: maxBytes, isOverQuota: false }
  }

  // 4. Sum storage across all admin spaces (vaultId = spaceId for spaces)
  const spaceIds = adminSpaces.map(s => s.spaceId)
  const [result] = await db.select({
    totalBytes: sql<string>`COALESCE(SUM(LENGTH(${syncChanges.encryptedValue})), 0)`,
  })
    .from(syncChanges)
    .where(sql`${syncChanges.vaultId} IN ${spaceIds}`)

  const usedBytes = parseInt(result?.totalBytes ?? '0')

  return {
    tier: identity.tier,
    maxBytes,
    usedBytes,
    remainingBytes: Math.max(0, maxBytes - usedBytes),
    isOverQuota: usedBytes > maxBytes,
  }
}
