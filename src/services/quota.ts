import { db } from '../db'
import { identities, syncChanges, tiers, vaultKeys, spaces } from '../db/schema'
import { eq, sql } from 'drizzle-orm'

export interface QuotaInfo {
  tier: string
  maxBytes: number
  usedBytes: number
  remainingBytes: number
  isOverQuota: boolean
}

export interface PartitionQuotaInfo {
  tier: string
  maxPartitions: number
  usedPartitions: number
  canCreate: boolean
}

/**
 * Calculate storage usage for a user.
 * Counts all sync_changes owned by this user (personal vault data + admin spaces).
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

  // If no tier entry found, treat as unlimited (operator hasn't configured limits)
  const maxBytes = tier ? parseInt(tier.maxStorageBytes) : Number.MAX_SAFE_INTEGER

  // 3. Sum all storage owned by this user (personal vaults + space data they pushed)
  const [result] = await db.select({
    totalBytes: sql<string>`COALESCE(SUM(LENGTH(${syncChanges.encryptedValue})), 0)`,
  })
    .from(syncChanges)
    .where(eq(syncChanges.userId, supabaseUserId))

  const usedBytes = parseInt(result?.totalBytes ?? '0')

  return {
    tier: identity.tier,
    maxBytes,
    usedBytes,
    remainingBytes: Math.max(0, maxBytes - usedBytes),
    isOverQuota: usedBytes > maxBytes,
  }
}

/**
 * Check if a user can create a new partition (vault or space).
 * Counts vault_keys (user's vaults) + spaces (user is owner) against tier limit.
 */
export async function getPartitionQuotaAsync(supabaseUserId: string): Promise<PartitionQuotaInfo> {
  const [identity] = await db.select()
    .from(identities)
    .where(eq(identities.supabaseUserId, supabaseUserId))
    .limit(1)

  if (!identity) {
    throw new Error('Identity not found')
  }

  const [tier] = await db.select()
    .from(tiers)
    .where(eq(tiers.name, identity.tier))
    .limit(1)

  const maxPartitions = tier?.maxSpaces ?? 3

  const [vaultCount] = await db.select({
    count: sql<number>`cast(count(*) as int)`,
  })
    .from(vaultKeys)
    .where(eq(vaultKeys.userId, supabaseUserId))

  const [spaceCount] = await db.select({
    count: sql<number>`cast(count(*) as int)`,
  })
    .from(spaces)
    .where(eq(spaces.ownerId, supabaseUserId))

  const usedPartitions = (vaultCount?.count ?? 0) + (spaceCount?.count ?? 0)

  return {
    tier: identity.tier,
    maxPartitions,
    usedPartitions,
    canCreate: usedPartitions < maxPartitions,
  }
}
