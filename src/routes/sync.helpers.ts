import { db, syncChanges, spaces, spaceMembers, identities } from '../db'
import { verifyRecordSignatureAsync } from '@haex-space/vault-sdk'
import { eq, and } from 'drizzle-orm'
import type { PushChange } from './sync.schemas'

/** Check if a vaultId corresponds to a space */
export async function isSpacePartition(vaultId: string): Promise<boolean> {
  const result = await db.select({ id: spaces.id })
    .from(spaces)
    .where(eq(spaces.id, vaultId))
    .limit(1)
  return result.length > 0
}

/** Look up a user's public key from the identities table */
export async function getUserPublicKey(userId: string): Promise<string | null> {
  const [identity] = await db.select()
    .from(identities)
    .where(eq(identities.supabaseUserId, userId))
    .limit(1)
  return identity?.publicKey ?? null
}

/** Look up a user's role in a space by resolving their publicKey */
export async function getCallerRoleByUserId(spaceId: string, userId: string): Promise<string | null> {
  const publicKey = await getUserPublicKey(userId)
  if (!publicKey) return null
  const result = await db.select({ role: spaceMembers.role })
    .from(spaceMembers)
    .where(and(
      eq(spaceMembers.spaceId, spaceId),
      eq(spaceMembers.publicKey, publicKey),
    ))
    .limit(1)
  return result[0]?.role ?? null
}

/** Validate all changes in a space push (signatures, ownership, roles) */
export async function validateSpacePush(
  changes: PushChange[],
  spaceId: string,
  authenticatedPublicKey: string,
  role: string,
  tx: Parameters<Parameters<typeof db.transaction>[0]>[0],
): Promise<{ valid: boolean; error?: string }> {
  // 1. Role check
  if (role === 'viewer') {
    return { valid: false, error: 'Viewers cannot push changes' }
  }

  for (const change of changes) {
    // 2. Signature required
    if (!change.signature || !change.signedBy) {
      return { valid: false, error: `Change for ${change.tableName}/${change.rowPks} missing signature` }
    }

    // 3. signedBy must match authenticated user
    if (change.signedBy !== authenticatedPublicKey) {
      return { valid: false, error: 'signedBy does not match authenticated user' }
    }

    // 4. Verify signature cryptographically
    const isValid = await verifyRecordSignatureAsync(
      {
        tableName: change.tableName,
        rowPks: change.rowPks,
        columnName: change.columnName,
        encryptedValue: change.encryptedValue,
        hlcTimestamp: change.hlcTimestamp,
      },
      change.signature,
      change.signedBy,
    )
    if (!isValid) {
      return { valid: false, error: `Invalid signature for ${change.tableName}/${change.rowPks}` }
    }

    // 5. Record ownership check (per-row, not per-column)
    const existingRecord = await tx.select({
      recordOwner: syncChanges.recordOwner,
      collaborative: syncChanges.collaborative,
    }).from(syncChanges)
      .where(and(
        eq(syncChanges.vaultId, spaceId),
        eq(syncChanges.tableName, change.tableName),
        eq(syncChanges.rowPks, change.rowPks),
      ))
      .limit(1)

    if (existingRecord.length === 0) {
      // New record: server sets record_owner = signedBy
      change.recordOwner = change.signedBy
    } else {
      const existing = existingRecord[0]!

      // Cannot change record_owner
      if (change.recordOwner && change.recordOwner !== existing.recordOwner) {
        return { valid: false, error: `Cannot change record_owner for ${change.rowPks}` }
      }
      change.recordOwner = existing.recordOwner

      // collaborative flag: only owner can change
      if (change.collaborative !== undefined && change.collaborative !== existing.collaborative) {
        if (change.signedBy !== existing.recordOwner) {
          return { valid: false, error: 'Only record owner can change collaborative flag' }
        }
      }

      // Data modification: only owner or collaborative (applies to updates and deletes)
      const isOwner = change.signedBy === existing.recordOwner
      const isCollaborative = existing.collaborative === true
      if (!isOwner && !isCollaborative) {
        return { valid: false, error: `Cannot modify record owned by ${existing.recordOwner}` }
      }
    }
  }

  return { valid: true }
}
