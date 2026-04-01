import { db, syncChanges, spaces, identities } from '../db'
import { verifyRecordSignatureAsync } from '@haex-space/vault-sdk'
import { eq, and } from 'drizzle-orm'
import type { PushChange } from './sync.schemas'

/**
 * Resolve the space owner's supabaseUserId.
 * Federation changes are billed to the space owner on the origin server.
 */
export async function resolveSpaceOwnerUserId(spaceId: string): Promise<string | null> {
  const [space] = await db
    .select({ ownerId: spaces.ownerId })
    .from(spaces)
    .where(eq(spaces.id, spaceId))
    .limit(1)

  if (!space) return null

  // ownerId is a DID — resolve to supabaseUserId via identities table
  const [identity] = await db
    .select({ supabaseUserId: identities.supabaseUserId })
    .from(identities)
    .where(eq(identities.did, space.ownerId))
    .limit(1)

  return identity?.supabaseUserId ?? null
}

/**
 * Validate changes pushed via federation.
 *
 * Similar to validateSpacePush but without the signedBy === authenticatedUser check,
 * because the authenticated entity is the relay server, not the actual signer.
 *
 * What we still validate:
 * 1. Every change has a signature and signedBy
 * 2. The signature is cryptographically valid
 * 3. Record ownership rules (immutable owner, collaborative flag)
 *
 * What we skip:
 * - signedBy === authenticatedPublicKey (the relay server is not the signer)
 * - Capability check (already done at the federation auth layer via UCAN)
 */
export async function validateFederationPush(
  changes: PushChange[],
  spaceId: string,
  tx: Parameters<Parameters<typeof db.transaction>[0]>[0],
): Promise<{ valid: boolean; error?: string }> {
  for (const change of changes) {
    // 1. Signature required
    if (!change.signature || !change.signedBy) {
      return { valid: false, error: `Change for ${change.tableName}/${change.rowPks} missing signature` }
    }

    // 2. Verify signature cryptographically
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

    // 3. Record ownership check
    const existingRecord = await tx.select({
      recordOwner: syncChanges.recordOwner,
      collaborative: syncChanges.collaborative,
    }).from(syncChanges)
      .where(and(
        eq(syncChanges.spaceId, spaceId),
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

      // Data modification: owner or collaborative record
      const isRecordOwner = change.signedBy === existing.recordOwner
      const isCollaborative = existing.collaborative === true
      if (!isRecordOwner && !isCollaborative) {
        return { valid: false, error: `Cannot modify record owned by ${existing.recordOwner}` }
      }
    }
  }

  return { valid: true }
}
