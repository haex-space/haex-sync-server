import { db, syncChanges, spaces, identities } from '../db'
import { verifyRecordSignatureAsync } from '@haex-space/vault-sdk'
import { eq, and } from 'drizzle-orm'
import { lookup } from 'dns/promises'
import type { PushChange } from './sync.schemas'

/**
 * Validate an external server URL before issuing any fetch to prevent SSRF.
 *
 * Blocks:
 * - Non-http(s) schemes
 * - Literal private/loopback/link-local IPs in the hostname
 * - Hostnames that DNS-resolve to private IPs (defeats DNS rebinding)
 */
export async function validateOriginServerUrl(url: string): Promise<{ valid: boolean; error?: string }> {
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return { valid: false, error: 'Invalid URL' }
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return { valid: false, error: `Unsupported protocol: ${parsed.protocol}` }
  }

  // URL.hostname keeps IPv6 brackets (e.g. "[::1]") — strip them so the
  // reserved-IP check can match on the raw address.
  const rawHostname = parsed.hostname.toLowerCase()
  const hostname = rawHostname.startsWith('[') && rawHostname.endsWith(']')
    ? rawHostname.slice(1, -1)
    : rawHostname

  if (hostname === '' || hostname === 'localhost' || hostname.endsWith('.localhost') || hostname === '0.0.0.0') {
    return { valid: false, error: 'Loopback host is not allowed' }
  }

  if (isPrivateOrReservedIp(hostname)) {
    return { valid: false, error: 'Private IP is not allowed' }
  }

  // DNS pre-check — protects against rebinding and hostnames pointing to internal IPs.
  try {
    const resolved = await lookup(hostname, { all: true })
    for (const entry of resolved) {
      if (isPrivateOrReservedIp(entry.address)) {
        return { valid: false, error: 'Hostname resolves to a private IP' }
      }
    }
  } catch {
    return { valid: false, error: 'DNS resolution failed' }
  }

  return { valid: true }
}

function isPrivateOrReservedIp(host: string): boolean {
  // IPv6 loopback / link-local / unique-local
  if (host === '::1' || host === '::' || host.startsWith('fe80:') || host.startsWith('fc') || host.startsWith('fd')) {
    return true
  }

  // IPv4
  const ipv4Match = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (!ipv4Match) return false

  const [a, b] = [parseInt(ipv4Match[1]!, 10), parseInt(ipv4Match[2]!, 10)]
  if (a === 10) return true                       // 10.0.0.0/8
  if (a === 127) return true                      // 127.0.0.0/8 loopback
  if (a === 169 && b === 254) return true         // link-local
  if (a === 172 && b >= 16 && b <= 31) return true // 172.16.0.0/12
  if (a === 192 && b === 168) return true         // 192.168.0.0/16
  if (a === 0) return true                        // 0.0.0.0/8
  if (a >= 224) return true                       // multicast / reserved

  return false
}

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
