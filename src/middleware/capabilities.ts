import type { Context } from 'hono'
import { eq, and } from 'drizzle-orm'
import {
  enforceDelegatable,
  findRootIssuer,
  isSpaceCapValue,
  spaceCapabilitySet,
  spaceResource,
  type DelegationError,
  type SpaceCapabilitySet,
} from '@haex-space/ucan'
import type { UcanContext } from './types'
import { db, spaces, spaceMembers } from '../db'

/**
 * The capability set the caller actually holds for one space, or the reason
 * their authority could not be established.
 */
export type CallerAuthority =
  | { ok: true; capabilities: SpaceCapabilitySet }
  | { ok: false; status: 401 | 403; error: string }

/**
 * The space root authority. Under the orthogonal model no capability implies
 * another, so the owner must hold every cap explicitly — all delegatable.
 */
export function ownerCapabilitySet(): SpaceCapabilitySet {
  return spaceCapabilitySet()
    .read(true)
    .write(true)
    .invite(true)
    .admin(true)
    .build()
}

/**
 * Resolve what the authenticated caller actually holds for a space.
 *
 * UCAN callers are trusted only for the caps their token declares, and only
 * once the root issuer of the proof chain is confirmed to be a member of the
 * space — without that, anyone can forge a self-signed UCAN with arbitrary
 * capabilities. DID-Auth callers are accepted solely as the space owner.
 */
export async function resolveCallerAuthority(
  c: Context,
  spaceId: string,
): Promise<CallerAuthority> {
  const ucan = c.get('ucan') as UcanContext | null

  if (ucan) {
    const resource = spaceResource(spaceId)
    const held = ucan.capabilities[resource]

    if (!isSpaceCapValue(held)) {
      return {
        ok: false,
        status: 403,
        error: `Forbidden - Insufficient capability for ${resource}`,
      }
    }

    const rootIssuerDid = findRootIssuer(ucan.verifiedUcan)
    const [member] = await db
      .select({ did: spaceMembers.did })
      .from(spaceMembers)
      .where(and(
        eq(spaceMembers.spaceId, spaceId),
        eq(spaceMembers.did, rootIssuerDid),
      ))
      .limit(1)

    if (!member) {
      return {
        ok: false,
        status: 403,
        error: `Forbidden - UCAN root issuer is not a member of this space`,
      }
    }

    return { ok: true, capabilities: held }
  }

  const didAuth = c.get('didAuth') as { did: string } | null
  if (didAuth) {
    const [space] = await db
      .select({ ownerId: spaces.ownerId })
      .from(spaces)
      .where(eq(spaces.id, spaceId))
      .limit(1)

    if (space && space.ownerId === didAuth.did) {
      return { ok: true, capabilities: ownerCapabilitySet() }
    }

    return { ok: false, status: 403, error: 'Forbidden - Non-owners must provide a UCAN' }
  }

  return { ok: false, status: 403, error: 'Forbidden - No auth context' }
}

/**
 * Check that a grant stays within what the caller may delegate.
 *
 * Deliberately the same predicate the UCAN chain walker applies, so an HTTP
 * invite and a UCAN delegation cannot diverge on what a member may hand out.
 *
 * @returns The first offending cap in SPACE_CAP_ORDER, or null if the grant
 *          is fully covered by the caller's delegatable authority.
 */
export function assertGrantWithinCallerAuthority(
  caller: SpaceCapabilitySet,
  granted: SpaceCapabilitySet,
): DelegationError | null {
  return enforceDelegatable(caller, granted)
}

/**
 * Map a legacy single-tier capability string to its role preset.
 *
 * Interim shim: removed in Phase 4, when the API accepts real CapabilitySets
 * instead of one `space/*` string. Read is a baseline on every preset; a
 * delegated admin may grant read/write/invite but not create further admins.
 *
 * Invariant: in any preset that carries `invite`, every other cap is
 * delegatable — except `admin`. Attenuation reports the first offender in
 * SPACE_CAP_ORDER, so an inviter whose own `read` were non-delegatable would
 * trip on `read` and never reach `invite`, making the cap inert. Holding
 * `admin` non-delegatable is what reserves minting admins to the space root.
 * `invite` itself stays delegatable, so an inviter may create further
 * inviters — bounded, since they can only ever pass on read and invite.
 *
 * Presets without `invite` keep `read` non-delegatable: they can never reach
 * a grant boundary, so least privilege is the honest default there.
 *
 * Throws on an unknown tier — an unrecognized value at a wire boundary must
 * never be silently downgraded to a weaker preset.
 */
export function presetForLegacyTier(tier: string): SpaceCapabilitySet {
  switch (tier) {
    case 'space/read':
      return spaceCapabilitySet().read(false).build()
    case 'space/write':
      return spaceCapabilitySet().read(false).write(false).build()
    case 'space/invite':
      return spaceCapabilitySet().read(true).invite(true).build()
    case 'space/admin':
      return spaceCapabilitySet().read(true).write(true).invite(true).admin(false).build()
    default:
      throw new Error(`Unknown capability tier: ${tier}`)
  }
}
