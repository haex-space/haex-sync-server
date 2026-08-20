import type { Context } from 'hono'
import { eq } from 'drizzle-orm'
import {
  enforceDelegatable,
  holdsSpaceCap,
  isSpaceCapValue,
  spaceCapabilitySet,
  spaceResource,
  type DelegationError,
  type SpaceCap,
  type SpaceCapabilitySet,
  type VerifiedUcan,
} from '@haex-space/ucan'
import type { UcanContext } from './types'
import { db, spaces } from '../db'

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
 * Every distinct root issuer in a verified proof forest.
 *
 * `findRootIssuer` from the library follows `proofs[0]` only, while
 * `verifyDelegationChain` is satisfied by *any* proof whose audience matches
 * the issuer. Those need not be the same proof, so a caller can launder a
 * self-signed root by parking an unrelated borrowed proof in slot 0. Only
 * inspecting every root closes that. Replaced by `findAllRootIssuers`
 * upstream in Phase 2; walking locally until then.
 *
 * Depth is already bounded by `verifyUcan`'s MAX_PROOF_DEPTH, so a crafted
 * token cannot drive this into unbounded recursion.
 */
function collectRootIssuers(verified: VerifiedUcan, into = new Set<string>()): Set<string> {
  if (verified.proofs.length === 0) {
    into.add(verified.payload.iss)
    return into
  }
  for (const proof of verified.proofs) {
    collectRootIssuers(proof, into)
  }
  return into
}

/**
 * Resolve what the authenticated caller actually holds for a space.
 *
 * UCAN callers are trusted only for the caps their token declares, and only
 * once every root of the proof forest is the space owner. A valid signature
 * proves who issued a token, never that they had standing to issue it:
 * `verifyUcan` skips the delegation-chain check entirely for a token with no
 * proofs, so anchoring on the owner is what makes a self-signed capability
 * worthless. Membership is deliberately NOT sufficient — a member could
 * otherwise self-sign a root claiming caps their membership never granted.
 *
 * DID-Auth callers are accepted solely as the space owner.
 *
 * haex-vault's Rust verifier instead binds the space id to the root DID
 * (`verify_space_id_binding`), which is not portable here: `spaces.id` is a
 * uuid column enforced by `createSpaceSchema`, and UUID primary keys are a
 * project invariant. `spaces.ownerId` is the server-side equivalent anchor.
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

    const roots = collectRootIssuers(ucan.verifiedUcan)
    const [space] = await db
      .select({ ownerId: spaces.ownerId })
      .from(spaces)
      .where(eq(spaces.id, spaceId))
      .limit(1)

    // Fail closed: an absent space, or an empty forest, must not pass. One
    // message covers both so space existence is not an oracle.
    const rootedInOwner =
      space !== undefined
      && roots.size > 0
      && [...roots].every((root) => root === space.ownerId)

    if (!rootedInOwner) {
      return {
        ok: false,
        status: 403,
        error: 'Forbidden - UCAN chain must root in the space owner',
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
 * Authorize a caller for one capability AND hand back what they hold.
 *
 * For grant sites, which need both: the gate, and the caller's actual set to
 * attenuate a requested grant against. Calling `requireCapability` and then
 * resolving again would repeat the owner lookup on every such request.
 *
 * `requireCapability` delegates here, so the rejection strings live in exactly
 * one place and the two entry points cannot drift apart.
 */
export async function requireCapabilityWithAuthority(
  c: Context,
  spaceId: string,
  required: SpaceCap,
): Promise<
  | { ok: true; capabilities: SpaceCapabilitySet }
  | { ok: false; response: Response }
> {
  const authority = await resolveCallerAuthority(c, spaceId)

  if (!authority.ok) {
    return { ok: false, response: c.json({ error: authority.error }, authority.status) }
  }

  // Exact match only — no capability implies another under the orthogonal model.
  if (!holdsSpaceCap(authority.capabilities, required)) {
    return {
      ok: false,
      response: c.json(
        {
          error: `Forbidden - Insufficient capability for ${spaceResource(spaceId)}, requires ${required}`,
        },
        403,
      ),
    }
  }

  return { ok: true, capabilities: authority.capabilities }
}

/**
 * The part of a grant that exceeds what the caller may delegate.
 *
 * Deliberately the same predicate the UCAN chain walker applies, so the two
 * routes where a caller names the granted capability — invite tokens and
 * direct member invitation — cannot diverge from a UCAN delegation on what a
 * member may hand out. Routes that set a capability from a constant rather
 * than from caller input (space creation, ownership transfer, federation
 * setup) are not grants and deliberately do not use this.
 *
 * Named for what it returns rather than what it checks: a truthy result means
 * the grant is NOT allowed. Call sites read `if (grantExceeding…) return 403`.
 *
 * @returns The first offending cap in SPACE_CAP_ORDER, or null if the grant
 *          is fully covered by the caller's delegatable authority.
 */
export function grantExceedingCallerAuthority(
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
