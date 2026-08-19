import { describe, test, expect } from 'bun:test'
import { spaceCapabilitySet } from '@haex-space/ucan'
import {
  assertGrantWithinCallerAuthority,
  ownerCapabilitySet,
  presetForLegacyTier,
} from '../src/middleware/capabilities'

// ============================================
// assertGrantWithinCallerAuthority
// ============================================

// A member may only hand out capabilities they hold *and* may delegate.
// enforceDelegatable reports the first offender in SPACE_CAP_ORDER
// (read, write, invite, admin), so a caller whose own read is
// non-delegatable trips on read before any later cap is considered.

describe('grant attenuation', () => {
  const inviteOnly = spaceCapabilitySet().read(true).invite(true).build()

  // write is the first cap the inviter lacks, so it is reported before admin.
  // The admin boundary itself is pinned by the delegated-admin case below.
  test('rejects a full four-cap grant from an invite-only caller', () => {
    const granted = spaceCapabilitySet()
      .read(true).write(true).invite(true).admin(true).build()
    expect(assertGrantWithinCallerAuthority(inviteOnly, granted))
      .toEqual({ kind: 'missing', cap: 'write' })
  })

  test('rejects a write grant from an invite-only caller', () => {
    const granted = spaceCapabilitySet().read(false).write(false).build()
    expect(assertGrantWithinCallerAuthority(inviteOnly, granted))
      .toEqual({ kind: 'missing', cap: 'write' })
  })

  test('rejects a grant of a cap the caller holds non-delegatably', () => {
    const writerNonDelegatable = spaceCapabilitySet().read(false).write(false).build()
    const granted = spaceCapabilitySet().read(false).write(false).build()
    expect(assertGrantWithinCallerAuthority(writerNonDelegatable, granted))
      .toEqual({ kind: 'not_delegatable', cap: 'read' })
  })

  test('rejects an invite grant from a caller who holds no invite', () => {
    const writerNoInvite = spaceCapabilitySet().read(true).write(true).build()
    const granted = spaceCapabilitySet().read(true).invite(true).build()
    expect(assertGrantWithinCallerAuthority(writerNoInvite, granted))
      .toEqual({ kind: 'missing', cap: 'invite' })
  })

  test('rejects an admin grant from a delegated admin caller', () => {
    const admin = presetForLegacyTier('space/admin')
    expect(assertGrantWithinCallerAuthority(admin, presetForLegacyTier('space/admin')))
      .toEqual({ kind: 'not_delegatable', cap: 'admin' })
  })

  test('accepts a reader grant from an admin caller', () => {
    const admin = spaceCapabilitySet()
      .read(true).write(true).invite(true).admin(false).build()
    const granted = spaceCapabilitySet().read(false).build()
    expect(assertGrantWithinCallerAuthority(admin, granted)).toBeNull()
  })

  test('accepts an admin grant from the space owner', () => {
    const owner = spaceCapabilitySet()
      .read(true).write(true).invite(true).admin(true).build()
    expect(assertGrantWithinCallerAuthority(owner, presetForLegacyTier('space/admin')))
      .toBeNull()
  })
})

// ============================================
// ownerCapabilitySet
// ============================================

describe('ownerCapabilitySet', () => {
  // The space root holds every cap explicitly — no cap implies another under
  // the orthogonal model — and all of them delegatably. admin(false) here
  // would strip the root's ability to mint admins at all, so this pins the
  // exact array rather than probing it through an attenuation check.
  test('grants all four caps, every one delegatable', () => {
    expect(ownerCapabilitySet()).toEqual([
      { cap: 'read', delegatable: true },
      { cap: 'write', delegatable: true },
      { cap: 'invite', delegatable: true },
      { cap: 'admin', delegatable: true },
    ])
  })
})

// ============================================
// presetForLegacyTier
// ============================================

describe('presetForLegacyTier', () => {
  test('space/read maps to a non-delegatable reader', () => {
    expect(presetForLegacyTier('space/read')).toEqual([
      { cap: 'read', delegatable: false },
    ])
  })

  test('space/write maps to a non-delegatable writer', () => {
    expect(presetForLegacyTier('space/write')).toEqual([
      { cap: 'read', delegatable: false },
      { cap: 'write', delegatable: false },
    ])
  })

  test('space/invite maps to a reader that may delegate read and invite', () => {
    expect(presetForLegacyTier('space/invite')).toEqual([
      { cap: 'read', delegatable: true },
      { cap: 'invite', delegatable: true },
    ])
  })

  // The inviter row's read MUST stay delegatable. Attenuation reports the
  // first offender in SPACE_CAP_ORDER, so a non-delegatable read would trip
  // before invite is ever considered and the cap would grant nothing at all.
  test('an inviter can grant a reader but not a writer', () => {
    const inviter = presetForLegacyTier('space/invite')
    expect(assertGrantWithinCallerAuthority(inviter, presetForLegacyTier('space/read')))
      .toBeNull()
    expect(assertGrantWithinCallerAuthority(inviter, presetForLegacyTier('space/write')))
      .toEqual({ kind: 'missing', cap: 'write' })
  })

  test('space/admin may delegate read/write/invite but not admin', () => {
    expect(presetForLegacyTier('space/admin')).toEqual([
      { cap: 'read', delegatable: true },
      { cap: 'write', delegatable: true },
      { cap: 'invite', delegatable: true },
      { cap: 'admin', delegatable: false },
    ])
  })

  test('throws on an unknown tier instead of downgrading', () => {
    expect(() => presetForLegacyTier('space/superuser')).toThrow()
    expect(() => presetForLegacyTier('read')).toThrow()
  })
})
