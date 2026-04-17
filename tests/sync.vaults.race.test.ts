/**
 * Tests for the vault-key race fix (2.2).
 *
 * Before the fix, POST /vault-key did a check-then-insert across a separate
 * SELECT and a db.transaction(). Two concurrent requests for the same
 * spaceId could both pass the SELECT, both enter the tx, and hit a UNIQUE
 * constraint violation on vault_keys — surfacing as a 500 instead of a
 * clean 409.
 *
 * After the fix, the insert uses `.onConflictDoNothing()` inside the
 * transaction; when the insert is skipped, the handler returns 409.
 *
 * We exercise the REAL route handler (via the real mlsRouter? no — sync.vaults
 * is mounted under `/sync/`). We swap in an in-memory db fake that models a
 * UNIQUE(userId, spaceId) constraint to make the race observable.
 */

import { describe, test, expect, mock, beforeAll, beforeEach } from 'bun:test'
import { makeIdentity, createDidAuthHeader } from './integration/helpers'
import { buildDbMock } from './helpers/db-mock'

// ── Fake Postgres for spaces + vault_keys ───────────────────────────────

interface VaultKeyRow {
  id: string
  userId: string
  spaceId: string
  encryptedVaultKey: string
  encryptedVaultName: string
  vaultKeySalt: string
  ephemeralPublicKey: string
  vaultKeyNonce: string
  vaultNameNonce: string
  vaultNameSalt: string
  createdAt: Date
}

const vaultKeyStore = new Map<string, VaultKeyRow>() // key = `${userId}:${spaceId}`
const spacesStore = new Map<string, { id: string; type: string; ownerId: string }>()

let insertAttempts = 0
let didAuthIdentityRow: { supabaseUserId: string; did: string; publicKey: string } | null = null

// A shared transaction runner that preserves isolation: two concurrent calls
// see the same db state (no per-tx snapshot), but `onConflictDoNothing`
// guarantees idempotence on the vault_keys insert.
function buildTx() {
  return {
    insert: (table: any) => {
      const chain: any = {}
      let vals: any = null
      chain.values = (v: any) => { vals = v; return chain }
      chain.onConflictDoNothing = () => chain
      chain.returning = async () => {
        insertAttempts++
        if (table === 'spaces_table') {
          if (spacesStore.has(vals.id)) return []
          spacesStore.set(vals.id, { id: vals.id, type: vals.type, ownerId: vals.ownerId })
          return [vals]
        }
        if (table === 'vault_keys_table') {
          const key = `${vals.userId}:${vals.spaceId}`
          if (vaultKeyStore.has(key)) return [] // skipped due to conflict
          const row: VaultKeyRow = {
            id: `vk-${Math.random().toString(36).slice(2)}`,
            userId: vals.userId,
            spaceId: vals.spaceId,
            encryptedVaultKey: vals.encryptedVaultKey,
            encryptedVaultName: vals.encryptedVaultName,
            vaultKeySalt: vals.vaultKeySalt,
            ephemeralPublicKey: vals.ephemeralPublicKey,
            vaultKeyNonce: vals.vaultKeyNonce,
            vaultNameNonce: vals.vaultNameNonce,
            vaultNameSalt: vals.vaultNameSalt,
            createdAt: new Date(),
          }
          vaultKeyStore.set(key, row)
          return [row]
        }
        return []
      }
      // Support `.values(...)` awaited directly (pre-fix pattern) — this
      // throws on conflict, modelling the PG UNIQUE constraint.
      chain.then = (resolve: any) => {
        if (!vals) return resolve()
        if (table === 'vault_keys_table') {
          const key = `${vals.userId}:${vals.spaceId}`
          if (vaultKeyStore.has(key)) throw new Error('UNIQUE constraint: vault_keys(user_id, space_id)')
          vaultKeyStore.set(key, { ...vals, id: 'x', createdAt: new Date() } as any)
        }
        return resolve()
      }
      return chain
    },
  }
}

const db = {
  query: {
    vaultKeys: {
      findFirst: async () => {
        for (const row of vaultKeyStore.values()) return row
        return undefined
      },
    },
  },
  transaction: async (fn: (tx: any) => any) => fn(buildTx()),
  // resolveDidIdentity queries `from(identities)`; any select on the
  // identities sentinel returns the pre-staged caller row.
  select: () => {
    let tableSentinel: string | null = null
    const chain: any = {}
    chain.from = (t: any) => { tableSentinel = t; return chain }
    chain.where = () => chain
    chain.limit = () => {
      if (tableSentinel === 'identities_table') {
        return Promise.resolve(didAuthIdentityRow ? [didAuthIdentityRow] : [])
      }
      return Promise.resolve([])
    }
    chain.orderBy = () => chain
    return chain
  },
  insert: () => {
    const chain: any = {}
    chain.values = () => chain
    chain.onConflictDoNothing = () => chain
    chain.returning = async () => []
    return chain
  },
  delete: () => {
    const chain: any = {}
    chain.where = () => chain
    chain.returning = async () => []
    return chain
  },
  update: () => {
    const chain: any = {}
    chain.set = () => chain
    chain.where = () => chain
    chain.returning = async () => []
    return chain
  },
}

// Some modules (e.g. middleware/didAuth) import `identities` directly from
// ../db/schema, bypassing the ../db index. Mock the schema module with the
// same sentinel strings so both import paths see consistent stubs.
const tableStubs = {
  vaultKeys: 'vault_keys_table',
  spaces: 'spaces_table',
  identities: 'identities_table',
  spaceMembers: 'space_members_table',
  syncChanges: 'sync_changes_table',
  authChallenges: 'auth_challenges_table',
  authUsers: 'auth_users_table',
  federationEvents: 'federation_events_table',
  federationLinks: 'federation_links_table',
  federationServers: 'federation_servers_table',
  mlsGroupInfo: 'mls_group_info_table',
  mlsKeyPackages: 'mls_key_packages_table',
  mlsMessages: 'mls_messages_table',
  mlsWelcomeMessages: 'mls_welcome_messages_table',
  spaceInvites: 'space_invites_table',
  spaceInviteTokens: 'space_invite_tokens_table',
  tiers: 'tiers_table',
  userStorageCredentials: 'user_storage_credentials_table',
}

mock.module('../src/db/schema', () => tableStubs)

mock.module('../src/db', () => {
  return { db, ...tableStubs }
})

let syncRouter: { request: (path: string, init?: any) => Response | Promise<Response> }
let caller: { did: string; keyPair: CryptoKeyPair }

beforeAll(async () => {
  const id = await makeIdentity()
  caller = { did: id.did, keyPair: id.keyPair }
  didAuthIdentityRow = {
    supabaseUserId: 'supa-user-uuid',
    did: id.did,
    publicKey: 'deadbeef',
  }
  syncRouter = (await import('../src/routes/sync.vaults')).default
})

beforeEach(() => {
  vaultKeyStore.clear()
  spacesStore.clear()
  insertAttempts = 0
})

async function postVaultKey(spaceId: string) {
  const body = JSON.stringify({
    spaceId,
    encryptedVaultKey: 'abc',
    encryptedVaultName: 'def',
    vaultKeySalt: 'salt',
    ephemeralPublicKey: 'epub',
    vaultKeyNonce: 'nonce',
    vaultNameNonce: 'n2',
    vaultNameSalt: 'ns',
  })
  const header = await createDidAuthHeader(caller.keyPair.privateKey, caller.did, 'vault-create', body)
  return syncRouter.request('/vault-key', {
    method: 'POST',
    headers: { Authorization: header, 'Content-Type': 'application/json' },
    body,
  })
}

// sync.vaults.ts expects authDispatcher mounted in the parent router, so we
// need to simulate that by mounting it ourselves (real module, real chain).
let wrappedSyncRouter: any

beforeAll(async () => {
  const { Hono } = await import('hono')
  const { authDispatcher } = await import('../src/middleware/authDispatcher')
  const app = new Hono()
  app.use('/*', authDispatcher)
  app.route('/', syncRouter as any)
  wrappedSyncRouter = app
})

async function postVaultKeyWrapped(spaceId: string) {
  const body = JSON.stringify({
    spaceId,
    encryptedVaultKey: 'abc',
    encryptedVaultName: 'def',
    vaultKeySalt: 'salt',
    ephemeralPublicKey: 'epub',
    vaultKeyNonce: 'nonce',
    vaultNameNonce: 'n2',
    vaultNameSalt: 'ns',
  })
  const header = await createDidAuthHeader(caller.keyPair.privateKey, caller.did, 'vault-create', body)
  return wrappedSyncRouter.request('/vault-key', {
    method: 'POST',
    headers: { Authorization: header, 'Content-Type': 'application/json' },
    body,
  })
}

// ── Tests ───────────────────────────────────────────────────────────────

describe('POST /vault-key — race-safety (fix 2.2)', () => {
  test('first create succeeds with 201', async () => {
    const res = await postVaultKeyWrapped('11111111-1111-4111-8111-111111111111')
    expect(res.status).toBe(201)
  })

  test('duplicate create (sequential) returns 409, not 500', async () => {
    const spaceId = '22222222-2222-4222-8222-222222222222'
    const first = await postVaultKeyWrapped(spaceId)
    expect(first.status).toBe(201)

    const second = await postVaultKeyWrapped(spaceId)
    expect(second.status).toBe(409)
    const body = await second.json() as any
    expect(body.error).toContain('already exists')
  })

  test('concurrent creates (race) — exactly one 201, the other 409; never 500', async () => {
    const spaceId = '33333333-3333-4333-8333-333333333333'
    const [a, b] = await Promise.all([
      postVaultKeyWrapped(spaceId),
      postVaultKeyWrapped(spaceId),
    ])
    const statuses = [a.status, b.status].sort()
    expect(statuses).toEqual([201, 409])
    // Only one row in store.
    expect(vaultKeyStore.size).toBe(1)
  })

  test('storm test: 10 concurrent creates — one 201, nine 409s, no 500', async () => {
    const spaceId = '44444444-4444-4444-8444-444444444444'
    const results = await Promise.all(
      Array.from({ length: 10 }, () => postVaultKeyWrapped(spaceId)),
    )
    const statuses = results.map(r => r.status)
    const twoOhOnes = statuses.filter(s => s === 201).length
    const fourOhNines = statuses.filter(s => s === 409).length
    const fiveHundreds = statuses.filter(s => s === 500).length
    expect(twoOhOnes).toBe(1)
    expect(fourOhNines).toBe(9)
    expect(fiveHundreds).toBe(0)
    expect(vaultKeyStore.size).toBe(1)
  })

  test('attack scenario: attacker races a legit user — cannot overwrite existing vault key', async () => {
    const spaceId = '55555555-5555-4555-8555-555555555555'
    // Pre-seed as though an attacker inserted first.
    vaultKeyStore.set(`supa-user-uuid:${spaceId}`, {
      id: 'seeded',
      userId: 'supa-user-uuid',
      spaceId,
      encryptedVaultKey: 'seeded-attacker-value',
      encryptedVaultName: 'x',
      vaultKeySalt: 'x',
      ephemeralPublicKey: 'x',
      vaultKeyNonce: 'x',
      vaultNameNonce: 'x',
      vaultNameSalt: 'x',
      createdAt: new Date(),
    })

    const res = await postVaultKeyWrapped(spaceId)
    expect(res.status).toBe(409)
    // The seeded row is intact — no overwrite happened.
    expect(vaultKeyStore.get(`supa-user-uuid:${spaceId}`)!.encryptedVaultKey).toBe('seeded-attacker-value')
  })
})
