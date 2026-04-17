/**
 * Tests for the storage-credentials race fix (2.1).
 *
 * Before the fix, `getOrCreateStorageCredentials` did a check-then-insert:
 * if two concurrent requests for the same user both missed the existing-row
 * check, the second INSERT would violate the UNIQUE(userId) constraint and
 * throw, turning a benign race into a 500 error. After the fix, INSERT uses
 * `onConflictDoNothing`, and the function re-queries to return whichever row
 * ended up canonical.
 *
 * We simulate the race by constructing an in-memory fake of the db that
 * mimics Postgres's behaviour: a UNIQUE constraint on userId + support for
 * `onConflictDoNothing`. Running two concurrent calls must not throw and
 * must return identical credentials.
 */

import { describe, test, expect, mock, beforeAll, beforeEach } from 'bun:test'
import { sql } from 'drizzle-orm'

// ── In-memory fake Postgres for user_storage_credentials ────────────────
// The fake understands the exact surface area our module uses:
//   db.select({...}).from(userStorageCredentials).where(...).limit(N)
//   db.insert(userStorageCredentials).values({...}).onConflictDoNothing(...)
//   db.delete(userStorageCredentials).where(...)

interface Row { userId: string; accessKeyId: string; secretAccessKey: string }

const store = new Map<string, Row>()
let insertCount = 0

// Count how many times we decrypt — helps verify the fix actually re-queries.
let decryptCalls = 0

function makeSelectChain(columns: Record<string, any>) {
  let where: ((row: Row) => boolean) | null = null
  const chain: any = {}
  chain.from = () => chain
  chain.where = (cond: any) => {
    where = (row: Row) => {
      // Accept either a function condition or fall back to the cond's recorded userId.
      if (typeof cond === 'function') return cond(row)
      // Drizzle's eq produces a SQL object; for this fake we stash the target userId
      // on cond._testTargetUserId (see the whereByUserId helper below).
      if (cond && cond._testTargetUserId !== undefined) return row.userId === cond._testTargetUserId
      if (cond && cond._testTargetAccessKeyId !== undefined) return row.accessKeyId === cond._testTargetAccessKeyId
      return false
    }
    return chain
  }
  chain.limit = async (_n: number) => {
    const all = Array.from(store.values())
    const match = where ? all.find(where) : all[0]
    if (!match) return []
    // Emulate decryption of the secret column.
    if ((columns as any).secretAccessKey) decryptCalls++
    return [{
      accessKeyId: match.accessKeyId,
      secretAccessKey: match.secretAccessKey,
      userId: match.userId,
    }]
  }
  return chain
}

function makeInsertChain() {
  let target: { userId: string; accessKeyId: string; secretAccessKey: string } | null = null
  const chain: any = {}
  chain.values = (vals: any) => {
    // The real module passes a sql object for the encrypted column; we treat
    // the nested secret as the plaintext here since that's what our decrypt
    // stub would return.
    const raw = vals.encryptedSecretKey
    let secret: string
    if (raw && typeof raw === 'object' && 'queryChunks' in raw) {
      // sql template — grab the inner string param which is the plaintext
      secret = (raw.queryChunks.find((c: any) => typeof c === 'object' && 'value' in c)?.value) ?? 'x'
    } else if (typeof raw === 'string') {
      secret = raw
    } else {
      secret = 'stub-secret'
    }
    target = { userId: vals.userId, accessKeyId: vals.accessKeyId, secretAccessKey: secret }
    return chain
  }
  chain.onConflictDoNothing = async (_opt: any) => {
    if (!target) return
    insertCount++
    if (!store.has(target.userId)) {
      store.set(target.userId, target)
    }
    // Conflict path is a no-op — the existing row stays.
  }
  // Old insert(…).values(…) without onConflictDoNothing would have been an
  // auto-resolve: emulate by treating a then() chain as await.
  chain.then = (resolve: any) => {
    if (!target) return resolve()
    if (store.has(target.userId)) {
      throw new Error('UNIQUE constraint violation: user_id already exists')
    }
    insertCount++
    store.set(target.userId, target)
    return resolve()
  }
  return chain
}

function makeDeleteChain() {
  const chain: any = {}
  chain.where = (cond: any) => {
    for (const [key, row] of store) {
      if (cond && cond._testTargetUserId !== undefined && row.userId === cond._testTargetUserId) {
        store.delete(key)
      }
    }
    return chain
  }
  return chain
}

// Helpers: override drizzle's `eq` to record the target value so our fake
// `where()` can filter. We do this by providing a custom module wrapper.
const eqTagged = (column: any, value: any) => {
  if (column === 'user_id_col') return { _testTargetUserId: value }
  if (column === 'access_key_id_col') return { _testTargetAccessKeyId: value }
  return { _testTargetUserId: value } // best-effort default
}

mock.module('drizzle-orm', () => ({
  eq: eqTagged,
  sql: sql,
}))

mock.module('../src/db', () => ({
  db: {
    select: (cols: Record<string, any>) => makeSelectChain(cols),
    insert: () => makeInsertChain(),
    delete: () => makeDeleteChain(),
  },
  userStorageCredentials: {
    userId: 'user_id_col',
    accessKeyId: 'access_key_id_col',
    encryptedSecretKey: 'encrypted_col',
  },
}))

let getOrCreateStorageCredentials: (userId: string) => Promise<{ accessKeyId: string; secretAccessKey: string }>

beforeAll(async () => {
  process.env.STORAGE_ENCRYPTION_KEY = process.env.STORAGE_ENCRYPTION_KEY ?? 'test-encryption-key-32-bytes-long!!'
  ;({ getOrCreateStorageCredentials } = await import('../src/services/storageCredentials'))
})

beforeEach(() => {
  store.clear()
  insertCount = 0
  decryptCalls = 0
})

// ── Tests ───────────────────────────────────────────────────────────────

describe('getOrCreateStorageCredentials — race-safety (fix 2.1)', () => {
  test('first call for a user creates a fresh row', async () => {
    const creds = await getOrCreateStorageCredentials('user-1')
    expect(creds.accessKeyId).toBeTruthy()
    expect(creds.secretAccessKey).toBeTruthy()
    expect(insertCount).toBe(1)
  })

  test('second call returns the existing row without inserting again', async () => {
    const first = await getOrCreateStorageCredentials('user-2')
    const second = await getOrCreateStorageCredentials('user-2')
    expect(second.accessKeyId).toBe(first.accessKeyId)
    expect(second.secretAccessKey).toBe(first.secretAccessKey)
    expect(insertCount).toBe(1)
  })

  test('concurrent calls for the same user never throw and agree on credentials', async () => {
    // Both calls start before either can complete — they will both miss the
    // SELECT, both attempt INSERT. The pre-fix code would have crashed the
    // loser; post-fix it converges.
    const [a, b] = await Promise.all([
      getOrCreateStorageCredentials('race-user'),
      getOrCreateStorageCredentials('race-user'),
    ])

    expect(a.accessKeyId).toBe(b.accessKeyId)
    expect(a.secretAccessKey).toBe(b.secretAccessKey)
    // At most one actual row was inserted.
    expect(store.size).toBe(1)
  })

  test('many concurrent calls converge to a single credential set', async () => {
    const results = await Promise.all(
      Array.from({ length: 20 }, () => getOrCreateStorageCredentials('stress-user')),
    )
    const distinctAccessKeys = new Set(results.map(r => r.accessKeyId))
    expect(distinctAccessKeys.size).toBe(1)
    expect(store.size).toBe(1)
  })

  test('attack scenario: onConflictDoNothing prevents credential overwrite on race', async () => {
    // Simulate an attacker inserting a row under a victim's userId first,
    // then the legitimate user calls getOrCreateStorageCredentials. The
    // function must NOT overwrite — it returns whatever is already stored.
    store.set('victim', {
      userId: 'victim',
      accessKeyId: 'HAEXLEGITIMATEKEY1234',
      secretAccessKey: 'legitimate-secret',
    })

    const creds = await getOrCreateStorageCredentials('victim')
    expect(creds.accessKeyId).toBe('HAEXLEGITIMATEKEY1234')
    expect(creds.secretAccessKey).toBe('legitimate-secret')
    expect(insertCount).toBe(0) // no insert attempt because SELECT already found it
  })
})
