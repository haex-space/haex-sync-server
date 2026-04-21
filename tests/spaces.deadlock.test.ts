/**
 * Regression: parallel createSpace must not deadlock on partition DDL.
 *
 * Without the advisory lock in src/routes/spaces.ts, two concurrent
 * createSpace transactions deadlock because the AFTER INSERT trigger runs
 *   CREATE TABLE ... PARTITION OF sync_changes
 *   ALTER PUBLICATION supabase_realtime ADD TABLE ...
 * Both statements take ShareUpdateExclusive/ShareRowExclusive locks on
 * the parent table and publication catalog in orders that can cycle
 * under concurrency (SQLSTATE 40P01 → surfaces as HTTP 500 to the client).
 *
 * This test spins up a real postgres via testcontainers, applies the
 * full migration + partitioning.sql, and drives parallel INSERT INTO
 * spaces rows to reproduce the scenario end-to-end.
 */

import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import postgres from 'postgres'

// ── Test fixtures ─────────────────────────────────────────────────────────

const CONTAINER_NAME = `haex-sync-deadlock-test-${process.pid}`
let sql: ReturnType<typeof postgres>

async function waitForPg(host: string, port: number, maxMs = 60_000): Promise<void> {
  const deadline = Date.now() + maxMs
  while (Date.now() < deadline) {
    try {
      const probe = postgres({ host, port, user: 'postgres', password: 'postgres', database: 'postgres', max: 1 })
      await probe`SELECT 1`
      await probe.end()
      return
    } catch {
      await new Promise((r) => setTimeout(r, 500))
    }
  }
  throw new Error(`Postgres at ${host}:${port} not ready after ${maxMs}ms`)
}

// CI runners have a cold docker cache: pulling postgres:15 alone takes ~5s,
// plus container boot and all migrations replay. Bun's default hook timeout
// of 5s is not enough. 120s is comfortably over the observed ~10s cost.
beforeAll(async () => {
  // Spawn postgres via plain `docker run` — avoids the testcontainers library's
  // wait-strategy hangs observed with Bun. Ports are randomized to avoid
  // collision with the dev docker-compose or other parallel runs.
  const port = 20000 + Math.floor(Math.random() * 10_000)

  spawnSync('docker', [
    'run', '-d',
    '--rm',
    '--name', CONTAINER_NAME,
    '-e', 'POSTGRES_PASSWORD=postgres',
    '-p', `${port}:5432`,
    'postgres:15',
  ], { stdio: 'inherit' })

  await waitForPg('127.0.0.1', port)

  sql = postgres({
    host: '127.0.0.1',
    port,
    user: 'postgres',
    password: 'postgres',
    database: 'postgres',
    max: 20,
  })

  // Stub Supabase symbols referenced by the migrations + partitioning.sql.
  // Early migrations FK into auth.users; later migrations drop those FKs and
  // retype the columns. Providing a minimal auth schema lets the historic
  // migrations replay cleanly without pulling in the full Supabase platform.
  await sql.unsafe(`
    CREATE SCHEMA IF NOT EXISTS auth;
    CREATE TABLE IF NOT EXISTS auth.users (id uuid PRIMARY KEY);
    CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid AS $$ SELECT NULL::uuid $$ LANGUAGE SQL STABLE;
  `)

  // Apply all drizzle migrations in order (mirrors scripts/migrate.ts),
  // then partitioning.sql for the trigger under test. Dynamic listing so
  // adding a new migration doesn't require touching this test.
  const migrationsDir = join(import.meta.dir, '../drizzle/migrations')
  const migrationFiles = readdirSync(migrationsDir)
    .filter((f) => f.endsWith('.sql'))
    .sort() // filenames are NNNN_-prefixed; lexical sort matches chronological order
  for (const file of migrationFiles) {
    const migrationSql = readFileSync(join(migrationsDir, file), 'utf-8')
    await sql.unsafe(migrationSql)
  }

  const partitioningSql = readFileSync(
    join(import.meta.dir, '../drizzle/partitioning.sql'),
    'utf-8',
  )
  await sql.unsafe(partitioningSql)
}, 120_000)

afterAll(async () => {
  await sql?.end()
  spawnSync('docker', ['rm', '-f', CONTAINER_NAME], { stdio: 'ignore' })
}, 30_000)

// ── Helpers ────────────────────────────────────────────────────────────────

/**
 * Insert a space the same way the route handler does:
 *   BEGIN
 *   SELECT pg_advisory_xact_lock(hashtext('haex.create_space')::bigint)
 *   INSERT INTO spaces ...                 ← trigger fires here
 *   INSERT INTO space_members ...
 *   COMMIT
 *
 * Returns true on success, false if postgres raised a deadlock (SQLSTATE
 * 40P01). Other errors are re-thrown.
 */
async function createSpaceTx(spaceId: string, ownerDid: string): Promise<boolean> {
  try {
    await sql.begin(async (tx) => {
      await tx`SELECT pg_advisory_xact_lock(hashtext('haex.create_space')::bigint)`
      await tx`
        INSERT INTO spaces (id, type, owner_id, encrypted_name, name_nonce)
        VALUES (${spaceId}, 'shared', ${ownerDid}, 'enc', 'nonce')
      `
      await tx`
        INSERT INTO space_members (space_id, public_key, did, label, capability, invited_by)
        VALUES (${spaceId}, 'pk', ${ownerDid}, 'Self', 'space/admin', NULL)
      `
    })
    return true
  } catch (err: any) {
    if (err?.code === '40P01') return false // deadlock
    throw err
  }
}

function makeUuid(): string {
  return crypto.randomUUID()
}

// ── Regression test ────────────────────────────────────────────────────────

describe('POST /spaces — partition-DDL deadlock regression', () => {
  test('N parallel createSpace transactions all commit without deadlock', async () => {
    const N = 12
    const spaceIds = Array.from({ length: N }, makeUuid)
    const ownerDid = 'did:key:z6MkTestOwner'

    const results = await Promise.all(
      spaceIds.map((id) => createSpaceTx(id, ownerDid)),
    )

    // No deadlocks (40P01) and no other silent failures.
    const deadlocks = results.filter((r) => r === false).length
    expect(deadlocks).toBe(0)
    expect(results.every((r) => r === true)).toBe(true)

    // Defend against silent rollbacks: every space we tried to create
    // must actually exist in the spaces table.
    const [{ count }] = await sql<[{ count: number }]>`
      SELECT COUNT(*)::int AS count FROM spaces WHERE id = ANY(${spaceIds})
    `
    expect(count).toBe(N)
  })
})
