import { describe, test, expect, beforeAll, afterAll, beforeEach } from 'bun:test'
import { drizzle } from 'drizzle-orm/postgres-js'
import postgres from 'postgres'
import { eq, and, gt, max, asc, sql } from 'drizzle-orm'
import { pgTable, text, timestamp, uuid, uniqueIndex, index, pgSchema } from 'drizzle-orm/pg-core'

// Define schema for tests (same as production but isolated)
const authSchema = pgSchema('auth')
const authUsers = authSchema.table('users', {
  id: uuid('id').primaryKey(),
})

const vaultKeys = pgTable('vault_keys', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id')
    .notNull()
    .references(() => authUsers.id, { onDelete: 'cascade' }),
  vaultId: text('vault_id').notNull(),
  encryptedVaultKey: text('encrypted_vault_key').notNull(),
  encryptedVaultName: text('encrypted_vault_name').notNull(),
  vaultKeySalt: text('vault_key_salt').notNull(),
  vaultNameSalt: text('vault_name_salt').notNull(),
  vaultKeyNonce: text('vault_key_nonce').notNull(),
  vaultNameNonce: text('vault_name_nonce').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
})

const syncChanges = pgTable(
  'sync_changes',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => authUsers.id, { onDelete: 'cascade' }),
    vaultId: text('vault_id').notNull(),
    tableName: text('table_name').notNull(),
    rowPks: text('row_pks').notNull(),
    columnName: text('column_name'),
    hlcTimestamp: text('hlc_timestamp').notNull(),
    deviceId: text('device_id'),
    encryptedValue: text('encrypted_value'),
    nonce: text('nonce'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex('sync_changes_unique_cell').on(
      table.vaultId,
      table.tableName,
      table.rowPks,
      table.columnName
    ),
    index('sync_changes_user_vault_idx').on(table.userId, table.vaultId),
    index('sync_changes_hlc_idx').on(table.hlcTimestamp),
    index('sync_changes_updated_idx').on(table.updatedAt),
    index('sync_changes_device_idx').on(table.deviceId),
  ]
)

// Test database connection - prefer DATABASE_URL_TEST to avoid production data pollution
const connectionString = process.env.DATABASE_URL_TEST || process.env.DATABASE_URL

// Skip all tests if no database is available (e.g., in CI without DB)
if (!connectionString) {
  describe('Pagination Tests', () => {
    test.skip('skipped - no DATABASE_URL available', () => {})
  })
  // Prevent rest of file from executing by using a conditional export pattern
} else {
  // Warn if using production database
  if (!process.env.DATABASE_URL_TEST && process.env.DATABASE_URL) {
    console.warn('⚠️  WARNING: Using DATABASE_URL for tests. Set DATABASE_URL_TEST for isolation.')
  }

  const client = postgres(connectionString)
  const db = drizzle(client, { schema: { syncChanges, authUsers, vaultKeys } })

// Test data - use unique identifiers to avoid collisions with production data
const TEST_RUN_ID = Date.now().toString(36) // Unique per test run
const TEST_USER_ID = '00000000-0000-0000-0000-000000000099' // Dedicated test user UUID
const TEST_VAULT_ID = `__test__pagination__${TEST_RUN_ID}`

/**
 * Helper: Create a test user in auth.users and vault_keys
 */
async function createTestUserAndVault(userId: string, vaultId: string) {
  await client`INSERT INTO auth.users (id) VALUES (${userId}) ON CONFLICT (id) DO NOTHING`
  await db
    .insert(vaultKeys)
    .values({
      userId,
      vaultId,
      encryptedVaultKey: 'test-key',
      encryptedVaultName: 'test-name',
      vaultKeySalt: 'test-salt',
      vaultNameSalt: 'test-name-salt',
      vaultKeyNonce: 'test-nonce',
      vaultNameNonce: 'test-name-nonce',
    })
    .onConflictDoNothing()
}

/**
 * Helper: Delete test data (current run)
 */
async function cleanupTestData() {
  await db.delete(syncChanges).where(eq(syncChanges.vaultId, TEST_VAULT_ID))
}

/**
 * Helper: Delete ALL test data (including previous runs)
 * Cleans up any leftover data from failed test runs
 */
async function cleanupAllTestData() {
  // Delete all sync_changes with test vault IDs (prefix __test__)
  await client`DELETE FROM sync_changes WHERE vault_id LIKE '__test__%'`
  // Delete all vault_keys with test vault IDs
  await client`DELETE FROM vault_keys WHERE vault_id LIKE '__test__%'`
}

/**
 * Helper: Bulk insert sync changes (simulates bulk import with same timestamps)
 */
async function bulkInsertChanges(
  changes: Array<{
    tableName: string
    rowPks: string
    columnName: string | null
    hlcTimestamp: string
  }>
) {
  // Insert in chunks to avoid parameter limit
  const CHUNK_SIZE = 500

  for (let i = 0; i < changes.length; i += CHUNK_SIZE) {
    const chunk = changes.slice(i, i + CHUNK_SIZE)
    await db.insert(syncChanges).values(
      chunk.map((change) => ({
        userId: TEST_USER_ID,
        vaultId: TEST_VAULT_ID,
        tableName: change.tableName,
        rowPks: change.rowPks,
        columnName: change.columnName,
        hlcTimestamp: change.hlcTimestamp,
        encryptedValue: 'test-value',
        nonce: 'test-nonce',
      }))
    )
  }
}

/**
 * Simulate the pagination query from sync.ts
 * Uses (updatedAt, tableName, rowPks) cursor for stable pagination even with equal timestamps
 */
async function pullChangesWithPagination(
  afterUpdatedAt: string | undefined,
  afterTableName: string | undefined,
  afterRowPks: string | undefined,
  limit: number
): Promise<{
  rowCount: number
  columnCount: number
  hasMore: boolean
  serverTimestamp: string
  lastTableName: string | undefined
  lastRowPks: string | undefined
  uniqueRows: Set<string>
}> {
  // Step 1: Find rows using GROUP BY with HAVING for cursor-based pagination
  const modifiedRowsQuery = await db
    .select({
      tableName: syncChanges.tableName,
      rowPks: syncChanges.rowPks,
      // Get max timestamp as ISO string with full microsecond precision to avoid cursor drift
      maxUpdatedAtIso: sql<string>`to_char(max(${syncChanges.updatedAt}) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`.as('max_updated_at_iso'),
    })
    .from(syncChanges)
    .where(
      and(
        eq(syncChanges.userId, TEST_USER_ID),
        eq(syncChanges.vaultId, TEST_VAULT_ID),
      )
    )
    .groupBy(syncChanges.tableName, syncChanges.rowPks)
    // Use HAVING to filter based on the aggregated MAX(updated_at) for proper cursor pagination
    // Condition: (timestamp > afterTimestamp) OR (timestamp = afterTimestamp AND (tableName, rowPks) > (afterTableName, afterRowPks))
    .having(
      afterUpdatedAt
        ? afterTableName && afterRowPks
          ? sql`(
              max(${syncChanges.updatedAt}) > ${afterUpdatedAt}::timestamptz
              OR (
                max(${syncChanges.updatedAt}) = ${afterUpdatedAt}::timestamptz
                AND (${syncChanges.tableName}, ${syncChanges.rowPks}) > (${afterTableName}, ${afterRowPks})
              )
            )`
          : sql`max(${syncChanges.updatedAt}) > ${afterUpdatedAt}::timestamptz`
        : undefined
    )
    .orderBy(asc(max(syncChanges.updatedAt)), asc(syncChanges.tableName), asc(syncChanges.rowPks))
    .limit(limit)

  if (modifiedRowsQuery.length === 0) {
    return {
      rowCount: 0,
      columnCount: 0,
      hasMore: false,
      serverTimestamp: new Date().toISOString(),
      lastTableName: undefined,
      lastRowPks: undefined,
      uniqueRows: new Set(),
    }
  }

  // Step 2: Fetch all columns for these rows
  const rowConditions = modifiedRowsQuery.map((row) =>
    and(eq(syncChanges.tableName, row.tableName), eq(syncChanges.rowPks, row.rowPks))
  )

  const allColumnsForRows = await db.query.syncChanges.findMany({
    where: and(
      eq(syncChanges.userId, TEST_USER_ID),
      eq(syncChanges.vaultId, TEST_VAULT_ID),
      sql`(${sql.join(rowConditions, sql` OR `)})`
    ),
    orderBy: syncChanges.updatedAt,
  })

  const hasMore = modifiedRowsQuery.length >= limit

  const lastRow = modifiedRowsQuery[modifiedRowsQuery.length - 1]
  const serverTimestamp = lastRow?.maxUpdatedAtIso ?? new Date().toISOString()

  const uniqueRows = new Set(allColumnsForRows.map((c) => `${c.tableName}:${c.rowPks}`))

  return {
    rowCount: modifiedRowsQuery.length,
    columnCount: allColumnsForRows.length,
    hasMore,
    serverTimestamp,
    lastTableName: lastRow?.tableName,
    lastRowPks: lastRow?.rowPks,
    uniqueRows,
  }
}

describe('Pagination Tests', () => {
  beforeAll(async () => {
    // Clean up any leftover test data from previous runs
    await cleanupAllTestData()
    await createTestUserAndVault(TEST_USER_ID, TEST_VAULT_ID)
  })

  afterAll(async () => {
    // Clean up all test data (not just current run)
    await cleanupAllTestData()
    await client.end()
  })

  beforeEach(async () => {
    await cleanupTestData()
  })

  test('pagination completes for bulk import with identical timestamps', async () => {
    // Simulate bulk import: 1500 rows, each with 5 columns
    // All inserted in same transaction = same timestamp
    const NUM_ROWS = 1500
    const COLUMNS_PER_ROW = 5
    const PAGE_LIMIT = 100

    console.log(`Creating ${NUM_ROWS} rows with ${COLUMNS_PER_ROW} columns each (bulk import)...`)

    const changes: Array<{
      tableName: string
      rowPks: string
      columnName: string | null
      hlcTimestamp: string
    }> = []

    for (let row = 0; row < NUM_ROWS; row++) {
      for (let col = 0; col < COLUMNS_PER_ROW; col++) {
        changes.push({
          tableName: 'entries',
          rowPks: `{"id":"row-${String(row).padStart(5, '0')}"}`,
          columnName: `col_${col}`,
          hlcTimestamp: `2026-01-01T00:00:00.${String(row * COLUMNS_PER_ROW + col).padStart(6, '0')}Z`,
        })
      }
    }

    await bulkInsertChanges(changes)
    console.log(`Inserted ${changes.length} changes`)

    // Paginate through all data using (timestamp, tableName, rowPks) cursor
    let cursor: string | undefined = undefined
    let lastTableName: string | undefined = undefined
    let lastRowPks: string | undefined = undefined
    let totalRowsFetched = 0
    let pageCount = 0
    const allSeenRows = new Set<string>()
    const MAX_PAGES = 50

    while (pageCount < MAX_PAGES) {
      pageCount++
      const result = await pullChangesWithPagination(cursor, lastTableName, lastRowPks, PAGE_LIMIT)

      console.log(
        `Page ${pageCount}: ${result.rowCount} rows, ${result.columnCount} columns, ` +
          `hasMore=${result.hasMore}, cursor=${result.serverTimestamp}, lastRow=${result.lastTableName}:${result.lastRowPks?.slice(0, 20)}...`
      )

      // Check for duplicate rows (would indicate pagination bug)
      for (const row of result.uniqueRows) {
        if (allSeenRows.has(row)) {
          throw new Error(`Duplicate row detected: ${row} - pagination bug!`)
        }
        allSeenRows.add(row)
      }

      totalRowsFetched += result.rowCount
      cursor = result.serverTimestamp
      lastTableName = result.lastTableName
      lastRowPks = result.lastRowPks

      if (!result.hasMore) {
        break
      }
    }

    console.log(`Pagination complete: ${pageCount} pages, ${totalRowsFetched} total rows`)

    // Verify we got all rows
    expect(allSeenRows.size).toBe(NUM_ROWS)
    expect(pageCount).toBeLessThan(MAX_PAGES)
  }, 60000)

  test('handles rows with multiple columns correctly', async () => {
    // 200 rows, each with 10 columns
    const NUM_ROWS = 200
    const COLUMNS_PER_ROW = 10

    const changes: Array<{
      tableName: string
      rowPks: string
      columnName: string | null
      hlcTimestamp: string
    }> = []

    for (let row = 0; row < NUM_ROWS; row++) {
      for (let col = 0; col < COLUMNS_PER_ROW; col++) {
        changes.push({
          tableName: 'entries',
          rowPks: `{"id":"multicolrow-${row}"}`,
          columnName: `field_${col}`,
          hlcTimestamp: `2026-01-01T00:00:${String(row).padStart(2, '0')}.${String(col).padStart(3, '0')}Z`,
        })
      }
    }

    await bulkInsertChanges(changes)

    // Paginate with limit 10 rows
    let cursor: string | undefined = undefined
    let lastTableName: string | undefined = undefined
    let lastRowPks: string | undefined = undefined
    const seenRows = new Set<string>()
    let pages = 0

    while (pages < 50) {
      pages++
      const result = await pullChangesWithPagination(cursor, lastTableName, lastRowPks, 10)

      for (const row of result.uniqueRows) {
        expect(seenRows.has(row)).toBe(false)
        seenRows.add(row)
      }

      cursor = result.serverTimestamp
      lastTableName = result.lastTableName
      lastRowPks = result.lastRowPks

      if (!result.hasMore) break
    }

    expect(seenRows.size).toBe(NUM_ROWS)
  })

  test('returns all columns for each row', async () => {
    const changes = [
      { tableName: 'entries', rowPks: '{"id":"full-row"}', columnName: 'col1', hlcTimestamp: '2026-01-01T00:00:00.001Z' },
      { tableName: 'entries', rowPks: '{"id":"full-row"}', columnName: 'col2', hlcTimestamp: '2026-01-01T00:00:00.002Z' },
      { tableName: 'entries', rowPks: '{"id":"full-row"}', columnName: 'col3', hlcTimestamp: '2026-01-01T00:00:00.003Z' },
      { tableName: 'entries', rowPks: '{"id":"full-row"}', columnName: 'col4', hlcTimestamp: '2026-01-01T00:00:00.004Z' },
      { tableName: 'entries', rowPks: '{"id":"full-row"}', columnName: 'col5', hlcTimestamp: '2026-01-01T00:00:00.005Z' },
    ]

    await bulkInsertChanges(changes)

    const result = await pullChangesWithPagination(undefined, undefined, undefined, 100)

    expect(result.rowCount).toBe(1)
    expect(result.columnCount).toBe(5)
  })

  test('empty result when no changes exist', async () => {
    const result = await pullChangesWithPagination(undefined, undefined, undefined, 100)

    expect(result.rowCount).toBe(0)
    expect(result.columnCount).toBe(0)
    expect(result.hasMore).toBe(false)
  })

  test('empty result when cursor is after all changes', async () => {
    await bulkInsertChanges([
      { tableName: 'entries', rowPks: '{"id":"old"}', columnName: 'title', hlcTimestamp: '2026-01-01T00:00:00.000Z' },
    ])

    const futureTime = new Date('2099-12-31T23:59:59.999Z')
    const result = await pullChangesWithPagination(futureTime.toISOString(), undefined, undefined, 100)

    expect(result.rowCount).toBe(0)
    expect(result.hasMore).toBe(false)
  })
})
} // end of else block for connectionString check
