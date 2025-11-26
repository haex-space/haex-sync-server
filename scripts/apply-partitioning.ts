/**
 * Apply List Partitioning to sync_changes table
 * This converts the table to be partitioned by vault_id for better performance
 *
 * Run with: bun run scripts/apply-partitioning.ts
 *
 * IMPORTANT: This script should be run AFTER all drizzle migrations
 * It is idempotent - running it multiple times is safe
 */

import { readFileSync } from 'fs'
import postgres from 'postgres'

const DATABASE_URL = process.env.DATABASE_URL

if (!DATABASE_URL) {
  console.error('❌ DATABASE_URL environment variable is not set')
  process.exit(1)
}

async function applyPartitioningAsync() {
  console.log('🔧 Applying List Partitioning to sync_changes table...')
  console.log('   This will create one partition per vault_id for better query performance.')
  console.log('')

  // Read SQL file
  const sql = readFileSync('./drizzle/partitioning.sql', 'utf-8')

  // Connect to database
  const db = postgres(DATABASE_URL)

  try {
    // Execute SQL
    await db.unsafe(sql)
    console.log('')
    console.log('✅ Partitioning applied successfully!')
    console.log('')
    console.log('   New vaults will automatically get their own partition.')
    console.log('   Deleting a vault will automatically drop its partition.')
  } catch (error) {
    console.error('❌ Failed to apply partitioning:', error)
    process.exit(1)
  } finally {
    await db.end()
  }
}

applyPartitioningAsync()
