/**
 * Apply Realtime configuration to Supabase database
 * Run with: bun run scripts/apply-realtime.ts
 */

import { readFileSync } from 'fs'
import postgres from 'postgres'

const DATABASE_URL = process.env.DATABASE_URL

if (!DATABASE_URL) {
  console.error('❌ DATABASE_URL environment variable is not set')
  process.exit(1)
}

// Validated value
const dbUrl: string = DATABASE_URL

async function applyRealtimeAsync() {
  console.log('📡 Applying Realtime configuration to Supabase...')

  // Read SQL file
  const sql = readFileSync('./drizzle/realtime.sql', 'utf-8')

  // Connect to database
  const db = postgres(dbUrl)

  try {
    // Execute SQL
    await db.unsafe(sql)
    console.log('✅ Realtime configuration applied successfully!')
  } catch (error) {
    console.error('❌ Failed to apply Realtime configuration:', error)
    process.exit(1)
  } finally {
    await db.end()
  }
}

applyRealtimeAsync()
