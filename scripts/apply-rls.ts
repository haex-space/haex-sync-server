/**
 * Apply RLS policies to Supabase database
 * Run with: bun run scripts/apply-rls.ts
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

async function applyRlsPoliciesAsync() {
  console.log('🔒 Applying RLS policies to Supabase...')

  // Read SQL files
  const sql = [
    readFileSync('./drizzle/rls-policies.sql', 'utf-8'),
    readFileSync('./drizzle/rls-spaces.sql', 'utf-8'),
  ].join('\n')

  // Connect to database
  const db = postgres(dbUrl)

  try {
    // Execute SQL
    await db.unsafe(sql)
    console.log('✅ RLS policies applied successfully!')
  } catch (error) {
    console.error('❌ Failed to apply RLS policies:', error)
    process.exit(1)
  } finally {
    await db.end()
  }
}

applyRlsPoliciesAsync()
