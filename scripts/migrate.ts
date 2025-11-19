import { drizzle } from 'drizzle-orm/postgres-js'
import { migrate } from 'drizzle-orm/postgres-js/migrator'
import postgres from 'postgres'
import { readFileSync } from 'fs'
import { join } from 'path'

// Get database URL from environment
const connectionString = process.env.DATABASE_URL

if (!connectionString) {
  throw new Error('DATABASE_URL environment variable is not set')
}

console.log('🔄 Connecting to database...')

// Create postgres connection for migrations
const migrationClient = postgres(connectionString, { max: 1 })
const db = drizzle(migrationClient)

try {
  console.log('🚀 Running migrations...')
  await migrate(db, { migrationsFolder: './drizzle/migrations' })
  console.log('✅ Migrations completed successfully')

  // Apply RLS policies (these need to be reapplied after schema changes)
  console.log('🔒 Applying RLS policies...')
  const rlsPoliciesSQL = readFileSync(join(import.meta.dir, '../drizzle/rls-policies.sql'), 'utf-8')
  await migrationClient.unsafe(rlsPoliciesSQL)
  console.log('✅ RLS policies applied successfully')
} catch (error) {
  console.error('❌ Migration failed:', error)
  await migrationClient.end()
  process.exit(1)
}

await migrationClient.end()
console.log('👋 Database connection closed')
process.exit(0)
