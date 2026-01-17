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

  // Apply Storage Bucket configuration (if file exists)
  const storageBucketPath = join(import.meta.dir, '../drizzle/storage-bucket.sql')
  try {
    const storageBucketSQL = readFileSync(storageBucketPath, 'utf-8')
    console.log('📦 Applying Storage Bucket configuration...')
    await migrationClient.unsafe(storageBucketSQL)
    console.log('✅ Storage Bucket configuration applied successfully')
  } catch (e) {
    // File might not exist, that's okay
    if ((e as NodeJS.ErrnoException).code !== 'ENOENT') {
      throw e
    }
  }
} catch (error) {
  console.error('❌ Migration failed:', error)
  await migrationClient.end()
  process.exit(1)
}

await migrationClient.end()
console.log('👋 Database connection closed')
process.exit(0)
