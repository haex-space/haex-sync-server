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

  // Fix FK constraints that may have been created incorrectly by db:push
  // This is idempotent and safe to run multiple times
  console.log('🔧 Ensuring FK constraints reference auth.users...')
  await migrationClient.unsafe(`
    DO $$
    BEGIN
      -- Check if the FK exists and points to public.users (wrong) instead of auth.users
      -- The constraint may exist but reference the wrong table due to db:push
      IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'user_storage_credentials_user_id_users_id_fk'
        AND table_name = 'user_storage_credentials'
      ) THEN
        -- Check if it references the correct schema
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.constraint_column_usage
          WHERE constraint_name = 'user_storage_credentials_user_id_users_id_fk'
          AND table_schema = 'auth'
          AND table_name = 'users'
        ) THEN
          -- Drop and recreate with correct reference
          ALTER TABLE user_storage_credentials DROP CONSTRAINT user_storage_credentials_user_id_users_id_fk;
          ALTER TABLE user_storage_credentials ADD CONSTRAINT user_storage_credentials_user_id_users_id_fk
            FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE ON UPDATE NO ACTION;
          RAISE NOTICE 'Fixed user_storage_credentials FK to reference auth.users';
        END IF;
      END IF;
    END $$;
  `)
  console.log('✅ FK constraints verified')

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
