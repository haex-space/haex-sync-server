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
    DECLARE
      ref_schema text;
    BEGIN
      -- Get the actual referenced schema using pg_constraint
      SELECT n.nspname INTO ref_schema
      FROM pg_constraint c
      JOIN pg_class cl ON c.confrelid = cl.oid
      JOIN pg_namespace n ON cl.relnamespace = n.oid
      WHERE c.conname = 'user_storage_credentials_user_id_users_id_fk'
      AND c.contype = 'f';

      IF ref_schema IS NOT NULL AND ref_schema != 'auth' THEN
        -- Drop and recreate with correct reference to auth.users
        RAISE NOTICE 'FK references schema %, fixing to auth...', ref_schema;
        ALTER TABLE user_storage_credentials DROP CONSTRAINT user_storage_credentials_user_id_users_id_fk;
        ALTER TABLE user_storage_credentials ADD CONSTRAINT user_storage_credentials_user_id_users_id_fk
          FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE ON UPDATE NO ACTION;
        RAISE NOTICE 'Fixed user_storage_credentials FK to reference auth.users';
      ELSIF ref_schema = 'auth' THEN
        RAISE NOTICE 'FK already correctly references auth.users';
      ELSE
        RAISE NOTICE 'FK constraint not found, nothing to fix';
      END IF;
    END $$;
  `)
  console.log('✅ FK constraints verified')

  // Apply Partitioning BEFORE RLS — sync_changes must exist before enabling RLS on it
  console.log('📊 Applying Partitioning configuration...')
  const partitioningSQL = readFileSync(join(import.meta.dir, '../drizzle/partitioning.sql'), 'utf-8')
  await migrationClient.unsafe(partitioningSQL)
  console.log('✅ Partitioning configuration applied successfully')

  // Apply RLS policies (these need to be reapplied after schema changes)
  console.log('🔒 Applying RLS policies...')
  const rlsPoliciesSQL = readFileSync(join(import.meta.dir, '../drizzle/rls-policies.sql'), 'utf-8')
  await migrationClient.unsafe(rlsPoliciesSQL)
  const rlsSpacesSQL = readFileSync(join(import.meta.dir, '../drizzle/rls-spaces.sql'), 'utf-8')
  await migrationClient.unsafe(rlsSpacesSQL)
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

  // Apply Realtime configuration (adds sync_changes partitions to supabase_realtime publication)
  // This must run AFTER partitioning to ensure all partitions are included
  console.log('📡 Applying Realtime configuration...')
  const realtimeSQL = readFileSync(join(import.meta.dir, '../drizzle/realtime.sql'), 'utf-8')
  await migrationClient.unsafe(realtimeSQL)
  console.log('✅ Realtime configuration applied successfully')

  // Ensure broadcast trigger exists — the partitioning.sql creates it only if
  // realtime.messages table exists. Due to a race condition (Realtime container
  // may not have finished creating the messages table when migrations run), the
  // trigger may have been skipped. Retry with backoff to handle this.
  const hasTrigger = await migrationClient`
    SELECT 1 FROM pg_trigger WHERE tgname = 'broadcast_sync_changes_trigger'
  `
  if (hasTrigger.length === 0) {
    console.log('⏳ Broadcast trigger not found, waiting for realtime.messages table...')
    const partSQL = readFileSync(join(import.meta.dir, '../drizzle/partitioning.sql'), 'utf-8')
    for (let attempt = 1; attempt <= 10; attempt++) {
      const tbl = await migrationClient`
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'realtime' AND c.relname = 'messages'
      `
      if (tbl.length > 0) {
        console.log(`✅ realtime.messages found after ${attempt} attempt(s), re-applying partitioning...`)
        await migrationClient.unsafe(partSQL)
        console.log('✅ Broadcast trigger created')
        break
      }
      if (attempt === 10) {
        console.warn('⚠️ realtime.messages table not available after 10 attempts — broadcast will not work')
      } else {
        await new Promise(r => setTimeout(r, 2000))
      }
    }
  } else {
    console.log('✅ Broadcast trigger already exists')
  }
} catch (error) {
  console.error('❌ Migration failed:', error)
  await migrationClient.end()
  process.exit(1)
}

await migrationClient.end()
console.log('👋 Database connection closed')
process.exit(0)
