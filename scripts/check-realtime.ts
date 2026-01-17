/**
 * Check Realtime configuration for a partition
 * Run with: bun run scripts/check-realtime.ts <vault-id>
 */

import postgres from 'postgres'

const DATABASE_URL = process.env.DATABASE_URL
const vaultId = process.argv[2]

if (!DATABASE_URL) {
  console.error('❌ DATABASE_URL environment variable is not set')
  process.exit(1)
}

if (!vaultId) {
  console.error('❌ Usage: bun run scripts/check-realtime.ts <vault-id>')
  process.exit(1)
}

const partitionName = `sync_changes_${vaultId.replace(/-/g, '_')}`

async function checkRealtimeAsync() {
  const db = postgres(DATABASE_URL)

  try {
    // Check RLS policies on the partition
    const policies = await db`
      SELECT polname, polcmd, polroles::regrole[], polqual::text, polwithcheck::text
      FROM pg_policy
      WHERE polrelid = ${partitionName}::regclass
    `
    console.log('📋 RLS Policies on partition:')
    console.log(JSON.stringify(policies, null, 2))

    // Check if RLS is enabled
    const rlsEnabled = await db`
      SELECT relname, relrowsecurity, relforcerowsecurity
      FROM pg_class
      WHERE relname = ${partitionName}
    `
    console.log('\n🔒 RLS enabled:')
    console.log(JSON.stringify(rlsEnabled, null, 2))

    // Check REPLICA IDENTITY
    const replicaIdentity = await db`
      SELECT relname, relreplident
      FROM pg_class
      WHERE relname = ${partitionName}
    `
    console.log('\n📡 Replica Identity (f=full, d=default, n=nothing):')
    console.log(JSON.stringify(replicaIdentity, null, 2))

    // Check if partition is in publication
    const inPublication = await db`
      SELECT * FROM pg_publication_tables
      WHERE pubname = 'supabase_realtime'
      AND tablename = ${partitionName}
    `
    console.log('\n📢 In supabase_realtime publication:')
    console.log(inPublication.length > 0 ? '✅ Yes' : '❌ No')
    if (inPublication.length > 0) {
      console.log(JSON.stringify(inPublication, null, 2))
    }

  } finally {
    await db.end()
  }
}

checkRealtimeAsync()
