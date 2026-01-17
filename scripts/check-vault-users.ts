/**
 * Check user_ids in a vault
 * Run with: bun run scripts/check-vault-users.ts <vault-id>
 */

import postgres from 'postgres'

const DATABASE_URL = process.env.DATABASE_URL
const vaultId = process.argv[2]

if (!DATABASE_URL) {
  console.error('❌ DATABASE_URL environment variable is not set')
  process.exit(1)
}

if (!vaultId) {
  console.error('❌ Usage: bun run scripts/check-vault-users.ts <vault-id>')
  process.exit(1)
}

async function checkVaultUsersAsync() {
  const db = postgres(DATABASE_URL)

  try {
    // Check user_ids in this vault
    const users = await db`
      SELECT DISTINCT user_id, COUNT(*) as count
      FROM sync_changes
      WHERE vault_id = ${vaultId}
      GROUP BY user_id
    `
    console.log('👤 User IDs in vault sync_changes:')
    console.log(JSON.stringify(users, null, 2))

    // Check vault_keys for this vault
    const vaultKeys = await db`
      SELECT user_id, vault_id
      FROM vault_keys
      WHERE vault_id = ${vaultId}
    `
    console.log('\n🔑 Vault keys owner:')
    console.log(JSON.stringify(vaultKeys, null, 2))

    // Check device_ids in this vault
    const devices = await db`
      SELECT DISTINCT device_id, COUNT(*) as count
      FROM sync_changes
      WHERE vault_id = ${vaultId}
      GROUP BY device_id
      ORDER BY count DESC
    `
    console.log('\n📱 Device IDs in vault:')
    console.log(JSON.stringify(devices, null, 2))

    // Check actual RLS policy expressions
    const partitionName = `sync_changes_${vaultId.replace(/-/g, '_')}`
    const policies = await db`
      SELECT polname, pg_get_expr(polqual, polrelid) as using_expr
      FROM pg_policy
      WHERE polrelid = ${partitionName}::regclass
    `
    console.log('\n📜 RLS policy expressions:')
    console.log(JSON.stringify(policies, null, 2))

  } finally {
    await db.end()
  }
}

checkVaultUsersAsync()
