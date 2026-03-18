import { db } from '../db'
import { tiers } from '../db/schema'
import { sql } from 'drizzle-orm'

/**
 * Parse a storage bytes value from an env variable.
 * Supports numeric strings and suffixes: KB, MB, GB, TB.
 * Returns null if the variable is not set.
 */
function parseStorageBytes(value: string | undefined): string | null {
  if (!value) return null
  const units: Record<string, number> = {
    KB: 1024,
    MB: 1024 ** 2,
    GB: 1024 ** 3,
    TB: 1024 ** 4,
  }
  const match = value.trim().match(/^(\d+(?:\.\d+)?)\s*(KB|MB|GB|TB)?$/i)
  if (!match) return null
  const num = parseFloat(match[1]!)
  const unit = match[2]?.toUpperCase()
  return String(Math.floor(unit ? num * (units[unit] ?? 1) : num))
}

/**
 * Sync tier configuration from environment variables into the database.
 *
 * Each tier is configured via:
 *   TIER_<NAME>_MAX_BYTES=<value>   (e.g. TIER_FREE_MAX_BYTES=100MB)
 *   TIER_<NAME>_MAX_SPACES=<n>      (e.g. TIER_FREE_MAX_SPACES=3)
 *   TIER_<NAME>_DESCRIPTION=<text>
 *
 * At minimum, the FREE tier must be configured via TIER_FREE_MAX_BYTES.
 * If not set, the free tier defaults to unlimited storage (9007199254740991 bytes).
 */
export async function syncTiersFromEnvAsync(): Promise<void> {
  const tierNames = new Set<string>()

  // Discover which tiers are configured via env
  for (const key of Object.keys(process.env)) {
    const match = key.match(/^TIER_([A-Z0-9_]+)_MAX_BYTES$/)
    if (match) tierNames.add(match[1]!.toLowerCase())
  }

  // Always ensure the 'free' tier exists
  if (!tierNames.has('free')) {
    tierNames.add('free')
  }

  for (const name of tierNames) {
    const envPrefix = `TIER_${name.toUpperCase()}`
    const maxBytes = parseStorageBytes(process.env[`${envPrefix}_MAX_BYTES`])
      ?? (name === 'free' ? '9007199254740991' : null) // unlimited for free if not set
    const maxSpaces = parseInt(process.env[`${envPrefix}_MAX_SPACES`] ?? '3')
    const description = process.env[`${envPrefix}_DESCRIPTION`] ?? null

    if (!maxBytes) continue

    await db.insert(tiers)
      .values({ name, maxStorageBytes: maxBytes, maxSpaces, description })
      .onConflictDoUpdate({
        target: tiers.name,
        set: {
          maxStorageBytes: sql`excluded.max_storage_bytes`,
          maxSpaces: sql`excluded.max_spaces`,
          description: sql`excluded.description`,
        },
      })

    console.log(`⚙️  Tier '${name}': ${maxBytes} bytes, ${maxSpaces} spaces`)
  }
}
