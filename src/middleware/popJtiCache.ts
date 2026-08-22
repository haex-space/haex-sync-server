import { createJtiTtlCache, type JtiCache } from '@haex-space/ucan'

/**
 * Server-wide singleton JTI cache for X-UCAN-PoP replay defence.
 *
 * Each successfully verified proof's `jti` is inserted with its own `payload.exp`
 * as the entry expiration, so retention matches the accepted proof's own
 * validity window. A background sweep runs every 30 s; lazy eviction on `has()`
 * catches expired entries between sweeps.
 *
 * Not shared across processes — multi-instance deploys accept the per-instance
 * replay window (at most one PoP lifetime of duplicates against a given
 * instance). Introducing a shared store is a deliberate scale decision, not
 * an oversight.
 */
let cache: JtiCache | null = null

export function getPopJtiCache(): JtiCache {
  if (!cache) {
    cache = createJtiTtlCache({ sweepIntervalMs: 30_000 })
  }
  return cache
}

/** Test hook — releases the sweep interval and drops the cached singleton. */
export function destroyPopJtiCache(): void {
  cache?.destroy()
  cache = null
}
