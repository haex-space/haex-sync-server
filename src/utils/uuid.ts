const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/**
 * Loose UUID check (any hex UUID with the standard 8-4-4-4-12 shape).
 *
 * Kept permissive rather than strict-v4 so user-supplied path params that
 * come from older clients (or non-Postgres UUID generators) still validate,
 * while malformed / injection payloads are reliably rejected.
 */
export function isValidUuid(id: string): boolean {
  return uuidRegex.test(id)
}
