/**
 * Pure utility functions for sync operations.
 * No environment dependencies - safe to import in tests.
 */

/**
 * Type for sync change wire format.
 *
 * Every change carries its sender-side transaction HLC. Changes sharing the
 * same `hlcTimestamp` originated in the same local transaction and must be
 * applied together on the receiver; the client guarantees atomic delivery
 * by chunking push requests at HLC boundaries.
 */
export type SyncChange = {
  tableName: string
  rowPks: string
  columnName: string | null
  hlcTimestamp: string
  deviceId?: string
  encryptedValue?: string | null
  nonce?: string | null
}
