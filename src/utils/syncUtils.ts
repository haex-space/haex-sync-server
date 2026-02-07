/**
 * Pure utility functions for sync operations.
 * No environment dependencies - safe to import in tests.
 */

/**
 * Type for sync change validation
 */
export type SyncChange = {
  tableName: string
  rowPks: string
  columnName: string | null
  hlcTimestamp: string
  deviceId?: string
  encryptedValue?: string | null
  nonce?: string | null
  batchId?: string
  batchSeq?: number
  batchTotal?: number
}

/**
 * Batch validation error type
 */
export type BatchValidationError = {
  error: string
  batchId: string
  missingSequences?: number[]
  expected?: number
  received?: number
}

/**
 * Validate batch completeness for sync changes.
 * Returns null if all batches are valid, or an error object if validation fails.
 *
 * Validates:
 * - All sequence numbers from 1 to batchTotal are present
 * - No duplicate sequence numbers within a batch
 */
export function validateBatches(changes: SyncChange[]): BatchValidationError | null {
  const batchMap = new Map<string, SyncChange[]>()

  // Group changes by batchId
  for (const change of changes) {
    if (change.batchId && change.batchSeq && change.batchTotal) {
      if (!batchMap.has(change.batchId)) {
        batchMap.set(change.batchId, [])
      }
      batchMap.get(change.batchId)!.push(change)
    }
  }

  // Validate each batch is complete
  for (const [batchId, batchChanges] of batchMap.entries()) {
    const batchTotal = batchChanges[0]?.batchTotal
    if (!batchTotal) continue

    // Check for duplicate sequence numbers first
    const sequences = new Set(batchChanges.map(c => c.batchSeq))
    if (sequences.size !== batchChanges.length) {
      return {
        error: 'Duplicate sequence numbers in batch',
        batchId,
      }
    }

    // Check we have all sequence numbers from 1 to batchTotal
    const missingSeqs: number[] = []
    for (let i = 1; i <= batchTotal; i++) {
      if (!sequences.has(i)) {
        missingSeqs.push(i)
      }
    }

    if (missingSeqs.length > 0) {
      return {
        error: 'Incomplete batch',
        batchId,
        missingSequences: missingSeqs,
        expected: batchTotal,
        received: batchChanges.length,
      }
    }
  }

  return null
}
