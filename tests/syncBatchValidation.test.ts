/**
 * Tests for Sync Push Batch Validation
 *
 * These tests verify the batch validation logic that ensures:
 * - All sequence numbers from 1 to batchTotal are present
 * - No duplicate sequence numbers exist
 * - Batches are validated atomically
 */

import { describe, test, expect } from 'bun:test'
import { validateBatches, type SyncChange } from '../src/utils/syncUtils'

describe('Sync - Batch Validation', () => {
  describe('validateBatches', () => {
    test('returns null for changes without batch metadata', () => {
      const changes: SyncChange[] = [
        { tableName: 'test', rowPks: '1', columnName: 'col', hlcTimestamp: '1', deviceId: 'd1' },
        { tableName: 'test', rowPks: '2', columnName: 'col', hlcTimestamp: '2', deviceId: 'd1' },
      ]

      const result = validateBatches(changes)
      expect(result).toBeNull()
    })

    test('returns null for complete single batch', () => {
      const changes: SyncChange[] = [
        { tableName: 'test', rowPks: '1', columnName: 'col', hlcTimestamp: '1', deviceId: 'd1', batchId: 'b1', batchSeq: 1, batchTotal: 3 },
        { tableName: 'test', rowPks: '2', columnName: 'col', hlcTimestamp: '2', deviceId: 'd1', batchId: 'b1', batchSeq: 2, batchTotal: 3 },
        { tableName: 'test', rowPks: '3', columnName: 'col', hlcTimestamp: '3', deviceId: 'd1', batchId: 'b1', batchSeq: 3, batchTotal: 3 },
      ]

      const result = validateBatches(changes)
      expect(result).toBeNull()
    })

    test('returns null for multiple complete batches', () => {
      const changes: SyncChange[] = [
        { tableName: 'test', rowPks: '1', columnName: 'col', hlcTimestamp: '1', deviceId: 'd1', batchId: 'b1', batchSeq: 1, batchTotal: 2 },
        { tableName: 'test', rowPks: '2', columnName: 'col', hlcTimestamp: '2', deviceId: 'd1', batchId: 'b1', batchSeq: 2, batchTotal: 2 },
        { tableName: 'test', rowPks: '3', columnName: 'col', hlcTimestamp: '3', deviceId: 'd1', batchId: 'b2', batchSeq: 1, batchTotal: 2 },
        { tableName: 'test', rowPks: '4', columnName: 'col', hlcTimestamp: '4', deviceId: 'd1', batchId: 'b2', batchSeq: 2, batchTotal: 2 },
      ]

      const result = validateBatches(changes)
      expect(result).toBeNull()
    })

    test('detects missing sequence numbers', () => {
      const changes: SyncChange[] = [
        { tableName: 'test', rowPks: '1', columnName: 'col', hlcTimestamp: '1', deviceId: 'd1', batchId: 'b1', batchSeq: 1, batchTotal: 3 },
        { tableName: 'test', rowPks: '3', columnName: 'col', hlcTimestamp: '3', deviceId: 'd1', batchId: 'b1', batchSeq: 3, batchTotal: 3 },
        // Missing batchSeq: 2
      ]

      const result = validateBatches(changes)
      expect(result).not.toBeNull()
      expect(result?.error).toBe('Incomplete batch')
      expect(result?.batchId).toBe('b1')
      expect(result?.missingSequences).toContain(2)
    })

    test('detects multiple missing sequence numbers', () => {
      const changes: SyncChange[] = [
        { tableName: 'test', rowPks: '1', columnName: 'col', hlcTimestamp: '1', deviceId: 'd1', batchId: 'b1', batchSeq: 1, batchTotal: 5 },
        { tableName: 'test', rowPks: '3', columnName: 'col', hlcTimestamp: '3', deviceId: 'd1', batchId: 'b1', batchSeq: 3, batchTotal: 5 },
        // Missing 2, 4, 5
      ]

      const result = validateBatches(changes)
      expect(result).not.toBeNull()
      expect(result?.missingSequences).toEqual([2, 4, 5])
      expect(result?.expected).toBe(5)
      expect(result?.received).toBe(2)
    })

    test('detects duplicate sequence numbers', () => {
      const changes: SyncChange[] = [
        { tableName: 'test', rowPks: '1', columnName: 'col', hlcTimestamp: '1', deviceId: 'd1', batchId: 'b1', batchSeq: 1, batchTotal: 2 },
        { tableName: 'test', rowPks: '2', columnName: 'col', hlcTimestamp: '2', deviceId: 'd1', batchId: 'b1', batchSeq: 1, batchTotal: 2 },
        // Duplicate batchSeq: 1
      ]

      const result = validateBatches(changes)
      expect(result).not.toBeNull()
      expect(result?.error).toBe('Duplicate sequence numbers in batch')
      expect(result?.batchId).toBe('b1')
    })

    test('handles mixed batched and non-batched changes', () => {
      const changes: SyncChange[] = [
        // Non-batched change
        { tableName: 'test', rowPks: '0', columnName: 'col', hlcTimestamp: '0', deviceId: 'd1' },
        // Complete batch
        { tableName: 'test', rowPks: '1', columnName: 'col', hlcTimestamp: '1', deviceId: 'd1', batchId: 'b1', batchSeq: 1, batchTotal: 2 },
        { tableName: 'test', rowPks: '2', columnName: 'col', hlcTimestamp: '2', deviceId: 'd1', batchId: 'b1', batchSeq: 2, batchTotal: 2 },
      ]

      const result = validateBatches(changes)
      expect(result).toBeNull()
    })

    test('returns error for first incomplete batch when multiple batches', () => {
      const changes: SyncChange[] = [
        // Incomplete batch b1
        { tableName: 'test', rowPks: '1', columnName: 'col', hlcTimestamp: '1', deviceId: 'd1', batchId: 'b1', batchSeq: 1, batchTotal: 2 },
        // Complete batch b2
        { tableName: 'test', rowPks: '3', columnName: 'col', hlcTimestamp: '3', deviceId: 'd1', batchId: 'b2', batchSeq: 1, batchTotal: 1 },
      ]

      const result = validateBatches(changes)
      expect(result).not.toBeNull()
      expect(result?.batchId).toBe('b1')
    })

    test('handles empty changes array', () => {
      const result = validateBatches([])
      expect(result).toBeNull()
    })

    test('handles single change batch', () => {
      const changes: SyncChange[] = [
        { tableName: 'test', rowPks: '1', columnName: 'col', hlcTimestamp: '1', deviceId: 'd1', batchId: 'b1', batchSeq: 1, batchTotal: 1 },
      ]

      const result = validateBatches(changes)
      expect(result).toBeNull()
    })

    test('validates out-of-order sequence numbers', () => {
      const changes: SyncChange[] = [
        { tableName: 'test', rowPks: '3', columnName: 'col', hlcTimestamp: '3', deviceId: 'd1', batchId: 'b1', batchSeq: 3, batchTotal: 3 },
        { tableName: 'test', rowPks: '1', columnName: 'col', hlcTimestamp: '1', deviceId: 'd1', batchId: 'b1', batchSeq: 1, batchTotal: 3 },
        { tableName: 'test', rowPks: '2', columnName: 'col', hlcTimestamp: '2', deviceId: 'd1', batchId: 'b1', batchSeq: 2, batchTotal: 3 },
      ]

      // Out of order but complete - should pass
      const result = validateBatches(changes)
      expect(result).toBeNull()
    })
  })
})
