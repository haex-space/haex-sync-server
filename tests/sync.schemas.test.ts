import { describe, test, expect } from 'bun:test'
import { pushChangesSchema, pullChangesSchema, pullColumnsSchema } from '../src/routes/sync.schemas'

// Valid v4 UUID (version=4 at digit 13, variant=8/9/a/b at digit 17)
const VALID_UUID = '11111111-1111-4111-8111-111111111111'

describe('sync schemas — UUID validation for spaceId', () => {
  // ── pushChangesSchema ───────────────────────────────────────────────

  test('pushChangesSchema rejects non-UUID spaceId', () => {
    const result = pushChangesSchema.safeParse({
      spaceId: 'not-a-uuid',
      changes: [],
    })
    expect(result.success).toBe(false)
    if (!result.success) {
      expect(result.error.issues.some(i => i.path[0] === 'spaceId')).toBe(true)
    }
  })

  test('pushChangesSchema rejects path-traversal attempt as spaceId', () => {
    const result = pushChangesSchema.safeParse({
      spaceId: '../../../etc/passwd',
      changes: [],
    })
    expect(result.success).toBe(false)
  })

  test('pushChangesSchema rejects SQL-injection attempt as spaceId', () => {
    const result = pushChangesSchema.safeParse({
      spaceId: "'; DROP TABLE spaces; --",
      changes: [],
    })
    expect(result.success).toBe(false)
  })

  test('pushChangesSchema accepts valid UUID spaceId', () => {
    const result = pushChangesSchema.safeParse({
      spaceId: VALID_UUID,
      changes: [],
    })
    expect(result.success).toBe(true)
  })

  // ── pullChangesSchema ───────────────────────────────────────────────

  test('pullChangesSchema rejects non-UUID spaceId', () => {
    const result = pullChangesSchema.safeParse({ spaceId: 'abc' })
    expect(result.success).toBe(false)
  })

  test('pullChangesSchema rejects empty spaceId', () => {
    const result = pullChangesSchema.safeParse({ spaceId: '' })
    expect(result.success).toBe(false)
  })

  test('pullChangesSchema accepts valid UUID spaceId', () => {
    const result = pullChangesSchema.safeParse({ spaceId: VALID_UUID })
    expect(result.success).toBe(true)
  })

  // ── pullColumnsSchema ───────────────────────────────────────────────

  test('pullColumnsSchema rejects non-UUID spaceId', () => {
    const result = pullColumnsSchema.safeParse({
      spaceId: 'abc',
      columns: [{ tableName: 't', columnName: 'c' }],
    })
    expect(result.success).toBe(false)
  })

  test('pullColumnsSchema accepts valid UUID spaceId', () => {
    const result = pullColumnsSchema.safeParse({
      spaceId: VALID_UUID,
      columns: [{ tableName: 't', columnName: 'c' }],
    })
    expect(result.success).toBe(true)
  })
})
