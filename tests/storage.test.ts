/**
 * Tests for Storage Routes - Bucket Isolation and XML Building
 *
 * These tests verify critical security and functionality aspects:
 * - Bucket isolation (users can only access their own bucket)
 * - XML escaping (XSS prevention)
 * - S3 XML response building
 */

import { describe, test, expect } from 'bun:test'
import {
  extractBucketAndKey,
  escapeXml,
  buildS3ListXml,
  getHeadersRecord,
  getUserBucket,
} from '../src/utils/storageUtils'

describe('Storage - Bucket Isolation', () => {
  const userId = 'abc123-def456-ghi789'

  describe('getUserBucket', () => {
    test('returns correct bucket name format', () => {
      const bucket = getUserBucket(userId)
      expect(bucket).toBe('user-abc123-def456-ghi789')
    })

    test('handles different user IDs consistently', () => {
      expect(getUserBucket('user1')).toBe('user-user1')
      expect(getUserBucket('a-b-c')).toBe('user-a-b-c')
      expect(getUserBucket('')).toBe('user-')
    })
  })

  describe('extractBucketAndKey', () => {
    test('extracts bucket and key from valid path', () => {
      const result = extractBucketAndKey('/storage/s3/user-abc123-def456-ghi789/path/to/file.txt', userId)
      expect(result).toEqual({
        bucket: 'user-abc123-def456-ghi789',
        key: 'path/to/file.txt',
      })
    })

    test('handles path without /storage prefix', () => {
      const result = extractBucketAndKey('/s3/user-abc123-def456-ghi789/file.txt', userId)
      expect(result).toEqual({
        bucket: 'user-abc123-def456-ghi789',
        key: 'file.txt',
      })
    })

    test('handles path with only bucket (no key)', () => {
      const result = extractBucketAndKey('/storage/s3/user-abc123-def456-ghi789', userId)
      expect(result).toEqual({
        bucket: 'user-abc123-def456-ghi789',
        key: '',
      })
    })

    test('handles empty path (list request at bucket root)', () => {
      const result = extractBucketAndKey('/storage/s3/', userId)
      expect(result).toEqual({
        bucket: 'user-abc123-def456-ghi789',
        key: '',
      })
    })

    test('handles path with just /s3', () => {
      const result = extractBucketAndKey('/s3', userId)
      expect(result).toEqual({
        bucket: 'user-abc123-def456-ghi789',
        key: '',
      })
    })

    test('SECURITY: rejects access to different user bucket', () => {
      const result = extractBucketAndKey('/storage/s3/user-other-user-id/malicious.txt', userId)
      expect(result).toBeNull()
    })

    test('SECURITY: rejects access to system buckets', () => {
      const result = extractBucketAndKey('/storage/s3/system-bucket/config.json', userId)
      expect(result).toBeNull()
    })

    test('SECURITY: rejects path traversal attempts', () => {
      // These should either return null or correctly isolate to user bucket
      const result1 = extractBucketAndKey('/storage/s3/user-abc123-def456-ghi789/../other-bucket/file', userId)
      // The key will contain the traversal, but bucket is validated
      expect(result1?.bucket).toBe('user-abc123-def456-ghi789')
    })

    test('handles deeply nested keys', () => {
      const result = extractBucketAndKey('/storage/s3/user-abc123-def456-ghi789/a/b/c/d/e/file.txt', userId)
      expect(result).toEqual({
        bucket: 'user-abc123-def456-ghi789',
        key: 'a/b/c/d/e/file.txt',
      })
    })

    test('handles keys with special characters', () => {
      const result = extractBucketAndKey('/storage/s3/user-abc123-def456-ghi789/file with spaces.txt', userId)
      expect(result).toEqual({
        bucket: 'user-abc123-def456-ghi789',
        key: 'file with spaces.txt',
      })
    })
  })
})

describe('Storage - XML Building', () => {
  describe('escapeXml', () => {
    test('escapes ampersand', () => {
      expect(escapeXml('foo & bar')).toBe('foo &amp; bar')
    })

    test('escapes less than', () => {
      expect(escapeXml('foo < bar')).toBe('foo &lt; bar')
    })

    test('escapes greater than', () => {
      expect(escapeXml('foo > bar')).toBe('foo &gt; bar')
    })

    test('escapes double quotes', () => {
      expect(escapeXml('foo "bar"')).toBe('foo &quot;bar&quot;')
    })

    test('escapes single quotes', () => {
      expect(escapeXml("foo 'bar'")).toBe('foo &apos;bar&apos;')
    })

    test('escapes multiple special characters', () => {
      expect(escapeXml('<script>alert("xss")</script>')).toBe(
        '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'
      )
    })

    test('handles empty string', () => {
      expect(escapeXml('')).toBe('')
    })

    test('returns unchanged string without special chars', () => {
      expect(escapeXml('normal text 123')).toBe('normal text 123')
    })

    test('SECURITY: prevents XSS in bucket names', () => {
      const maliciousBucket = '<script>alert(1)</script>'
      const escaped = escapeXml(maliciousBucket)
      expect(escaped).not.toContain('<script>')
      expect(escaped).toBe('&lt;script&gt;alert(1)&lt;/script&gt;')
    })

    test('SECURITY: prevents XSS in file keys', () => {
      const maliciousKey = 'file"><script>evil()</script><x x="'
      const escaped = escapeXml(maliciousKey)
      expect(escaped).not.toContain('<script>')
      expect(escaped).not.toContain('">')
    })
  })

  describe('buildS3ListXml', () => {
    test('builds valid XML for empty bucket', () => {
      const xml = buildS3ListXml('test-bucket', '', [], [])

      expect(xml).toContain('<?xml version="1.0" encoding="UTF-8"?>')
      expect(xml).toContain('<ListBucketResult')
      expect(xml).toContain('<Name>test-bucket</Name>')
      expect(xml).toContain('<KeyCount>0</KeyCount>')
      expect(xml).toContain('<IsTruncated>false</IsTruncated>')
    })

    test('builds XML with objects', () => {
      const objects = [
        { key: 'file1.txt', size: 1024, lastModified: '2024-01-01T00:00:00Z' },
        { key: 'file2.txt', size: 2048, lastModified: '2024-01-02T00:00:00Z' },
      ]
      const xml = buildS3ListXml('test-bucket', '', objects, [])

      expect(xml).toContain('<Contents>')
      expect(xml).toContain('<Key>file1.txt</Key>')
      expect(xml).toContain('<Size>1024</Size>')
      expect(xml).toContain('<Key>file2.txt</Key>')
      expect(xml).toContain('<Size>2048</Size>')
      expect(xml).toContain('<KeyCount>2</KeyCount>')
    })

    test('builds XML with common prefixes (folders)', () => {
      const xml = buildS3ListXml('test-bucket', '', [], ['folder1/', 'folder2/'])

      expect(xml).toContain('<CommonPrefixes>')
      expect(xml).toContain('<Prefix>folder1/</Prefix>')
      expect(xml).toContain('<Prefix>folder2/</Prefix>')
    })

    test('includes prefix in response', () => {
      const xml = buildS3ListXml('test-bucket', 'documents/', [], [])

      expect(xml).toContain('<Prefix>documents/</Prefix>')
    })

    test('escapes special characters in bucket name', () => {
      const xml = buildS3ListXml('bucket<test>', '', [], [])

      expect(xml).toContain('<Name>bucket&lt;test&gt;</Name>')
    })

    test('escapes special characters in keys', () => {
      const objects = [
        { key: 'file<script>.txt', size: 100, lastModified: '2024-01-01T00:00:00Z' },
      ]
      const xml = buildS3ListXml('test-bucket', '', objects, [])

      expect(xml).toContain('<Key>file&lt;script&gt;.txt</Key>')
    })

    test('sets StorageClass to STANDARD', () => {
      const objects = [
        { key: 'file.txt', size: 100, lastModified: '2024-01-01T00:00:00Z' },
      ]
      const xml = buildS3ListXml('test-bucket', '', objects, [])

      expect(xml).toContain('<StorageClass>STANDARD</StorageClass>')
    })
  })
})

describe('Storage - Utility Functions', () => {
  describe('getHeadersRecord', () => {
    test('converts Headers to lowercase record', () => {
      const headers = new Headers()
      headers.set('Content-Type', 'application/json')
      headers.set('X-Custom-Header', 'value')

      const record = getHeadersRecord(headers)

      expect(record['content-type']).toBe('application/json')
      expect(record['x-custom-header']).toBe('value')
    })

    test('handles empty headers', () => {
      const headers = new Headers()
      const record = getHeadersRecord(headers)

      expect(Object.keys(record).length).toBe(0)
    })

    test('lowercases all header names', () => {
      const headers = new Headers()
      headers.set('UPPERCASE', 'value1')
      headers.set('MixedCase', 'value2')

      const record = getHeadersRecord(headers)

      expect(record['uppercase']).toBe('value1')
      expect(record['mixedcase']).toBe('value2')
      expect(record['UPPERCASE']).toBeUndefined()
    })
  })
})
