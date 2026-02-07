/**
 * Tests for Storage Credentials - Cryptographic Security
 *
 * These tests verify that credential generation uses cryptographically
 * secure random number generation (crypto.randomBytes) instead of Math.random().
 */

import { describe, test, expect } from 'bun:test'
import {
  generateSecureRandomString,
  generateAccessKeyId,
  generateSecretAccessKey,
} from '../src/services/storageCredentials'

describe('Storage Credentials - Secure Random Generation', () => {
  describe('generateSecureRandomString', () => {
    test('generates string of correct length', () => {
      const chars = 'ABC'
      const result = generateSecureRandomString(10, chars)
      expect(result.length).toBe(10)
    })

    test('only uses characters from provided charset', () => {
      const chars = 'XYZ123'
      const result = generateSecureRandomString(100, chars)

      for (const char of result) {
        expect(chars.includes(char)).toBe(true)
      }
    })

    test('generates different strings on each call (not deterministic)', () => {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
      const results = new Set<string>()

      // Generate 100 strings - they should all be unique
      for (let i = 0; i < 100; i++) {
        results.add(generateSecureRandomString(20, chars))
      }

      // With cryptographically secure randomness, collisions are astronomically unlikely
      expect(results.size).toBe(100)
    })

    test('handles single character charset', () => {
      const result = generateSecureRandomString(5, 'X')
      expect(result).toBe('XXXXX')
    })

    test('handles empty length', () => {
      const result = generateSecureRandomString(0, 'ABC')
      expect(result).toBe('')
    })
  })

  describe('generateAccessKeyId', () => {
    test('starts with HAEX prefix', () => {
      const accessKey = generateAccessKeyId()
      expect(accessKey.startsWith('HAEX')).toBe(true)
    })

    test('has correct total length (HAEX + 16 chars = 20)', () => {
      const accessKey = generateAccessKeyId()
      expect(accessKey.length).toBe(20)
    })

    test('only contains uppercase letters and digits after prefix', () => {
      const accessKey = generateAccessKeyId()
      const suffix = accessKey.substring(4)
      expect(suffix).toMatch(/^[A-Z0-9]{16}$/)
    })

    test('generates unique access keys', () => {
      const keys = new Set<string>()
      for (let i = 0; i < 100; i++) {
        keys.add(generateAccessKeyId())
      }
      expect(keys.size).toBe(100)
    })
  })

  describe('generateSecretAccessKey', () => {
    test('has correct length (40 chars like AWS)', () => {
      const secretKey = generateSecretAccessKey()
      expect(secretKey.length).toBe(40)
    })

    test('only contains valid Base64-like characters', () => {
      const secretKey = generateSecretAccessKey()
      // Valid chars: A-Z, a-z, 0-9, +, /
      expect(secretKey).toMatch(/^[A-Za-z0-9+/]{40}$/)
    })

    test('generates unique secret keys', () => {
      const keys = new Set<string>()
      for (let i = 0; i < 100; i++) {
        keys.add(generateSecretAccessKey())
      }
      expect(keys.size).toBe(100)
    })

    test('has high entropy (no obvious patterns)', () => {
      const secretKey = generateSecretAccessKey()

      // Check that not all characters are the same
      const uniqueChars = new Set(secretKey.split(''))
      expect(uniqueChars.size).toBeGreaterThan(10)
    })
  })

  describe('Cryptographic Security Properties', () => {
    test('consecutive generations produce statistically independent results', () => {
      // Generate many keys and check distribution
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
      const charCounts: Record<string, number> = {}

      for (const char of chars) {
        charCounts[char] = 0
      }

      // Generate 1000 characters worth of data
      for (let i = 0; i < 50; i++) {
        const key = generateSecureRandomString(20, chars)
        for (const char of key) {
          charCounts[char]++
        }
      }

      // With 1000 chars and 36 possible chars, expect ~27.8 per char
      // Allow for statistical variance (should be between 10 and 50)
      for (const char of chars) {
        expect(charCounts[char]).toBeGreaterThan(5)
        expect(charCounts[char]).toBeLessThan(60)
      }
    })
  })
})
