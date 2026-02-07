/**
 * Pure utility functions for credential generation.
 * No environment dependencies - safe to import in tests.
 */

import { randomBytes } from 'crypto'

/**
 * Generate a cryptographically secure random string from a character set.
 * Uses crypto.randomBytes() for security-critical credential generation.
 */
export function generateSecureRandomString(length: number, chars: string): string {
  const bytes = randomBytes(length)
  let result = ''
  for (let i = 0; i < length; i++) {
    result += chars.charAt(bytes[i]! % chars.length)
  }
  return result
}

/**
 * Generate a random access key ID (format: HAEX + 16 alphanumeric chars)
 */
export function generateAccessKeyId(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  return 'HAEX' + generateSecureRandomString(16, chars)
}

/**
 * Generate a random secret access key (40 chars, like AWS)
 */
export function generateSecretAccessKey(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  return generateSecureRandomString(40, chars)
}
