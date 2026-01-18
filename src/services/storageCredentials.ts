/**
 * Storage Credentials Service
 *
 * Manages S3-compatible credentials for users.
 * Credentials are encrypted at rest using pgcrypto's pgp_sym_encrypt.
 */

import { db } from '../db'
import { userStorageCredentials } from '../db/schema'
import { eq, sql } from 'drizzle-orm'

const STORAGE_ENCRYPTION_KEY = process.env.STORAGE_ENCRYPTION_KEY

if (!STORAGE_ENCRYPTION_KEY) {
  console.warn('Warning: STORAGE_ENCRYPTION_KEY not set. Storage credentials will not work.')
}

/**
 * Generate a random access key ID (format: HAEX + 16 alphanumeric chars)
 */
function generateAccessKeyId(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  let result = 'HAEX'
  for (let i = 0; i < 16; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length))
  }
  return result
}

/**
 * Generate a random secret access key (40 chars, like AWS)
 */
function generateSecretAccessKey(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  let result = ''
  for (let i = 0; i < 40; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length))
  }
  return result
}

export interface StorageCredentials {
  accessKeyId: string
  secretAccessKey: string
}

/**
 * Get or create storage credentials for a user.
 *
 * If credentials exist, returns them (decrypting the secret).
 * If not, creates new credentials and returns them.
 */
export async function getOrCreateStorageCredentials(userId: string): Promise<StorageCredentials> {
  if (!STORAGE_ENCRYPTION_KEY) {
    throw new Error('STORAGE_ENCRYPTION_KEY not configured')
  }

  // Try to get existing credentials with decrypted secret
  const existing = await db
    .select({
      accessKeyId: userStorageCredentials.accessKeyId,
      secretAccessKey: sql<string>`pgp_sym_decrypt(${userStorageCredentials.encryptedSecretKey}::bytea, ${STORAGE_ENCRYPTION_KEY})`,
    })
    .from(userStorageCredentials)
    .where(eq(userStorageCredentials.userId, userId))
    .limit(1)

  if (existing.length > 0 && existing[0]) {
    return {
      accessKeyId: existing[0].accessKeyId,
      secretAccessKey: existing[0].secretAccessKey,
    }
  }

  // Generate new credentials
  const accessKeyId = generateAccessKeyId()
  const secretAccessKey = generateSecretAccessKey()

  // Insert with encrypted secret using sql template for pgp_sym_encrypt
  await db
    .insert(userStorageCredentials)
    .values({
      userId,
      accessKeyId,
      // Use sql to call pgp_sym_encrypt
      encryptedSecretKey: sql`pgp_sym_encrypt(${secretAccessKey}, ${STORAGE_ENCRYPTION_KEY})`,
    } as any) // Type assertion needed because encryptedSecretKey expects string but we pass SQL

  return { accessKeyId, secretAccessKey }
}

/**
 * Get credentials by access key ID (for signature verification).
 * Returns the user_id and decrypted secret.
 */
export async function getCredentialsByAccessKeyId(accessKeyId: string): Promise<{
  userId: string
  secretAccessKey: string
} | null> {
  if (!STORAGE_ENCRYPTION_KEY) {
    throw new Error('STORAGE_ENCRYPTION_KEY not configured')
  }

  const result = await db
    .select({
      userId: userStorageCredentials.userId,
      secretAccessKey: sql<string>`pgp_sym_decrypt(${userStorageCredentials.encryptedSecretKey}::bytea, ${STORAGE_ENCRYPTION_KEY})`,
    })
    .from(userStorageCredentials)
    .where(eq(userStorageCredentials.accessKeyId, accessKeyId))
    .limit(1)

  const first = result[0]
  if (!first) {
    return null
  }

  return {
    userId: first.userId,
    secretAccessKey: first.secretAccessKey,
  }
}

/**
 * Regenerate credentials for a user (e.g., if compromised).
 * Deletes existing credentials and creates new ones.
 */
export async function regenerateStorageCredentials(userId: string): Promise<StorageCredentials> {
  if (!STORAGE_ENCRYPTION_KEY) {
    throw new Error('STORAGE_ENCRYPTION_KEY not configured')
  }

  // Delete existing
  await db
    .delete(userStorageCredentials)
    .where(eq(userStorageCredentials.userId, userId))

  // Create new
  return getOrCreateStorageCredentials(userId)
}
