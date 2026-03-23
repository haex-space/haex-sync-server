import { z } from 'zod'

export class SpacePushValidationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'SpacePushValidationError'
  }
}

// Validation schemas
export const vaultKeySchema = z.object({
  spaceId: z.string().uuid(),
  encryptedVaultKey: z.string(),
  encryptedVaultName: z.string(),
  vaultKeySalt: z.string(), // Salt for vault password -> vault key encryption
  ephemeralPublicKey: z.string(), // ECDH ephemeral public key for vault name decryption
  vaultKeyNonce: z.string(),
  vaultNameNonce: z.string(),
})

export const updateVaultNameSchema = z.object({
  encryptedVaultName: z.string(),
  vaultNameNonce: z.string(),
  ephemeralPublicKey: z.string(),
})

export const pushChangeSchema = z.object({
  tableName: z.string(),
  rowPks: z.string(), // JSON string
  columnName: z.string().nullable(),
  hlcTimestamp: z.string(),
  deviceId: z.string().optional(),
  encryptedValue: z.string().nullable(),
  nonce: z.string().nullable(),
  batchId: z.string().optional(), // UUID for grouping related changes
  batchSeq: z.number().int().positive().optional(), // 1-based sequence within batch
  batchTotal: z.number().int().positive().optional(), // Total changes in this batch
  // Space-specific fields (required for space pushes, ignored for personal vaults)
  signature: z.string().optional(), // ECDSA P-256 signature (Base64)
  signedBy: z.string().optional(), // Public key of signer (Base64 SPKI)
  collaborative: z.boolean().optional(), // Can others modify this record?
})

export type PushChange = z.infer<typeof pushChangeSchema> & {
  recordOwner?: string | null // Set by server during validation
}

export const pushChangesSchema = z.object({
  spaceId: z.string(),
  changes: z.array(pushChangeSchema),
})

export const pullChangesSchema = z.object({
  spaceId: z.string(),
  excludeDeviceId: z.string().optional(), // Exclude changes from this device ID
  afterUpdatedAt: z.string().optional(), // Pull changes after this server timestamp (ISO 8601)
  afterTableName: z.string().optional(), // Secondary cursor for stable pagination (table name)
  afterRowPks: z.string().optional(), // Secondary cursor for stable pagination (row primary keys)
  limit: z.coerce.number().int().min(1).max(1000).default(100), // Coerce string to number for query params
})

export const pullColumnsSchema = z.object({
  spaceId: z.string(),
  columns: z.array(
    z.object({
      tableName: z.string(),
      columnName: z.string(),
    })
  ).min(1).max(100), // Limit to 100 columns per request
  limit: z.number().int().min(1).max(10000).default(1000), // Higher limit since we're fetching specific columns
  afterRowPks: z.string().optional(), // Cursor for pagination (rowPks of last item)
  afterTableName: z.string().optional(), // Cursor for pagination (tableName of last item)
})
