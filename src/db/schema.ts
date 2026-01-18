import {
  pgTable,
  pgSchema,
  text,
  timestamp,
  uuid,
  index,
  uniqueIndex,
} from "drizzle-orm/pg-core";

// Define Supabase auth schema
const authSchema = pgSchema("auth");

// Reference to auth.users table from Supabase
// We only define the columns we need for foreign key references
export const authUsers = authSchema.table("users", {
  id: uuid("id").primaryKey(),
});

/**
 * Vault Keys Table
 * Stores encrypted vault keys for each user
 * The vault_key is encrypted with the user's password-derived key (Hybrid-Ansatz)
 * References auth.users from Supabase Auth
 */
export const vaultKeys = pgTable(
  "vault_keys",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: uuid("user_id")
      .notNull()
      .references(() => authUsers.id, { onDelete: "cascade" }),
    vaultId: text("vault_id").notNull(),
    encryptedVaultKey: text("encrypted_vault_key").notNull(), // Base64 of AES-GCM encrypted key
    encryptedVaultName: text("encrypted_vault_name").notNull(), // Base64 of AES-GCM encrypted vault name
    vaultKeySalt: text("vault_key_salt").notNull(), // For PBKDF2 key derivation (vault password -> vault key encryption)
    vaultNameSalt: text("vault_name_salt").notNull(), // For PBKDF2 key derivation (server password -> vault name encryption)
    vaultKeyNonce: text("vault_key_nonce").notNull(), // For AES-GCM encryption of vault key
    vaultNameNonce: text("vault_name_nonce").notNull(), // For AES-GCM encryption of vault name
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("vault_keys_user_vault_idx").on(table.userId, table.vaultId),
    index("vault_keys_user_idx").on(table.userId),
  ]
);

/**
 * Sync Changes Table
 * Stores CRDT changes with unencrypted metadata for efficient deduplication
 *
 * Unencrypted (for sync efficiency):
 * - tableName, rowPks, columnName: Required for server-side deduplication
 * - hlcTimestamp: Required for conflict resolution (Last-Write-Wins)
 * - deviceId: For filtering own changes on pull
 *
 * Encrypted:
 * - encryptedValue: The actual column value (only sensitive data is encrypted)
 *
 * Privacy note: Metadata reveals table structure and change patterns, but not actual data.
 * This is an acceptable trade-off for efficient CRDT sync. Server can be self-hosted.
 *
 * Uses composite unique index (vaultId, tableName, rowPks, columnName) to store only latest value per cell.
 * ON CONFLICT DO UPDATE ensures updates when HLC is newer (Last-Write-Wins CRDT semantics).
 * References auth.users from Supabase Auth
 */
export const syncChanges = pgTable(
  "sync_changes",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: uuid("user_id")
      .notNull()
      .references(() => authUsers.id, { onDelete: "cascade" }),
    vaultId: text("vault_id").notNull(),

    // Unencrypted CRDT metadata (required for server-side deduplication)
    tableName: text("table_name").notNull(),
    rowPks: text("row_pks").notNull(), // JSON string of primary key(s), e.g. '{"id": "uuid-here"}'
    columnName: text("column_name"), // Column name for column-level CRDT
    hlcTimestamp: text("hlc_timestamp").notNull(), // Hybrid Logical Clock timestamp
    deviceId: text("device_id"), // Device ID that created this change

    // Encrypted payload (only the actual value is encrypted)
    encryptedValue: text("encrypted_value"), // NULL for DELETE operations
    nonce: text("nonce"), // IV for AES-GCM, NULL for DELETE

    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    // Composite unique index to ensure only one entry per (vault, table, row, column)
    uniqueIndex("sync_changes_unique_cell").on(
      table.vaultId,
      table.tableName,
      table.rowPks,
      table.columnName
    ),
    index("sync_changes_user_vault_idx").on(table.userId, table.vaultId),
    index("sync_changes_hlc_idx").on(table.hlcTimestamp),
    index("sync_changes_updated_idx").on(table.updatedAt),
    index("sync_changes_device_idx").on(table.deviceId),
  ]
);

// Type exports for TypeScript
export type VaultKey = typeof vaultKeys.$inferSelect;
export type NewVaultKey = typeof vaultKeys.$inferInsert;

export type SyncChange = typeof syncChanges.$inferSelect;
export type NewSyncChange = typeof syncChanges.$inferInsert;

// Legacy type aliases for backward compatibility
export type SyncLog = SyncChange;
export type NewSyncLog = NewSyncChange;

// ============================================
// S3 STORAGE CREDENTIALS
// ============================================

/**
 * User Storage Credentials Table
 * Stores S3-compatible credentials for each user
 *
 * These credentials allow users to access their storage via any S3-compatible client
 * (Cyberduck, rclone, S3 Browser, AWS CLI, etc.)
 *
 * Security:
 * - access_key_id: Unique identifier (format: HAEX + 16 random alphanumeric chars)
 * - secret_access_key: Encrypted with pgcrypto pgp_sym_encrypt using STORAGE_ENCRYPTION_KEY
 *
 * The encryption key is set via environment variable and passed to postgres functions.
 * This ensures secrets are encrypted at rest but can be decrypted for AWS Signature v4 verification.
 */
export const userStorageCredentials = pgTable(
  "user_storage_credentials",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: uuid("user_id")
      .notNull()
      .unique()
      .references(() => authUsers.id, { onDelete: "cascade" }),
    accessKeyId: text("access_key_id").notNull().unique(), // Format: HAEX + 16 random chars
    encryptedSecretKey: text("encrypted_secret_key").notNull(), // pgp_sym_encrypt(secret, key)
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index("user_storage_credentials_access_key_idx").on(table.accessKeyId),
  ]
);

export type UserStorageCredential = typeof userStorageCredentials.$inferSelect;
export type NewUserStorageCredential = typeof userStorageCredentials.$inferInsert;
