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
    salt: text("salt").notNull(), // For PBKDF2 key derivation
    nonce: text("nonce").notNull(), // For AES-GCM encryption
    createdAt: timestamp("created_at").notNull().defaultNow(),
    updatedAt: timestamp("updated_at").notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("vault_keys_user_vault_idx").on(table.userId, table.vaultId),
    index("vault_keys_user_idx").on(table.userId),
  ]
);

/**
 * Sync Changes Table
 * Stores fully encrypted CRDT change entries for synchronization (Zero-Knowledge)
 * The server only sees: userId, vaultId, deviceId, encrypted blob, and server timestamps
 * All CRDT metadata (table, row, column, operation, hlc, value) is encrypted inside encryptedData
 * Client performs decryption and CRDT conflict resolution locally
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
    deviceId: text("device_id"), // Device ID that created this change (for filtering on pull)

    // Fully encrypted CRDT change (contains: tableName, rowPks, columnName, operation, hlcTimestamp, value)
    encryptedData: text("encrypted_data").notNull(),
    nonce: text("nonce").notNull(), // IV for AES-GCM

    createdAt: timestamp("created_at").notNull().defaultNow(),
  },
  (table) => [
    index("sync_changes_user_vault_idx").on(table.userId, table.vaultId),
    index("sync_changes_created_idx").on(table.createdAt),
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
