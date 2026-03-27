import {
  pgTable,
  pgSchema,
  text,
  timestamp,
  uuid,
  index,
  uniqueIndex,
  integer,
  boolean,
  primaryKey,
  bigserial,
  bigint,
  customType,
} from "drizzle-orm/pg-core";

const bytea = customType<{ data: Buffer; driverData: Buffer }>({
  dataType() {
    return "bytea";
  },
});

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
    spaceId: uuid("space_id")
      .notNull()
      .references(() => spaces.id, { onDelete: "cascade" }),
    encryptedVaultKey: text("encrypted_vault_key").notNull(), // Base64 of AES-GCM encrypted key
    encryptedVaultName: text("encrypted_vault_name").notNull(), // Base64 of AES-GCM encrypted vault name
    vaultKeySalt: text("vault_key_salt").notNull(), // For PBKDF2 key derivation (vault password -> vault key encryption)
    ephemeralPublicKey: text("ephemeral_public_key").notNull(), // ECDH ephemeral public key for vault name decryption
    vaultKeyNonce: text("vault_key_nonce").notNull(), // For AES-GCM encryption of vault key
    vaultNameNonce: text("vault_name_nonce").notNull(), // For AES-GCM encryption of vault name
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("vault_keys_user_space_idx").on(table.userId, table.spaceId),
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
    spaceId: uuid("space_id")
      .notNull()
      .references(() => spaces.id, { onDelete: "cascade" }),

    // Unencrypted CRDT metadata (required for server-side deduplication)
    tableName: text("table_name").notNull(),
    rowPks: text("row_pks").notNull(), // JSON string of primary key(s), e.g. '{"id": "uuid-here"}'
    columnName: text("column_name"), // Column name for column-level CRDT
    hlcTimestamp: text("hlc_timestamp").notNull(), // Hybrid Logical Clock timestamp
    deviceId: text("device_id"), // Device ID that created this change

    // Encrypted payload (only the actual value is encrypted)
    encryptedValue: text("encrypted_value"), // NULL for DELETE operations
    nonce: text("nonce"), // IV for AES-GCM, NULL for DELETE

    // Space-specific metadata (unencrypted, for server-side validation)
    signature: text("signature"), // ECDSA P-256 signature (Base64)
    signedBy: text("signed_by"), // Public key of signer (Base64 SPKI)
    recordOwner: text("record_owner"), // Public key of record creator (set by server, immutable)
    collaborative: boolean("collaborative").default(false), // Can others modify this record?

    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    // Composite unique index to ensure only one entry per (vault, table, row, column)
    uniqueIndex("sync_changes_unique_cell").on(
      table.spaceId,
      table.tableName,
      table.rowPks,
      table.columnName
    ),
    index("sync_changes_user_space_idx").on(table.userId, table.spaceId),
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

// ============================================
// SHARED SPACES
// ============================================

/**
 * Spaces Table
 * A space is a shared encrypted container that multiple users can access.
 * The space name is encrypted client-side (only members can read it).
 */
export const spaces = pgTable("spaces", {
  id: uuid("id").primaryKey().defaultRandom(),
  type: text("type").notNull().default("shared"),
  ownerId: uuid("owner_id")
    .notNull()
    .references(() => authUsers.id, { onDelete: "cascade" }),
  encryptedName: text("encrypted_name"),
  nameNonce: text("name_nonce"),
  currentKeyGeneration: integer("current_key_generation").notNull().default(1),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export type Space = typeof spaces.$inferSelect;
export type NewSpace = typeof spaces.$inferInsert;

/**
 * Space Members Table
 * Tracks which public keys belong to a space and their permissions.
 * Uses publicKey (not userId) as identifier — enables federation across servers.
 * Composite primary key: (spaceId, publicKey)
 */
export const spaceMembers = pgTable(
  "space_members",
  {
    spaceId: uuid("space_id")
      .notNull()
      .references(() => spaces.id, { onDelete: "cascade" }),
    publicKey: text("public_key").notNull(), // ECDSA P-256 public key (Base64 SPKI)
    label: text("label").notNull(), // Human-readable name assigned by the inviter
    role: text("role").notNull(), // 'admin' | 'owner' | 'member' | 'reader'
    invitedBy: text("invited_by"), // Public key of the inviter (null for space creator)
    joinedAt: timestamp("joined_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    primaryKey({ columns: [table.spaceId, table.publicKey] }),
  ]
);

export type SpaceMember = typeof spaceMembers.$inferSelect;
export type NewSpaceMember = typeof spaceMembers.$inferInsert;

/**
 * Space Key Grants Table
 * Stores encrypted space keys per public key per key generation.
 * When a member is removed, a new generation is created and re-granted to remaining members.
 * Composite primary key: (spaceId, publicKey, generation)
 */
export const spaceKeyGrants = pgTable(
  "space_key_grants",
  {
    spaceId: uuid("space_id")
      .notNull()
      .references(() => spaces.id, { onDelete: "cascade" }),
    publicKey: text("public_key").notNull(), // ECDSA P-256 public key (Base64 SPKI)
    generation: integer("generation").notNull(),
    encryptedSpaceKey: text("encrypted_space_key").notNull(),
    keyNonce: text("key_nonce").notNull(),
    ephemeralPublicKey: text("ephemeral_public_key").notNull(),
    grantedBy: text("granted_by"), // Public key of the granter
    grantedAt: timestamp("granted_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    primaryKey({ columns: [table.spaceId, table.publicKey, table.generation] }),
  ]
);

export type SpaceKeyGrant = typeof spaceKeyGrants.$inferSelect;
export type NewSpaceKeyGrant = typeof spaceKeyGrants.$inferInsert;

// ============================================
// SPACE ACCESS TOKENS
// ============================================

/**
 * Space Access Tokens Table
 * Tokens scoped to a single space, bound to a public key, and carrying a role.
 *
 * Security guarantees:
 * - Stolen token + wrong private key = server rejects (signature mismatch during push)
 * - Reader token = no writes allowed
 * - Revoked token = immediate access loss
 */
export const spaceAccessTokens = pgTable("space_access_tokens", {
  id: uuid("id").primaryKey().defaultRandom(),
  spaceId: uuid("space_id")
    .notNull()
    .references(() => spaces.id, { onDelete: "cascade" }),
  token: text("token").notNull().unique(),
  publicKey: text("public_key").notNull(),
  role: text("role").notNull(), // 'admin' | 'owner' | 'member' | 'reader'
  label: text("label"),
  issuedBy: uuid("issued_by").references(() => authUsers.id),
  revoked: boolean("revoked").notNull().default(false),
  revokedAt: timestamp("revoked_at", { withTimezone: true }),
  revokedBy: text("revoked_by"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
});

export type SpaceAccessToken = typeof spaceAccessTokens.$inferSelect;
export type NewSpaceAccessToken = typeof spaceAccessTokens.$inferInsert;

// ============================================
// IDENTITY AUTH
// ============================================

/**
 * Identities Table
 * Maps DID-based identities to Supabase shadow users.
 * Enables challenge-response auth without email/password.
 */
export const identities = pgTable('identities', {
  id: uuid('id').primaryKey().defaultRandom(),
  did: text('did').notNull().unique(),
  publicKey: text('public_key').notNull().unique(),
  supabaseUserId: uuid('supabase_user_id')
    .references(() => authUsers.id, { onDelete: 'cascade' }),
  email: text('email').unique(),
  tier: text('tier').notNull().default('free'),
  encryptedPrivateKey: text('encrypted_private_key'),
  privateKeyNonce: text('private_key_nonce'),
  privateKeySalt: text('private_key_salt'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
})

export type Identity = typeof identities.$inferSelect
export type NewIdentity = typeof identities.$inferInsert

/**
 * Auth Challenges Table
 * Stores short-lived nonces for challenge-response authentication.
 */
export const authChallenges = pgTable('auth_challenges', {
  id: uuid('id').primaryKey().defaultRandom(),
  did: text('did').notNull(),
  nonce: text('nonce').notNull().unique(),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  usedAt: timestamp('used_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
})

/**
 * Tiers Table
 * Defines service tiers with storage and space limits.
 */
export const tiers = pgTable('tiers', {
  name: text('name').primaryKey(),
  maxStorageBytes: text('max_storage_bytes').notNull(),
  maxSpaces: integer('max_spaces').notNull().default(3),
  description: text('description'),
})

// ============================================
// MLS (Message Layer Security) - Delivery Service
// ============================================

/**
 * MLS Key Packages
 * Pre-published credential+public-key bundles. Single-use.
 * Members upload KeyPackages so others can add them to groups.
 */
export const mlsKeyPackages = pgTable(
  "mls_key_packages",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    spaceId: uuid("space_id")
      .notNull()
      .references(() => spaces.id, { onDelete: "cascade" }),
    identityPublicKey: text("identity_public_key").notNull(),
    keyPackage: bytea("key_package").notNull(),
    consumed: boolean("consumed").notNull().default(false),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index("mls_key_packages_space_identity_idx").on(table.spaceId, table.identityPublicKey),
  ]
);

export type MlsKeyPackage = typeof mlsKeyPackages.$inferSelect;
export type NewMlsKeyPackage = typeof mlsKeyPackages.$inferInsert;

/**
 * Space Invites
 * 2-Step invite flow: Owner creates invite → User accepts → MLS Add happens.
 * Protects KeyPackages from DoS (only consumed after explicit accept).
 */
export const spaceInvites = pgTable(
  "space_invites",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    spaceId: uuid("space_id")
      .notNull()
      .references(() => spaces.id, { onDelete: "cascade" }),
    inviterPublicKey: text("inviter_public_key").notNull(),
    inviteeDid: text("invitee_did").notNull(),
    status: text("status").notNull().default("pending"), // 'pending' | 'accepted' | 'declined'
    includeHistory: boolean("include_history").notNull().default(false),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    respondedAt: timestamp("responded_at", { withTimezone: true }),
  },
  (table) => [
    uniqueIndex("space_invites_unique_idx").on(table.spaceId, table.inviteeDid),
    index("space_invites_invitee_idx").on(table.inviteeDid),
  ]
);

export type SpaceInvite = typeof spaceInvites.$inferSelect;
export type NewSpaceInvite = typeof spaceInvites.$inferInsert;

/**
 * MLS Messages
 * Ordered message queue per space. BIGSERIAL id guarantees monotonic ordering.
 * Server stores opaque blobs — no MLS understanding needed.
 */
export const mlsMessages = pgTable(
  "mls_messages",
  {
    id: bigserial("id", { mode: "number" }).primaryKey(),
    spaceId: uuid("space_id")
      .notNull()
      .references(() => spaces.id, { onDelete: "cascade" }),
    senderPublicKey: text("sender_public_key").notNull(),
    messageType: text("message_type").notNull(), // 'commit' | 'application'
    payload: bytea("payload").notNull(),
    epoch: bigint("epoch", { mode: "number" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index("mls_messages_space_id_idx").on(table.spaceId, table.id),
  ]
);

export type MlsMessage = typeof mlsMessages.$inferSelect;
export type NewMlsMessage = typeof mlsMessages.$inferInsert;

/**
 * MLS Welcome Messages
 * Targeted at specific recipients when they are added to a group.
 * Single-use: consumed after retrieval.
 */
export const mlsWelcomeMessages = pgTable(
  "mls_welcome_messages",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    spaceId: uuid("space_id")
      .notNull()
      .references(() => spaces.id, { onDelete: "cascade" }),
    recipientPublicKey: text("recipient_public_key").notNull(),
    payload: bytea("payload").notNull(),
    consumed: boolean("consumed").notNull().default(false),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index("mls_welcome_recipient_idx").on(table.spaceId, table.recipientPublicKey),
  ]
);

export type MlsWelcomeMessage = typeof mlsWelcomeMessages.$inferSelect;
export type NewMlsWelcomeMessage = typeof mlsWelcomeMessages.$inferInsert;
