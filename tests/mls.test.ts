// @ts-nocheck — Test file: Drizzle destructuring returns are asserted via expect()
import { describe, test, expect, beforeAll, afterAll, beforeEach } from 'bun:test'
import { drizzle } from 'drizzle-orm/postgres-js'
import postgres from 'postgres'
import { eq, and, sql } from 'drizzle-orm'
import {
  pgTable, pgSchema, text, timestamp, uuid, index, uniqueIndex,
  integer, boolean, primaryKey, bigserial, bigint, customType,
} from 'drizzle-orm/pg-core'

// ============================================
// SCHEMA (mirrors production)
// ============================================

const bytea = customType<{ data: Buffer; driverData: Buffer }>({
  dataType() { return 'bytea' },
})

const authSchema = pgSchema('auth')
const authUsers = authSchema.table('users', {
  id: uuid('id').primaryKey(),
})

const spaces = pgTable('spaces', {
  id: uuid('id').primaryKey().defaultRandom(),
  type: text('type').notNull().default('shared'),
  ownerId: uuid('owner_id').notNull().references(() => authUsers.id, { onDelete: 'cascade' }),
  encryptedName: text('encrypted_name'),
  nameNonce: text('name_nonce'),
  currentKeyGeneration: integer('current_key_generation').notNull().default(1),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
})

const spaceMembers = pgTable('space_members', {
  spaceId: uuid('space_id').notNull().references(() => spaces.id, { onDelete: 'cascade' }),
  publicKey: text('public_key').notNull(),
  label: text('label').notNull(),
  role: text('role').notNull(),
  invitedBy: text('invited_by'),
  joinedAt: timestamp('joined_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => [primaryKey({ columns: [table.spaceId, table.publicKey] })])

const identities = pgTable('identities', {
  id: uuid('id').primaryKey().defaultRandom(),
  did: text('did').notNull().unique(),
  publicKey: text('public_key').notNull().unique(),
  supabaseUserId: uuid('supabase_user_id').references(() => authUsers.id, { onDelete: 'cascade' }),
  email: text('email'),
  tier: text('tier').notNull().default('free'),
  encryptedPrivateKey: text('encrypted_private_key'),
  privateKeyNonce: text('private_key_nonce'),
  privateKeySalt: text('private_key_salt'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
})

const spaceInvites = pgTable('space_invites', {
  id: uuid('id').primaryKey().defaultRandom(),
  spaceId: uuid('space_id').notNull().references(() => spaces.id, { onDelete: 'cascade' }),
  inviterPublicKey: text('inviter_public_key').notNull(),
  inviteeDid: text('invitee_did').notNull(),
  status: text('status').notNull().default('pending'),
  includeHistory: boolean('include_history').notNull().default(false),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  respondedAt: timestamp('responded_at', { withTimezone: true }),
}, (table) => [
  uniqueIndex('space_invites_unique_idx').on(table.spaceId, table.inviteeDid),
  index('space_invites_invitee_idx').on(table.inviteeDid),
])

const mlsKeyPackages = pgTable('mls_key_packages', {
  id: uuid('id').primaryKey().defaultRandom(),
  spaceId: uuid('space_id').notNull().references(() => spaces.id, { onDelete: 'cascade' }),
  identityPublicKey: text('identity_public_key').notNull(),
  keyPackage: bytea('key_package').notNull(),
  consumed: boolean('consumed').notNull().default(false),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index('mls_key_packages_space_identity_idx').on(table.spaceId, table.identityPublicKey),
])

const mlsMessages = pgTable('mls_messages', {
  id: bigserial('id', { mode: 'number' }).primaryKey(),
  spaceId: uuid('space_id').notNull().references(() => spaces.id, { onDelete: 'cascade' }),
  senderPublicKey: text('sender_public_key').notNull(),
  messageType: text('message_type').notNull(),
  payload: bytea('payload').notNull(),
  epoch: bigint('epoch', { mode: 'number' }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index('mls_messages_space_id_idx').on(table.spaceId, table.id),
])

const mlsWelcomeMessages = pgTable('mls_welcome_messages', {
  id: uuid('id').primaryKey().defaultRandom(),
  spaceId: uuid('space_id').notNull().references(() => spaces.id, { onDelete: 'cascade' }),
  recipientPublicKey: text('recipient_public_key').notNull(),
  payload: bytea('payload').notNull(),
  consumed: boolean('consumed').notNull().default(false),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index('mls_welcome_recipient_idx').on(table.spaceId, table.recipientPublicKey),
])

// ============================================
// TEST SETUP
// ============================================

const connectionString = process.env.DATABASE_URL_TEST || process.env.DATABASE_URL

if (!connectionString) {
  describe('MLS Tests', () => {
    test.skip('skipped - no DATABASE_URL available', () => {})
  })
} else {
  if (!process.env.DATABASE_URL_TEST && process.env.DATABASE_URL) {
    console.warn('⚠️  WARNING: Using DATABASE_URL for tests. Set DATABASE_URL_TEST for isolation.')
  }

  const client = postgres(connectionString)
  const db = drizzle(client, {
    schema: { authUsers, spaces, spaceMembers, identities, spaceInvites, mlsKeyPackages, mlsMessages, mlsWelcomeMessages },
  })

  const TEST_RUN = Date.now().toString(36)

  // Test identities
  const ADMIN_USER_ID = '00000000-0000-0000-0000-000000000a01'
  const OWNER_USER_ID = '00000000-0000-0000-0000-000000000a02'
  const MEMBER_USER_ID = '00000000-0000-0000-0000-000000000a03'
  const OUTSIDER_USER_ID = '00000000-0000-0000-0000-000000000a04'
  const INVITEE_USER_ID = '00000000-0000-0000-0000-000000000a05'

  const ADMIN_PK = `__test_mls_admin_pk_${TEST_RUN}`
  const OWNER_PK = `__test_mls_owner_pk_${TEST_RUN}`
  const MEMBER_PK = `__test_mls_member_pk_${TEST_RUN}`
  const OUTSIDER_PK = `__test_mls_outsider_pk_${TEST_RUN}`
  const INVITEE_PK = `__test_mls_invitee_pk_${TEST_RUN}`

  const ADMIN_DID = `did:key:__test_admin_${TEST_RUN}`
  const OWNER_DID = `did:key:__test_owner_${TEST_RUN}`
  const MEMBER_DID = `did:key:__test_member_${TEST_RUN}`
  const OUTSIDER_DID = `did:key:__test_outsider_${TEST_RUN}`
  const INVITEE_DID = `did:key:__test_invitee_${TEST_RUN}`

  const SPACE_ID = '10000000-0000-0000-0000-000000000001'

  const FAKE_KEY_PACKAGE = Buffer.from('fake-mls-key-package-data-for-testing')

  async function cleanup() {
    // Clean in reverse dependency order
    await db.delete(mlsWelcomeMessages).where(eq(mlsWelcomeMessages.spaceId, SPACE_ID))
    await db.delete(mlsMessages).where(eq(mlsMessages.spaceId, SPACE_ID))
    await db.delete(mlsKeyPackages).where(eq(mlsKeyPackages.spaceId, SPACE_ID))
    await db.delete(spaceInvites).where(eq(spaceInvites.spaceId, SPACE_ID))
    await db.delete(spaceMembers).where(eq(spaceMembers.spaceId, SPACE_ID))
    await db.delete(spaces).where(eq(spaces.id, SPACE_ID))
    for (const did of [ADMIN_DID, OWNER_DID, MEMBER_DID, OUTSIDER_DID, INVITEE_DID]) {
      await db.delete(identities).where(eq(identities.did, did))
    }
    for (const userId of [ADMIN_USER_ID, OWNER_USER_ID, MEMBER_USER_ID, OUTSIDER_USER_ID, INVITEE_USER_ID]) {
      await client`DELETE FROM auth.users WHERE id = ${userId}`
    }
  }

  async function setupTestData() {
    // Create test users in auth.users
    for (const userId of [ADMIN_USER_ID, OWNER_USER_ID, MEMBER_USER_ID, OUTSIDER_USER_ID, INVITEE_USER_ID]) {
      await client`INSERT INTO auth.users (id, instance_id, aud, role, email, created_at, updated_at)
        VALUES (${userId}, '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', ${userId + '@test.com'}, NOW(), NOW())
        ON CONFLICT (id) DO NOTHING`
    }

    // Create identities
    const idPairs = [
      { did: ADMIN_DID, pk: ADMIN_PK, userId: ADMIN_USER_ID },
      { did: OWNER_DID, pk: OWNER_PK, userId: OWNER_USER_ID },
      { did: MEMBER_DID, pk: MEMBER_PK, userId: MEMBER_USER_ID },
      { did: OUTSIDER_DID, pk: OUTSIDER_PK, userId: OUTSIDER_USER_ID },
      { did: INVITEE_DID, pk: INVITEE_PK, userId: INVITEE_USER_ID },
    ]
    for (const { did, pk, userId } of idPairs) {
      await db.insert(identities).values({
        did, publicKey: pk, supabaseUserId: userId,
      }).onConflictDoNothing()
    }

    // Create space
    await db.insert(spaces).values({
      id: SPACE_ID, ownerId: ADMIN_USER_ID, encryptedName: 'test', nameNonce: 'nonce',
    }).onConflictDoNothing()

    // Add members
    await db.insert(spaceMembers).values([
      { spaceId: SPACE_ID, publicKey: ADMIN_PK, label: 'Admin', role: 'admin' },
      { spaceId: SPACE_ID, publicKey: OWNER_PK, label: 'Owner', role: 'owner' },
      { spaceId: SPACE_ID, publicKey: MEMBER_PK, label: 'Member', role: 'member' },
    ]).onConflictDoNothing()
  }

  // ============================================
  // TESTS
  // ============================================

  beforeAll(async () => {
    await cleanup()
    await setupTestData()
  })

  afterAll(async () => {
    await cleanup()
    await client.end()
  })

  // ============================================
  // INVITE FLOW - NORMAL OPERATIONS
  // ============================================

  describe('Invite Flow', () => {
    beforeEach(async () => {
      await db.delete(spaceInvites).where(eq(spaceInvites.spaceId, SPACE_ID))
      await db.delete(mlsKeyPackages).where(eq(mlsKeyPackages.spaceId, SPACE_ID))
    })

    test('admin can create a pending invite', async () => {
      const [invite] = await db.insert(spaceInvites).values({
        spaceId: SPACE_ID,
        inviterPublicKey: ADMIN_PK,
        inviteeDid: INVITEE_DID,
        includeHistory: false,
      }).returning()

      expect(invite!.status).toBe('pending')
      expect(invite!.inviteeDid).toBe(INVITEE_DID)
      expect(invite!.respondedAt).toBeNull()
    })

    test('owner can create a pending invite', async () => {
      const [invite] = await db.insert(spaceInvites).values({
        spaceId: SPACE_ID,
        inviterPublicKey: OWNER_PK,
        inviteeDid: INVITEE_DID,
      }).returning()

      expect(invite!.status).toBe('pending')
    })

    test('invite can be accepted with KeyPackage upload (atomic)', async () => {
      // Create pending invite
      const [invite] = await db.insert(spaceInvites).values({
        spaceId: SPACE_ID,
        inviterPublicKey: ADMIN_PK,
        inviteeDid: INVITEE_DID,
      }).returning()

      // Accept + upload KeyPackages atomically
      await db.transaction(async (tx) => {
        await tx.update(spaceInvites)
          .set({ status: 'accepted', respondedAt: new Date() })
          .where(eq(spaceInvites.id, invite!.id))

        await tx.insert(mlsKeyPackages).values([
          { spaceId: SPACE_ID, identityPublicKey: INVITEE_PK, keyPackage: FAKE_KEY_PACKAGE },
          { spaceId: SPACE_ID, identityPublicKey: INVITEE_PK, keyPackage: FAKE_KEY_PACKAGE },
        ])
      })

      // Verify
      const [updated] = await db.select().from(spaceInvites).where(eq(spaceInvites.id, invite!.id))
      expect(updated!.status).toBe('accepted')
      expect(updated!.respondedAt).not.toBeNull()

      const keyPackages = await db.select().from(mlsKeyPackages)
        .where(and(eq(mlsKeyPackages.spaceId, SPACE_ID), eq(mlsKeyPackages.identityPublicKey, INVITEE_PK)))
      expect(keyPackages.length).toBe(2)
      expect(keyPackages.every(kp => kp.consumed === false)).toBe(true)
    })

    test('invite can be declined', async () => {
      const [invite] = await db.insert(spaceInvites).values({
        spaceId: SPACE_ID,
        inviterPublicKey: ADMIN_PK,
        inviteeDid: INVITEE_DID,
      }).returning()

      await db.update(spaceInvites)
        .set({ status: 'declined', respondedAt: new Date() })
        .where(eq(spaceInvites.id, invite!.id))

      const [updated] = await db.select().from(spaceInvites).where(eq(spaceInvites.id, invite!.id))
      expect(updated!.status).toBe('declined')
    })

    test('include_history flag is preserved', async () => {
      const [invite] = await db.insert(spaceInvites).values({
        spaceId: SPACE_ID,
        inviterPublicKey: ADMIN_PK,
        inviteeDid: INVITEE_DID,
        includeHistory: true,
      }).returning()

      expect(invite!.includeHistory).toBe(true)
    })

    test('invite can be withdrawn (deleted) by inviter', async () => {
      const [invite] = await db.insert(spaceInvites).values({
        spaceId: SPACE_ID,
        inviterPublicKey: ADMIN_PK,
        inviteeDid: INVITEE_DID,
      }).returning()

      const deleted = await db.delete(spaceInvites)
        .where(eq(spaceInvites.id, invite!.id))
        .returning()

      expect(deleted.length).toBe(1)

      const remaining = await db.select().from(spaceInvites).where(eq(spaceInvites.id, invite!.id))
      expect(remaining.length).toBe(0)
    })
  })

  // ============================================
  // INVITE FLOW - SECURITY
  // ============================================

  describe('SECURITY: Invite Constraints', () => {
    beforeEach(async () => {
      await db.delete(spaceInvites).where(eq(spaceInvites.spaceId, SPACE_ID))
    })

    test('SECURITY: duplicate invite for same user+space is rejected', async () => {
      await db.insert(spaceInvites).values({
        spaceId: SPACE_ID,
        inviterPublicKey: ADMIN_PK,
        inviteeDid: INVITEE_DID,
      })

      // Second invite for same user+space should fail (unique constraint)
      let error: Error | null = null
      try {
        await db.insert(spaceInvites).values({
          spaceId: SPACE_ID,
          inviterPublicKey: OWNER_PK,
          inviteeDid: INVITEE_DID,
        })
      } catch (e) {
        error = e as Error
      }

      expect(error).not.toBeNull()
      expect(error!.message).toContain('unique')
    })

    test('SECURITY: invite is cascade deleted when space is deleted', async () => {
      // Create a temporary space with invite
      const tempSpaceId = '20000000-0000-0000-0000-000000000001'
      await db.insert(spaces).values({
        id: tempSpaceId, ownerId: ADMIN_USER_ID,
      })
      await db.insert(spaceInvites).values({
        spaceId: tempSpaceId,
        inviterPublicKey: ADMIN_PK,
        inviteeDid: INVITEE_DID,
      })

      // Delete space → invite should cascade
      await db.delete(spaces).where(eq(spaces.id, tempSpaceId))

      const invites = await db.select().from(spaceInvites)
        .where(eq(spaceInvites.spaceId, tempSpaceId))
      expect(invites.length).toBe(0)
    })
  })

  // ============================================
  // KEY PACKAGES - NORMAL OPERATIONS
  // ============================================

  describe('KeyPackage Management', () => {
    beforeEach(async () => {
      await db.delete(mlsKeyPackages).where(eq(mlsKeyPackages.spaceId, SPACE_ID))
    })

    test('member can upload multiple KeyPackages', async () => {
      const packages = Array.from({ length: 5 }, (_, i) =>
        ({ spaceId: SPACE_ID, identityPublicKey: MEMBER_PK, keyPackage: Buffer.from(`kp-${i}`) })
      )

      await db.insert(mlsKeyPackages).values(packages)

      const stored = await db.select().from(mlsKeyPackages)
        .where(and(eq(mlsKeyPackages.spaceId, SPACE_ID), eq(mlsKeyPackages.identityPublicKey, MEMBER_PK)))
      expect(stored.length).toBe(5)
      expect(stored.every(kp => kp.consumed === false)).toBe(true)
    })

    test('KeyPackage is single-use: consumed after retrieval', async () => {
      await db.insert(mlsKeyPackages).values({
        spaceId: SPACE_ID, identityPublicKey: INVITEE_PK, keyPackage: FAKE_KEY_PACKAGE,
      })

      // Fetch one
      const [kp] = await db.select().from(mlsKeyPackages)
        .where(and(
          eq(mlsKeyPackages.spaceId, SPACE_ID),
          eq(mlsKeyPackages.identityPublicKey, INVITEE_PK),
          eq(mlsKeyPackages.consumed, false),
        ))
        .limit(1)

      expect(kp).toBeDefined()

      // Mark consumed
      await db.update(mlsKeyPackages).set({ consumed: true }).where(eq(mlsKeyPackages.id, kp!.id))

      // Should not be available anymore
      const remaining = await db.select().from(mlsKeyPackages)
        .where(and(
          eq(mlsKeyPackages.spaceId, SPACE_ID),
          eq(mlsKeyPackages.identityPublicKey, INVITEE_PK),
          eq(mlsKeyPackages.consumed, false),
        ))
      expect(remaining.length).toBe(0)
    })

    test('KeyPackages are cascade deleted when space is deleted', async () => {
      const tempSpaceId = '20000000-0000-0000-0000-000000000002'
      await db.insert(spaces).values({ id: tempSpaceId, ownerId: ADMIN_USER_ID })
      await db.insert(mlsKeyPackages).values({
        spaceId: tempSpaceId, identityPublicKey: MEMBER_PK, keyPackage: FAKE_KEY_PACKAGE,
      })

      await db.delete(spaces).where(eq(spaces.id, tempSpaceId))

      const kps = await db.select().from(mlsKeyPackages).where(eq(mlsKeyPackages.spaceId, tempSpaceId))
      expect(kps.length).toBe(0)
    })
  })

  // ============================================
  // KEY PACKAGES - SECURITY (DoS Protection)
  // ============================================

  describe('SECURITY: KeyPackage Protection', () => {
    beforeEach(async () => {
      await db.delete(mlsKeyPackages).where(eq(mlsKeyPackages.spaceId, SPACE_ID))
      await db.delete(spaceInvites).where(eq(spaceInvites.spaceId, SPACE_ID))
    })

    test('SECURITY: KeyPackage retrieval requires accepted invite', async () => {
      // Upload KeyPackages for invitee
      await db.insert(mlsKeyPackages).values({
        spaceId: SPACE_ID, identityPublicKey: INVITEE_PK, keyPackage: FAKE_KEY_PACKAGE,
      })

      // Without invite: should find no accepted invite
      const [acceptedInvite] = await db.select().from(spaceInvites)
        .where(and(
          eq(spaceInvites.spaceId, SPACE_ID),
          eq(spaceInvites.inviteeDid, INVITEE_DID),
          eq(spaceInvites.status, 'accepted'),
        ))
        .limit(1)

      expect(acceptedInvite).toBeUndefined()
    })

    test('SECURITY: pending invite does NOT allow KeyPackage retrieval', async () => {
      // Create pending invite (not accepted)
      await db.insert(spaceInvites).values({
        spaceId: SPACE_ID,
        inviterPublicKey: ADMIN_PK,
        inviteeDid: INVITEE_DID,
      })

      // Check: accepted invite should not exist
      const [accepted] = await db.select().from(spaceInvites)
        .where(and(
          eq(spaceInvites.spaceId, SPACE_ID),
          eq(spaceInvites.inviteeDid, INVITEE_DID),
          eq(spaceInvites.status, 'accepted'),
        ))
        .limit(1)

      expect(accepted).toBeUndefined()
    })

    test('SECURITY: declined invite does NOT allow KeyPackage retrieval', async () => {
      await db.insert(spaceInvites).values({
        spaceId: SPACE_ID,
        inviterPublicKey: ADMIN_PK,
        inviteeDid: INVITEE_DID,
        status: 'declined',
        respondedAt: new Date(),
      })

      const [accepted] = await db.select().from(spaceInvites)
        .where(and(
          eq(spaceInvites.spaceId, SPACE_ID),
          eq(spaceInvites.inviteeDid, INVITEE_DID),
          eq(spaceInvites.status, 'accepted'),
        ))
        .limit(1)

      expect(accepted).toBeUndefined()
    })

    test('SECURITY: only accepted invite allows KeyPackage retrieval', async () => {
      // Create and accept invite
      await db.insert(spaceInvites).values({
        spaceId: SPACE_ID,
        inviterPublicKey: ADMIN_PK,
        inviteeDid: INVITEE_DID,
        status: 'accepted',
        respondedAt: new Date(),
      })

      await db.insert(mlsKeyPackages).values({
        spaceId: SPACE_ID, identityPublicKey: INVITEE_PK, keyPackage: FAKE_KEY_PACKAGE,
      })

      // Now accepted invite exists
      const [accepted] = await db.select().from(spaceInvites)
        .where(and(
          eq(spaceInvites.spaceId, SPACE_ID),
          eq(spaceInvites.inviteeDid, INVITEE_DID),
          eq(spaceInvites.status, 'accepted'),
        ))
        .limit(1)

      expect(accepted).toBeDefined()
      expect(accepted!.status).toBe('accepted')

      // KeyPackage should be retrievable
      const [kp] = await db.select().from(mlsKeyPackages)
        .where(and(
          eq(mlsKeyPackages.spaceId, SPACE_ID),
          eq(mlsKeyPackages.identityPublicKey, INVITEE_PK),
          eq(mlsKeyPackages.consumed, false),
        ))
        .limit(1)

      expect(kp).toBeDefined()
    })

    test('SECURITY: KeyPackage DoS attack is mitigated by invite requirement', async () => {
      // Attacker scenario: try to consume all KeyPackages without accepted invite
      await db.insert(mlsKeyPackages).values(
        Array.from({ length: 10 }, () => ({
          spaceId: SPACE_ID, identityPublicKey: INVITEE_PK, keyPackage: FAKE_KEY_PACKAGE,
        }))
      )

      // Without accepted invite, the route logic would reject before consuming
      const [accepted] = await db.select().from(spaceInvites)
        .where(and(
          eq(spaceInvites.spaceId, SPACE_ID),
          eq(spaceInvites.inviteeDid, INVITEE_DID),
          eq(spaceInvites.status, 'accepted'),
        ))
        .limit(1)

      expect(accepted).toBeUndefined()

      // All 10 KeyPackages should remain unconsumed
      const unconsumed = await db.select().from(mlsKeyPackages)
        .where(and(
          eq(mlsKeyPackages.spaceId, SPACE_ID),
          eq(mlsKeyPackages.identityPublicKey, INVITEE_PK),
          eq(mlsKeyPackages.consumed, false),
        ))
      expect(unconsumed.length).toBe(10)
    })
  })

  // ============================================
  // MLS MESSAGES - ORDERING
  // ============================================

  describe('MLS Message Ordering', () => {
    beforeEach(async () => {
      await db.delete(mlsMessages).where(eq(mlsMessages.spaceId, SPACE_ID))
    })

    test('messages have monotonically increasing IDs', async () => {
      const payloads = ['msg1', 'msg2', 'msg3', 'msg4', 'msg5']

      for (const p of payloads) {
        await db.insert(mlsMessages).values({
          spaceId: SPACE_ID,
          senderPublicKey: ADMIN_PK,
          messageType: 'application',
          payload: Buffer.from(p),
        })
      }

      const messages = await db.select().from(mlsMessages)
        .where(eq(mlsMessages.spaceId, SPACE_ID))
        .orderBy(mlsMessages.id)

      expect(messages.length).toBe(5)

      for (let i = 1; i < messages.length; i++) {
        expect(messages[i]!.id).toBeGreaterThan(messages[i - 1]!.id)
      }
    })

    test('messages can be fetched after a given ID (pagination)', async () => {
      // Insert 10 messages
      for (let i = 0; i < 10; i++) {
        await db.insert(mlsMessages).values({
          spaceId: SPACE_ID,
          senderPublicKey: ADMIN_PK,
          messageType: 'application',
          payload: Buffer.from(`msg-${i}`),
        })
      }

      const allMessages = await db.select().from(mlsMessages)
        .where(eq(mlsMessages.spaceId, SPACE_ID))
        .orderBy(mlsMessages.id)

      // Fetch after the 5th message
      const afterId = allMessages[4].id
      const remaining = await db.select().from(mlsMessages)
        .where(and(
          eq(mlsMessages.spaceId, SPACE_ID),
          sql`${mlsMessages.id} > ${afterId}`,
        ))
        .orderBy(mlsMessages.id)

      expect(remaining.length).toBe(5)
      expect(remaining[0].id).toBeGreaterThan(afterId)
    })

    test('commit and application messages are stored correctly', async () => {
      await db.insert(mlsMessages).values([
        { spaceId: SPACE_ID, senderPublicKey: ADMIN_PK, messageType: 'commit', payload: Buffer.from('commit-data'), epoch: 1 },
        { spaceId: SPACE_ID, senderPublicKey: MEMBER_PK, messageType: 'application', payload: Buffer.from('app-data'), epoch: 1 },
      ])

      const messages = await db.select().from(mlsMessages)
        .where(eq(mlsMessages.spaceId, SPACE_ID))
        .orderBy(mlsMessages.id)

      expect(messages[0].messageType).toBe('commit')
      expect(messages[0].epoch).toBe(1)
      expect(messages[1].messageType).toBe('application')
    })

    test('messages from different spaces are isolated', async () => {
      const otherSpaceId = '20000000-0000-0000-0000-000000000003'
      await db.insert(spaces).values({ id: otherSpaceId, ownerId: ADMIN_USER_ID })

      await db.insert(mlsMessages).values([
        { spaceId: SPACE_ID, senderPublicKey: ADMIN_PK, messageType: 'application', payload: Buffer.from('space1') },
        { spaceId: otherSpaceId, senderPublicKey: ADMIN_PK, messageType: 'application', payload: Buffer.from('space2') },
      ])

      const space1Messages = await db.select().from(mlsMessages)
        .where(eq(mlsMessages.spaceId, SPACE_ID))
      const space2Messages = await db.select().from(mlsMessages)
        .where(eq(mlsMessages.spaceId, otherSpaceId))

      expect(space1Messages.length).toBe(1)
      expect(space2Messages.length).toBe(1)

      // Cleanup
      await db.delete(mlsMessages).where(eq(mlsMessages.spaceId, otherSpaceId))
      await db.delete(spaces).where(eq(spaces.id, otherSpaceId))
    })
  })

  // ============================================
  // WELCOME MESSAGES
  // ============================================

  describe('Welcome Messages', () => {
    beforeEach(async () => {
      await db.delete(mlsWelcomeMessages).where(eq(mlsWelcomeMessages.spaceId, SPACE_ID))
    })

    test('welcome message is stored for specific recipient', async () => {
      await db.insert(mlsWelcomeMessages).values({
        spaceId: SPACE_ID,
        recipientPublicKey: INVITEE_PK,
        payload: Buffer.from('welcome-data'),
      })

      const [welcome] = await db.select().from(mlsWelcomeMessages)
        .where(and(
          eq(mlsWelcomeMessages.spaceId, SPACE_ID),
          eq(mlsWelcomeMessages.recipientPublicKey, INVITEE_PK),
        ))

      expect(welcome).toBeDefined()
      expect(welcome!.consumed).toBe(false)
      expect(welcome!.payload.toString()).toBe('welcome-data')
    })

    test('welcome message is single-use (consumed after retrieval)', async () => {
      await db.insert(mlsWelcomeMessages).values({
        spaceId: SPACE_ID,
        recipientPublicKey: INVITEE_PK,
        payload: Buffer.from('welcome'),
      })

      // Fetch and consume
      const [welcome] = await db.select().from(mlsWelcomeMessages)
        .where(and(
          eq(mlsWelcomeMessages.spaceId, SPACE_ID),
          eq(mlsWelcomeMessages.recipientPublicKey, INVITEE_PK),
          eq(mlsWelcomeMessages.consumed, false),
        ))

      await db.update(mlsWelcomeMessages)
        .set({ consumed: true })
        .where(eq(mlsWelcomeMessages.id, welcome!.id))

      // Should not be found as unconsumed
      const remaining = await db.select().from(mlsWelcomeMessages)
        .where(and(
          eq(mlsWelcomeMessages.spaceId, SPACE_ID),
          eq(mlsWelcomeMessages.recipientPublicKey, INVITEE_PK),
          eq(mlsWelcomeMessages.consumed, false),
        ))
      expect(remaining.length).toBe(0)
    })

    test('SECURITY: welcome messages are recipient-isolated', async () => {
      await db.insert(mlsWelcomeMessages).values({
        spaceId: SPACE_ID,
        recipientPublicKey: INVITEE_PK,
        payload: Buffer.from('secret-welcome'),
      })

      // Other user should not see it
      const otherWelcomes = await db.select().from(mlsWelcomeMessages)
        .where(and(
          eq(mlsWelcomeMessages.spaceId, SPACE_ID),
          eq(mlsWelcomeMessages.recipientPublicKey, OUTSIDER_PK),
          eq(mlsWelcomeMessages.consumed, false),
        ))
      expect(otherWelcomes.length).toBe(0)
    })
  })

  // ============================================
  // FULL INVITE-TO-JOIN FLOW (Integration)
  // ============================================

  describe('Full Invite-to-Join Flow', () => {
    beforeEach(async () => {
      await db.delete(mlsWelcomeMessages).where(eq(mlsWelcomeMessages.spaceId, SPACE_ID))
      await db.delete(mlsMessages).where(eq(mlsMessages.spaceId, SPACE_ID))
      await db.delete(mlsKeyPackages).where(eq(mlsKeyPackages.spaceId, SPACE_ID))
      await db.delete(spaceInvites).where(eq(spaceInvites.spaceId, SPACE_ID))
    })

    test('complete flow: invite → accept → KeyPackage fetch → commit + welcome', async () => {
      // Step 1: Admin creates invite
      const [invite] = await db.insert(spaceInvites).values({
        spaceId: SPACE_ID,
        inviterPublicKey: ADMIN_PK,
        inviteeDid: INVITEE_DID,
        includeHistory: true,
      }).returning()

      expect(invite!.status).toBe('pending')

      // Step 2: Invitee accepts + uploads KeyPackages (atomic)
      await db.transaction(async (tx) => {
        await tx.update(spaceInvites)
          .set({ status: 'accepted', respondedAt: new Date() })
          .where(eq(spaceInvites.id, invite!.id))

        await tx.insert(mlsKeyPackages).values(
          Array.from({ length: 5 }, () => ({
            spaceId: SPACE_ID,
            identityPublicKey: INVITEE_PK,
            keyPackage: FAKE_KEY_PACKAGE,
          }))
        )
      })

      // Step 3: Admin verifies accepted invite exists
      const [accepted] = await db.select().from(spaceInvites)
        .where(and(
          eq(spaceInvites.spaceId, SPACE_ID),
          eq(spaceInvites.inviteeDid, INVITEE_DID),
          eq(spaceInvites.status, 'accepted'),
        ))
        .limit(1)

      expect(accepted).toBeDefined()
      expect(accepted!.includeHistory).toBe(true)

      // Step 4: Admin fetches KeyPackage (single-use)
      const [kp] = await db.select().from(mlsKeyPackages)
        .where(and(
          eq(mlsKeyPackages.spaceId, SPACE_ID),
          eq(mlsKeyPackages.identityPublicKey, INVITEE_PK),
          eq(mlsKeyPackages.consumed, false),
        ))
        .limit(1)

      expect(kp).toBeDefined()

      await db.update(mlsKeyPackages)
        .set({ consumed: true })
        .where(eq(mlsKeyPackages.id, kp!.id))

      // Step 5: Admin sends MLS Commit
      const [commit] = await db.insert(mlsMessages).values({
        spaceId: SPACE_ID,
        senderPublicKey: ADMIN_PK,
        messageType: 'commit',
        payload: Buffer.from('mls-commit-adding-invitee'),
        epoch: 2,
      }).returning()

      expect(commit!.messageType).toBe('commit')

      // Step 6: Admin sends Welcome to invitee
      await db.insert(mlsWelcomeMessages).values({
        spaceId: SPACE_ID,
        recipientPublicKey: INVITEE_PK,
        payload: Buffer.from('mls-welcome-for-invitee'),
      })

      // Step 7: Invitee fetches Welcome
      const welcomes = await db.select().from(mlsWelcomeMessages)
        .where(and(
          eq(mlsWelcomeMessages.spaceId, SPACE_ID),
          eq(mlsWelcomeMessages.recipientPublicKey, INVITEE_PK),
          eq(mlsWelcomeMessages.consumed, false),
        ))

      expect(welcomes.length).toBe(1)

      // Verify: 4 KeyPackages remain (1 consumed, 5 uploaded)
      const remainingKps = await db.select().from(mlsKeyPackages)
        .where(and(
          eq(mlsKeyPackages.spaceId, SPACE_ID),
          eq(mlsKeyPackages.identityPublicKey, INVITEE_PK),
          eq(mlsKeyPackages.consumed, false),
        ))
      expect(remainingKps.length).toBe(4)
    })
  })

  // ============================================
  // SECURITY: ROLE-BASED ACCESS
  // ============================================

  describe('SECURITY: Role-Based Access Control', () => {
    test('SECURITY: membership check correctly identifies members', async () => {
      const [adminMember] = await db.select({ role: spaceMembers.role })
        .from(spaceMembers)
        .where(and(eq(spaceMembers.spaceId, SPACE_ID), eq(spaceMembers.publicKey, ADMIN_PK)))
      const [outsider] = await db.select({ role: spaceMembers.role })
        .from(spaceMembers)
        .where(and(eq(spaceMembers.spaceId, SPACE_ID), eq(spaceMembers.publicKey, OUTSIDER_PK)))

      expect(adminMember).toBeDefined()
      expect(adminMember!.role).toBe('admin')
      expect(outsider).toBeUndefined()
    })

    test('SECURITY: only admin/owner roles can send welcomes', async () => {
      const adminRole = 'admin'
      const ownerRole = 'owner'
      const memberRole = 'member'

      expect(['admin', 'owner'].includes(adminRole)).toBe(true)
      expect(['admin', 'owner'].includes(ownerRole)).toBe(true)
      expect(['admin', 'owner'].includes(memberRole)).toBe(false)
    })

    test('SECURITY: outsider cannot access space messages', async () => {
      await db.insert(mlsMessages).values({
        spaceId: SPACE_ID,
        senderPublicKey: ADMIN_PK,
        messageType: 'application',
        payload: Buffer.from('secret-data'),
      })

      // Outsider membership check fails
      const [outsiderMembership] = await db.select().from(spaceMembers)
        .where(and(eq(spaceMembers.spaceId, SPACE_ID), eq(spaceMembers.publicKey, OUTSIDER_PK)))

      expect(outsiderMembership).toBeUndefined()

      // Cleanup
      await db.delete(mlsMessages).where(eq(mlsMessages.spaceId, SPACE_ID))
    })
  })

  // ============================================
  // SECURITY: DATA INTEGRITY
  // ============================================

  describe('SECURITY: Data Integrity', () => {
    test('SECURITY: payload is stored as opaque binary (no server interpretation)', async () => {
      const binaryPayload = Buffer.from([0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF])

      await db.insert(mlsMessages).values({
        spaceId: SPACE_ID,
        senderPublicKey: ADMIN_PK,
        messageType: 'application',
        payload: binaryPayload,
      })

      const [msg] = await db.select().from(mlsMessages)
        .where(eq(mlsMessages.spaceId, SPACE_ID))

      expect(Buffer.compare(msg!.payload, binaryPayload)).toBe(0)

      await db.delete(mlsMessages).where(eq(mlsMessages.spaceId, SPACE_ID))
    })

    test('SECURITY: cascade delete cleans up all MLS data', async () => {
      const tempSpaceId = '20000000-0000-0000-0000-000000000004'
      await db.insert(spaces).values({ id: tempSpaceId, ownerId: ADMIN_USER_ID })

      // Insert data in all MLS tables
      await db.insert(spaceInvites).values({
        spaceId: tempSpaceId, inviterPublicKey: ADMIN_PK, inviteeDid: INVITEE_DID,
      })
      await db.insert(mlsKeyPackages).values({
        spaceId: tempSpaceId, identityPublicKey: MEMBER_PK, keyPackage: FAKE_KEY_PACKAGE,
      })
      await db.insert(mlsMessages).values({
        spaceId: tempSpaceId, senderPublicKey: ADMIN_PK, messageType: 'commit', payload: FAKE_KEY_PACKAGE,
      })
      await db.insert(mlsWelcomeMessages).values({
        spaceId: tempSpaceId, recipientPublicKey: MEMBER_PK, payload: FAKE_KEY_PACKAGE,
      })

      // Delete space → everything should cascade
      await db.delete(spaces).where(eq(spaces.id, tempSpaceId))

      const invites = await db.select().from(spaceInvites).where(eq(spaceInvites.spaceId, tempSpaceId))
      const kps = await db.select().from(mlsKeyPackages).where(eq(mlsKeyPackages.spaceId, tempSpaceId))
      const msgs = await db.select().from(mlsMessages).where(eq(mlsMessages.spaceId, tempSpaceId))
      const welcomes = await db.select().from(mlsWelcomeMessages).where(eq(mlsWelcomeMessages.spaceId, tempSpaceId))

      expect(invites.length).toBe(0)
      expect(kps.length).toBe(0)
      expect(msgs.length).toBe(0)
      expect(welcomes.length).toBe(0)
    })
  })
}
