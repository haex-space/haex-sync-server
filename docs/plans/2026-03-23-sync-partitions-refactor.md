# sync_partitions Refactor — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the broken FK constraint on `sync_changes` with a `sync_partitions` registry table that cleanly supports both personal vaults and shared spaces, and fix the broken Space RLS policies.

**Architecture:** A new `sync_partitions` table acts as the single source of truth for all valid `vault_id` values. Both vault creation and space creation register in this table. `sync_changes.vault_id` gets an FK to `sync_partitions.id`. Space-partition RLS policies are rewritten to use `identities → space_members` joins (the old policies referenced the removed `user_id` column on `space_members`).

**Tech Stack:** PostgreSQL 15+ (list partitioning), Drizzle ORM, Supabase Auth (RLS with `auth.uid()`), Supabase Realtime (broadcast via `realtime.messages`)

---

## Current Bugs Being Fixed

1. **FK `sync_changes_vault_fk`** references `vault_keys(user_id, vault_id)` — breaks all inserts into space partitions
2. **Space-partition RLS policies** reference `space_members.user_id` which was renamed to `public_key` in migration 0021 — all space RLS is silently broken
3. **Space-partition RLS** uses `user_id = auth.uid()` but space access is via `public_key`, requiring a join through `identities`

## Design

### New Table: `sync_partitions`

```sql
CREATE TABLE sync_partitions (
    id TEXT PRIMARY KEY,           -- vault_id or space_id (matches sync_changes.vault_id)
    type TEXT NOT NULL,            -- 'vault' or 'space'
    owner_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### FK Chain

```
sync_changes.vault_id → sync_partitions.id (ON DELETE CASCADE)
```

When a `sync_partition` row is deleted, PostgreSQL cascades to all `sync_changes` rows in that partition. The partition table itself is dropped by the existing triggers.

### Registration Flow

- **Vault created** (`INSERT INTO vault_keys`): trigger also inserts into `sync_partitions(id=vault_id, type='vault', owner_id=user_id)`
- **Space created** (`INSERT INTO spaces`): trigger also inserts into `sync_partitions(id=space_id, type='space', owner_id=owner_id)`
- **Vault deleted**: trigger deletes from `sync_partitions` → FK cascades to `sync_changes` → trigger drops partition table
- **Space deleted**: trigger deletes from `sync_partitions` → FK cascades → trigger drops partition table

### RLS Helper Function

A single `SECURITY DEFINER` function used by both partition RLS and broadcast RLS:

```sql
CREATE FUNCTION public.can_access_sync_partition(p_user_id UUID, p_vault_id TEXT)
RETURNS boolean SECURITY DEFINER SET search_path = 'public' AS $$
BEGIN
    -- Personal vault: user owns a vault_key
    IF EXISTS (
        SELECT 1 FROM vault_keys
        WHERE user_id = p_user_id AND vault_id = p_vault_id
    ) THEN RETURN true; END IF;

    -- Shared space: user's identity is a space member
    IF EXISTS (
        SELECT 1 FROM identities i
        JOIN space_members sm ON sm.public_key = i.public_key
        WHERE i.supabase_user_id = p_user_id
        AND sm.space_id = p_vault_id::uuid
    ) THEN RETURN true; END IF;

    RETURN false;
EXCEPTION
    WHEN invalid_text_representation THEN RETURN false;
END;
$$ LANGUAGE plpgsql;
```

A write-access variant:

```sql
CREATE FUNCTION public.can_write_sync_partition(p_user_id UUID, p_vault_id TEXT)
RETURNS boolean SECURITY DEFINER SET search_path = 'public' AS $$
BEGIN
    -- Personal vault: owner can always write
    IF EXISTS (
        SELECT 1 FROM vault_keys
        WHERE user_id = p_user_id AND vault_id = p_vault_id
    ) THEN RETURN true; END IF;

    -- Shared space: only member/admin/owner roles can write
    IF EXISTS (
        SELECT 1 FROM identities i
        JOIN space_members sm ON sm.public_key = i.public_key
        WHERE i.supabase_user_id = p_user_id
        AND sm.space_id = p_vault_id::uuid
        AND sm.role IN ('member', 'admin', 'owner')
    ) THEN RETURN true; END IF;

    RETURN false;
EXCEPTION
    WHEN invalid_text_representation THEN RETURN false;
END;
$$ LANGUAGE plpgsql;
```

### Partition RLS (unified for vault and space partitions)

```sql
-- On parent table (inherited by all partitions):
CREATE POLICY sync_select ON sync_changes FOR SELECT
    USING (can_access_sync_partition((SELECT auth.uid()), vault_id));

CREATE POLICY sync_insert ON sync_changes FOR INSERT
    WITH CHECK (can_write_sync_partition((SELECT auth.uid()), vault_id));

CREATE POLICY sync_update ON sync_changes FOR UPDATE
    USING (can_write_sync_partition((SELECT auth.uid()), vault_id));
```

No more per-partition policies needed — the parent-level policies + helper functions handle everything.

---

## Tasks

### Task 1: Add `sync_partitions` table to schema

**Files:**
- Modify: `src/db/schema.ts`

Add the new table definition after `vaultKeys`:

```typescript
export const syncPartitions = pgTable("sync_partitions", {
  id: text("id").primaryKey(),
  type: text("type").notNull(), // 'vault' | 'space'
  ownerId: uuid("owner_id")
    .notNull()
    .references(() => authUsers.id, { onDelete: "cascade" }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});
```

**Commit:** `feat: add sync_partitions table to schema`

### Task 2: Generate Drizzle migration

**Run:** `cd /home/haex/Projekte/haex-sync-server && npx drizzle-kit generate`

Verify the generated migration creates the `sync_partitions` table.

**Commit:** `chore: generate sync_partitions migration`

### Task 3: Rewrite `partitioning.sql` from scratch

**Files:**
- Rewrite: `drizzle/partitioning.sql`

The file should contain these sections in order:

1. **Idempotent conversion** — convert `sync_changes` to partitioned table (keep existing logic but remove the `vault_keys` FK)
2. **Access helper functions** — `can_access_sync_partition()` and `can_write_sync_partition()` (SECURITY DEFINER)
3. **Parent-level RLS** — unified policies using the helper functions
4. **Parent-level FK** — `sync_changes.vault_id → sync_partitions.id ON DELETE CASCADE`
5. **Vault partition lifecycle** — create/drop triggers on `vault_keys` (also register/deregister in `sync_partitions`)
6. **Space partition lifecycle** — create/drop triggers on `spaces` (also register/deregister in `sync_partitions`)
7. **Broadcast trigger** — INSERT into `realtime.messages` with `private=true`, minimal payload
8. **Broadcast RLS** — policy on `realtime.messages` using `can_access_sync_partition()`

Key changes vs. current:
- Remove FK to `vault_keys(user_id, vault_id)` — replaced by FK to `sync_partitions(id)`
- Remove per-partition RLS policies — parent-level policies cover everything
- Fix space partition creation to NOT create broken `user_id`-based policies
- Vault trigger inserts into `sync_partitions` before creating partition
- Space trigger inserts into `sync_partitions` before creating partition
- Delete triggers remove from `sync_partitions` (cascade handles sync_changes cleanup)

**Commit:** `refactor: rewrite partitioning.sql with sync_partitions registry`

### Task 4: Update vault routes to register in `sync_partitions`

**Files:**
- Modify: `src/routes/sync.vaults.ts`

The trigger on `vault_keys` handles `sync_partitions` registration automatically (done in Task 3).
But `POST /partitions/create` (the ahead-of-time partition creation) also needs to insert into `sync_partitions`.

Find the `POST /partitions/create` handler and add:
```typescript
await db.insert(syncPartitions).values({
  id: partitionId,
  type: 'vault',
  ownerId: user.userId,
});
```

**Commit:** `feat: register ahead-of-time partitions in sync_partitions`

### Task 5: Update `isSpacePartition` to use `sync_partitions`

**Files:**
- Modify: `src/routes/sync.helpers.ts`

Replace the current `isSpacePartition` implementation:

```typescript
export async function isSpacePartition(vaultId: string): Promise<boolean> {
  const result = await db.select({ type: syncPartitions.type })
    .from(syncPartitions)
    .where(eq(syncPartitions.id, vaultId))
    .limit(1)
  return result[0]?.type === 'space'
}
```

This is cleaner — single table lookup instead of querying `spaces`.

**Commit:** `refactor: use sync_partitions for isSpacePartition lookup`

### Task 6: Update `migrate.ts` retry logic

**Files:**
- Modify: `scripts/migrate.ts`

The retry logic currently waits for `realtime.messages` table. Keep that, but also:
- Remove the `vault_keys_user_vault_unique` constraint promotion (no longer needed)
- The broadcast trigger check can stay as-is

**Commit:** `chore: update migrate.ts for new partitioning`

### Task 7: Fix E2E test infrastructure

**Files:**
- Modify: `docker/docker-compose.yml` (in haex-e2e-tests) — `GOTRUE_JWT_DEFAULT_GROUP_NAME` already added
- Modify: `tests/helpers/sync-server-helpers.ts` — replace `insertBroadcastMessage` (docker exec) with a DB-based approach or remove it entirely and use `signAndPushSpaceChanges`
- Modify: `tests/sync/realtime-auth-lifecycle.spec.ts` — fix test that expects public channels (now private)

**Commit:** `fix: update E2E tests for private broadcast channels`

### Task 8: Run full test suite locally

**Run:**
```bash
cd /home/haex/Projekte/haex-e2e-tests
# Start Docker stack with sync-server rebuild
HAEX_SYNC_SERVER_PATH=/home/haex/Projekte/haex-sync-server docker compose -f docker/docker-compose.yml build sync-server
# Start services...
# Run all realtime tests
SYNC_SERVER_DIRECT_URL=http://localhost:13002 SUPABASE_URL=http://localhost:18001 \
  npx playwright test tests/sync/realtime- tests/spaces/ --reporter=list --config=playwright.local.config.ts
```

All 37+ broadcast tests and all RBAC tests must pass.

**Commit:** `test: verify all tests pass with sync_partitions`

### Task 9: Release

```bash
cd /home/haex/Projekte/haex-sync-server && git push
cd /home/haex/Projekte/haex-e2e-tests && git push
cd /home/haex/Projekte/haex-vault && node scripts/release.js patch
```

---

## Risk Assessment

- **Data migration**: Existing partitions need to be backfilled into `sync_partitions`. The conversion block in `partitioning.sql` handles this by scanning existing vault_keys and spaces.
- **Rollback**: If something breaks, the old `partitioning.sql` can be restored. The `sync_partitions` table is additive — it doesn't break existing functionality if unused.
- **Performance**: The helper functions add one extra DB query per RLS check, but they use SECURITY DEFINER (no nested RLS evaluation) and hit indexed columns.

## Files Changed (Summary)

| File | Action | Repo |
|---|---|---|
| `src/db/schema.ts` | Add `syncPartitions` table | haex-sync-server |
| `drizzle/migrations/0029_*.sql` | Generated migration | haex-sync-server |
| `drizzle/partitioning.sql` | Complete rewrite | haex-sync-server |
| `src/routes/sync.vaults.ts` | Register in sync_partitions | haex-sync-server |
| `src/routes/sync.helpers.ts` | Use sync_partitions for lookup | haex-sync-server |
| `scripts/migrate.ts` | Update retry logic | haex-sync-server |
| `docker/docker-compose.yml` | GoTrue config fix | haex-e2e-tests |
| `tests/helpers/sync-server-helpers.ts` | Fix insertBroadcastMessage | haex-e2e-tests |
| `tests/sync/realtime-auth-lifecycle.spec.ts` | Fix public channel test | haex-e2e-tests |
