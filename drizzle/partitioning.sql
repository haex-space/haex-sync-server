-- ============================================================================
-- Unified Partitioning for sync_changes by space_id
-- ============================================================================
-- This file converts sync_changes to a LIST-partitioned table (one partition
-- per space). Run AFTER all Drizzle migrations via `npm run db:push`.
--
-- Key design:
-- - Every space (type='vault' or type='shared') gets its own partition
-- - Triggers on `spaces` INSERT/DELETE manage partitions automatically
-- - RLS policies differ by space type (vault vs shared)
-- - Realtime broadcast via direct INSERT into realtime.messages
--
-- This script is idempotent.
-- ============================================================================

-- ============================================================================
-- 1. Convert sync_changes to partitioned table (if not already)
-- ============================================================================

DO $$
DECLARE
    is_partitioned BOOLEAN;
    col_defs TEXT;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM pg_partitioned_table pt
        JOIN pg_class c ON c.oid = pt.partrelid
        WHERE c.relname = 'sync_changes'
    ) INTO is_partitioned;

    IF is_partitioned THEN
        RAISE NOTICE 'sync_changes is already partitioned, skipping conversion...';
        RETURN;
    END IF;

    RAISE NOTICE 'Converting sync_changes to partitioned table...';

    -- Build column definitions dynamically from existing table
    SELECT string_agg(
        format(
            '%I %s%s%s',
            column_name,
            CASE
                WHEN data_type = 'character varying' THEN 'varchar(' || character_maximum_length || ')'
                WHEN data_type = 'numeric' THEN 'numeric(' || numeric_precision || ',' || numeric_scale || ')'
                WHEN data_type = 'timestamp with time zone' THEN 'timestamptz'
                WHEN data_type = 'timestamp without time zone' THEN 'timestamp'
                WHEN data_type = 'USER-DEFINED' THEN udt_name
                ELSE data_type
            END,
            CASE
                WHEN column_default IS NOT NULL THEN ' DEFAULT ' || column_default
                ELSE ''
            END,
            CASE
                WHEN is_nullable = 'NO' THEN ' NOT NULL'
                ELSE ''
            END
        ),
        E',\n        '
        ORDER BY ordinal_position
    ) INTO col_defs
    FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'sync_changes';

    -- Drop indexes on old table
    DROP INDEX IF EXISTS "sync_changes_unique_cell";
    DROP INDEX IF EXISTS "sync_changes_user_space_idx";
    DROP INDEX IF EXISTS "sync_changes_hlc_idx";
    DROP INDEX IF EXISTS "sync_changes_updated_idx";
    DROP INDEX IF EXISTS "sync_changes_device_idx";

    -- Rename old table
    ALTER TABLE "sync_changes" RENAME TO "sync_changes_old";

    -- Drop constraints that reference the old table
    ALTER TABLE "sync_changes_old" DROP CONSTRAINT IF EXISTS "sync_changes_user_id_users_id_fk";
    ALTER TABLE "sync_changes_old" DROP CONSTRAINT IF EXISTS "sync_changes_space_id_spaces_id_fk";

    -- Create new partitioned table with dynamic column definitions
    -- PRIMARY KEY must include partition key for partitioned tables
    EXECUTE format(
        'CREATE TABLE "sync_changes" (
        %s,
        PRIMARY KEY ("id", "space_id")
    ) PARTITION BY LIST ("space_id")',
        col_defs
    );

    -- Create default partition (catches any space_id without its own partition)
    CREATE TABLE "sync_changes_default" PARTITION OF "sync_changes" DEFAULT;
    ALTER TABLE "sync_changes_default" ENABLE ROW LEVEL SECURITY;

    -- Add foreign key constraints
    ALTER TABLE "sync_changes" ADD CONSTRAINT "sync_changes_user_id_users_id_fk"
        FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;

    ALTER TABLE "sync_changes" ADD CONSTRAINT "sync_changes_space_id_spaces_id_fk"
        FOREIGN KEY ("space_id") REFERENCES "spaces"("id") ON DELETE CASCADE;

    -- Recreate indexes on the partitioned table
    CREATE UNIQUE INDEX IF NOT EXISTS "sync_changes_unique_cell"
        ON "sync_changes" ("space_id", "table_name", "row_pks", "column_name");
    CREATE INDEX IF NOT EXISTS "sync_changes_user_space_idx"
        ON "sync_changes" ("user_id", "space_id");
    CREATE INDEX IF NOT EXISTS "sync_changes_hlc_idx"
        ON "sync_changes" ("hlc_timestamp");
    CREATE INDEX IF NOT EXISTS "sync_changes_updated_idx"
        ON "sync_changes" ("updated_at");
    CREATE INDEX IF NOT EXISTS "sync_changes_device_idx"
        ON "sync_changes" ("device_id");

    -- Enable RLS on parent table
    ALTER TABLE "sync_changes" ENABLE ROW LEVEL SECURITY;

    -- Drop old table (fresh setup, no data migration needed)
    DROP TABLE "sync_changes_old";

    RAISE NOTICE 'Partitioning conversion complete.';
END $$;

-- ============================================================================
-- 2. Drop old triggers/functions that referenced vault_keys
-- ============================================================================

DROP TRIGGER IF EXISTS create_partition_on_vault_insert ON vault_keys;
DROP TRIGGER IF EXISTS drop_partition_on_vault_delete ON vault_keys;
DROP FUNCTION IF EXISTS create_sync_changes_partition();
DROP FUNCTION IF EXISTS drop_sync_changes_partition();

-- Drop old space-specific triggers/functions (replaced by unified ones)
DROP TRIGGER IF EXISTS create_space_partition_trigger ON spaces;
DROP TRIGGER IF EXISTS drop_space_partition_trigger ON spaces;
DROP FUNCTION IF EXISTS create_space_partition();
DROP FUNCTION IF EXISTS drop_space_partition();

-- ============================================================================
-- 3. Unified partition trigger: CREATE on spaces INSERT
-- ============================================================================

CREATE OR REPLACE FUNCTION create_sync_partition()
RETURNS TRIGGER
SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
    partition_name TEXT;
    space_type TEXT;
BEGIN
    partition_name := 'sync_changes_' || replace(NEW.id::text, '-', '_');
    space_type := NEW.type;

    -- Check if partition already exists
    IF NOT EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = partition_name AND n.nspname = 'public'
    ) THEN
        -- Create partition
        EXECUTE format(
            'CREATE TABLE public.%I PARTITION OF public.sync_changes FOR VALUES IN (%L)',
            partition_name, NEW.id::text
        );

        -- Enable RLS
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', partition_name);

        -- RLS policies differ by space type
        IF space_type = 'vault' THEN
            -- Vault: only the owner can read/write
            EXECUTE format(
                'CREATE POLICY "vault_select" ON public.%I FOR SELECT USING ((select auth.uid()) = user_id)',
                partition_name
            );
            EXECUTE format(
                'CREATE POLICY "vault_insert" ON public.%I FOR INSERT WITH CHECK ((select auth.uid()) = user_id)',
                partition_name
            );
        ELSIF space_type = 'shared' THEN
            -- Shared: members can read/write via identities -> space_members join
            EXECUTE format(
                'CREATE POLICY "space_select" ON public.%I FOR SELECT USING (
                    EXISTS (
                        SELECT 1 FROM public.identities i
                        JOIN public.space_members sm ON sm.public_key = i.public_key
                        WHERE i.supabase_user_id = (SELECT auth.uid())
                        AND sm.space_id = %L::uuid
                    )
                )', partition_name, NEW.id::text
            );
            EXECUTE format(
                'CREATE POLICY "space_insert" ON public.%I FOR INSERT WITH CHECK (
                    EXISTS (
                        SELECT 1 FROM public.identities i
                        JOIN public.space_members sm ON sm.public_key = i.public_key
                        WHERE i.supabase_user_id = (SELECT auth.uid())
                        AND sm.space_id = %L::uuid
                        AND sm.role IN (''member'', ''admin'', ''owner'')
                    )
                )', partition_name, NEW.id::text
            );
            EXECUTE format(
                'CREATE POLICY "space_update" ON public.%I FOR UPDATE USING (
                    EXISTS (
                        SELECT 1 FROM public.identities i
                        JOIN public.space_members sm ON sm.public_key = i.public_key
                        WHERE i.supabase_user_id = (SELECT auth.uid())
                        AND sm.space_id = %L::uuid
                        AND sm.role IN (''member'', ''admin'', ''owner'')
                    )
                )', partition_name, NEW.id::text
            );
        END IF;

        -- Realtime: set REPLICA IDENTITY and add to publication
        EXECUTE format('ALTER TABLE public.%I REPLICA IDENTITY FULL', partition_name);

        IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
            EXECUTE format('ALTER PUBLICATION supabase_realtime ADD TABLE public.%I', partition_name);
        END IF;

        RAISE NOTICE 'Created partition % for space % (type=%)', partition_name, NEW.id, space_type;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS create_sync_partition_trigger ON spaces;
CREATE TRIGGER create_sync_partition_trigger
    AFTER INSERT ON spaces
    FOR EACH ROW
    EXECUTE FUNCTION create_sync_partition();

-- ============================================================================
-- 4. Unified partition trigger: DROP on spaces DELETE
-- ============================================================================

CREATE OR REPLACE FUNCTION drop_sync_partition()
RETURNS TRIGGER
SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
    partition_name TEXT;
BEGIN
    partition_name := 'sync_changes_' || replace(OLD.id::text, '-', '_');
    EXECUTE format('DROP TABLE IF EXISTS public.%I', partition_name);
    RAISE NOTICE 'Dropped partition % for deleted space %', partition_name, OLD.id;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS drop_sync_partition_trigger ON spaces;
CREATE TRIGGER drop_sync_partition_trigger
    BEFORE DELETE ON spaces
    FOR EACH ROW
    EXECUTE FUNCTION drop_sync_partition();

-- ============================================================================
-- 5. Realtime broadcast trigger on sync_changes
-- ============================================================================
-- Uses direct INSERT into realtime.messages instead of postgres_changes.
-- PostgreSQL 15+ auto-clones row triggers on partitioned parent to all
-- existing and future child partitions.
-- ============================================================================

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'realtime' AND c.relname = 'messages'
    ) THEN
        CREATE OR REPLACE FUNCTION public.broadcast_sync_changes()
        RETURNS trigger
        SECURITY DEFINER SET search_path = ''
        AS $fn$
        BEGIN
            -- Minimal notification — no record data.
            -- The app uses this as a trigger to pull changes via the pull endpoint.
            -- All actual data is E2E-encrypted.
            INSERT INTO realtime.messages (topic, extension, event, payload, private)
            VALUES (
                'sync:' || COALESCE(NEW.space_id, OLD.space_id)::text,
                'broadcast',
                TG_OP,
                jsonb_build_object('op', TG_OP),
                true
            );
            RETURN NULL;
        END;
        $fn$ LANGUAGE plpgsql;

        DROP TRIGGER IF EXISTS broadcast_sync_changes_trigger ON public.sync_changes;
        CREATE TRIGGER broadcast_sync_changes_trigger
            AFTER INSERT OR UPDATE OR DELETE ON public.sync_changes
            FOR EACH ROW
            EXECUTE FUNCTION public.broadcast_sync_changes();

        RAISE NOTICE 'Realtime broadcast trigger created on sync_changes';

        -- ====================================================================
        -- 6. can_access_sync_channel() — broadcast authorization helper
        -- ====================================================================
        -- SECURITY DEFINER bypasses RLS to avoid infinite recursion
        -- (space_members has its own RLS that self-references).

        -- can_access_sync_channel removed: Supabase Realtime replaced by custom WebSocket

        -- Realtime RLS policies removed: Supabase Realtime replaced by custom WebSocket
        DROP POLICY IF EXISTS "authenticated can receive broadcasts" ON realtime.messages;
        DROP POLICY IF EXISTS "vault owner can receive sync broadcasts" ON realtime.messages;
        DROP POLICY IF EXISTS "sync participant can receive broadcasts" ON realtime.messages;
    ELSE
        RAISE NOTICE 'Skipping broadcast trigger: realtime.messages table not available';
    END IF;
END
$$;

-- ============================================================================
-- 8. Ensure RLS on all existing partitions (idempotent)
-- ============================================================================
-- Handles partitions that may have been created before RLS was configured.

DO $$
DECLARE
    partition_rec RECORD;
BEGIN
    FOR partition_rec IN
        SELECT c.relname AS partition_name
        FROM pg_inherits i
        JOIN pg_class c ON c.oid = i.inhrelid
        JOIN pg_class p ON p.oid = i.inhparent
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE p.relname = 'sync_changes' AND n.nspname = 'public'
    LOOP
        -- Enable RLS (idempotent — no error if already enabled)
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', partition_rec.partition_name);
    END LOOP;
END $$;
