-- Enable List Partitioning for sync_changes table
-- This file converts sync_changes to a partitioned table with one partition per vault_id
-- Run this AFTER all drizzle migrations are applied
--
-- Benefits:
-- - Queries on a single vault only scan that partition
-- - Deleting a vault = DROP TABLE (instant, no vacuum needed)
-- - Each partition can be backed up/restored independently
--
-- Security:
-- - RLS is enabled on the parent table AND on each partition
-- - PostgreSQL requires RLS to be enabled on each partition separately
-- - The trigger function also enables RLS when creating new partitions
--
-- This script is idempotent - it checks if partitioning is already enabled
-- It dynamically reads the table structure from Drizzle's schema (DRY principle)

DO $$
DECLARE
    v_id TEXT;
    partition_name TEXT;
    is_partitioned BOOLEAN;
    col_defs TEXT;
BEGIN
    -- Check if table is already partitioned
    SELECT EXISTS (
        SELECT 1 FROM pg_partitioned_table pt
        JOIN pg_class c ON c.oid = pt.partrelid
        WHERE c.relname = 'sync_changes'
    ) INTO is_partitioned;

    IF is_partitioned THEN
        RAISE NOTICE 'sync_changes is already partitioned, skipping...';
        RETURN;
    END IF;

    RAISE NOTICE 'Converting sync_changes to partitioned table...';

    -- Step 1: Build column definitions dynamically from existing table
    SELECT string_agg(
        format(
            '%I %s%s%s',
            column_name,
            -- Full type with precision
            CASE
                WHEN data_type = 'character varying' THEN 'varchar(' || character_maximum_length || ')'
                WHEN data_type = 'numeric' THEN 'numeric(' || numeric_precision || ',' || numeric_scale || ')'
                WHEN data_type = 'timestamp with time zone' THEN 'timestamptz'
                WHEN data_type = 'timestamp without time zone' THEN 'timestamp'
                WHEN data_type = 'USER-DEFINED' THEN udt_name
                ELSE data_type
            END,
            -- Default value
            CASE
                WHEN column_default IS NOT NULL THEN ' DEFAULT ' || column_default
                ELSE ''
            END,
            -- NOT NULL constraint
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

    -- Step 2: Drop indexes on old table (they will be recreated on the partitioned table)
    DROP INDEX IF EXISTS "sync_changes_unique_cell";
    DROP INDEX IF EXISTS "sync_changes_user_vault_idx";
    DROP INDEX IF EXISTS "sync_changes_hlc_idx";
    DROP INDEX IF EXISTS "sync_changes_updated_idx";
    DROP INDEX IF EXISTS "sync_changes_device_idx";

    -- Step 3: Rename old table
    ALTER TABLE "sync_changes" RENAME TO "sync_changes_old";

    -- Step 4: Drop constraints that reference the old table
    ALTER TABLE "sync_changes_old" DROP CONSTRAINT IF EXISTS "sync_changes_user_id_users_id_fk";

    -- Step 5: Create new partitioned table with dynamic column definitions
    -- Note: PRIMARY KEY must include partition key for partitioned tables
    EXECUTE format(
        'CREATE TABLE "sync_changes" (
        %s,
        PRIMARY KEY ("id", "vault_id")
    ) PARTITION BY LIST ("vault_id")',
        col_defs
    );

    -- Step 5: Create default partition for safety (catches any vault_id without its own partition)
    CREATE TABLE "sync_changes_default" PARTITION OF "sync_changes" DEFAULT;
    -- Enable RLS on default partition
    ALTER TABLE "sync_changes_default" ENABLE ROW LEVEL SECURITY;
    -- Create RLS policies on default partition
    CREATE POLICY "Users can only access their own sync changes" ON "sync_changes_default" FOR SELECT USING ((select auth.uid()) = user_id);
    CREATE POLICY "Users can only insert their own sync changes" ON "sync_changes_default" FOR INSERT WITH CHECK ((select auth.uid()) = user_id);

    -- Step 6: Create partitions for existing vault_ids and migrate data
    FOR v_id IN SELECT DISTINCT vault_id FROM sync_changes_old
    LOOP
        -- Generate safe partition name (replace hyphens with underscores)
        partition_name := 'sync_changes_' || replace(v_id, '-', '_');

        RAISE NOTICE 'Creating partition % for vault %', partition_name, v_id;

        -- Create partition for this vault_id
        EXECUTE format(
            'CREATE TABLE %I PARTITION OF sync_changes FOR VALUES IN (%L)',
            partition_name,
            v_id
        );

        -- Enable RLS on the partition (required for each partition separately)
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', partition_name);

        -- Move data to the new partition
        EXECUTE format(
            'INSERT INTO sync_changes SELECT * FROM sync_changes_old WHERE vault_id = %L',
            v_id
        );
    END LOOP;

    -- Step 7: Add foreign key constraint to auth.users
    ALTER TABLE "sync_changes" ADD CONSTRAINT "sync_changes_user_id_users_id_fk"
        FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;

    -- Step 8: Add foreign key constraint to vault_keys (user_id, vault_id)
    -- First ensure vault_keys has the unique constraint (convert index to constraint if needed)
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'vault_keys_user_vault_unique'
    ) THEN
        -- The unique index exists, convert it to a constraint
        ALTER TABLE "vault_keys" ADD CONSTRAINT "vault_keys_user_vault_unique"
            UNIQUE USING INDEX "vault_keys_user_vault_idx";
    END IF;

    -- Now add the foreign key from sync_changes to vault_keys
    ALTER TABLE "sync_changes" ADD CONSTRAINT "sync_changes_vault_fk"
        FOREIGN KEY ("user_id", "vault_id") REFERENCES "vault_keys"("user_id", "vault_id") ON DELETE CASCADE;

    -- Step 9: Recreate indexes on the partitioned table (IF NOT EXISTS for idempotency)
    CREATE UNIQUE INDEX IF NOT EXISTS "sync_changes_unique_cell" ON "sync_changes" ("vault_id", "table_name", "row_pks", "column_name");
    CREATE INDEX IF NOT EXISTS "sync_changes_user_vault_idx" ON "sync_changes" ("user_id", "vault_id");
    CREATE INDEX IF NOT EXISTS "sync_changes_hlc_idx" ON "sync_changes" ("hlc_timestamp");
    CREATE INDEX IF NOT EXISTS "sync_changes_updated_idx" ON "sync_changes" ("updated_at");
    CREATE INDEX IF NOT EXISTS "sync_changes_device_idx" ON "sync_changes" ("device_id");

    -- Step 10: Re-enable RLS
    ALTER TABLE "sync_changes" ENABLE ROW LEVEL SECURITY;

    -- Step 11: Recreate RLS policies
    CREATE POLICY "Users can only access their own sync changes"
        ON sync_changes FOR SELECT
        USING ((select auth.uid()) = user_id);

    CREATE POLICY "Users can only insert their own sync changes"
        ON sync_changes FOR INSERT
        WITH CHECK ((select auth.uid()) = user_id);

    -- Step 12: Drop old table
    -- Note: Realtime configuration is handled by db:realtime script
    DROP TABLE "sync_changes_old";

    RAISE NOTICE 'Partitioning complete!';
END $$;

-- Create function to automatically create partition for new vaults
CREATE OR REPLACE FUNCTION create_sync_changes_partition()
RETURNS TRIGGER AS $$
DECLARE
    partition_name TEXT;
BEGIN
    -- Generate safe partition name
    partition_name := 'sync_changes_' || replace(NEW.vault_id, '-', '_');

    -- Check if partition already exists
    IF NOT EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = partition_name AND n.nspname = 'public'
    ) THEN
        -- Create new partition (explicit public schema to avoid search_path issues)
        EXECUTE format(
            'CREATE TABLE public.%I PARTITION OF public.sync_changes FOR VALUES IN (%L)',
            partition_name,
            NEW.vault_id
        );

        -- Enable RLS on the new partition
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', partition_name);

        -- Create RLS policies on partition (policies are NOT inherited from parent!)
        EXECUTE format(
            'CREATE POLICY "Users can only access their own sync changes" ON public.%I FOR SELECT USING ((select auth.uid()) = user_id)',
            partition_name
        );
        EXECUTE format(
            'CREATE POLICY "Users can only insert their own sync changes" ON public.%I FOR INSERT WITH CHECK ((select auth.uid()) = user_id)',
            partition_name
        );

        -- Configure Realtime for the new partition
        EXECUTE format('ALTER TABLE public.%I REPLICA IDENTITY FULL', partition_name);

        -- Add to supabase_realtime publication if it exists
        -- Note: Partitions should be pre-created via the /partitions/create API endpoint
        -- so that Realtime has time to pick them up before the first subscription.
        -- This trigger is a fallback for partitions created via vault_keys INSERT.
        IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
            EXECUTE format('ALTER PUBLICATION supabase_realtime ADD TABLE public.%I', partition_name);
        END IF;

        RAISE NOTICE 'Created partition % for new vault % (with RLS, policies, and Realtime enabled)', partition_name, NEW.vault_id;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SET search_path = '';

-- Create trigger to auto-create partition when vault is created (idempotent)
DROP TRIGGER IF EXISTS create_partition_on_vault_insert ON vault_keys;
CREATE TRIGGER create_partition_on_vault_insert
    AFTER INSERT ON vault_keys
    FOR EACH ROW
    EXECUTE FUNCTION create_sync_changes_partition();

-- Create function to drop partition when vault is deleted
CREATE OR REPLACE FUNCTION drop_sync_changes_partition()
RETURNS TRIGGER AS $$
DECLARE
    partition_name TEXT;
BEGIN
    -- Generate partition name
    partition_name := 'sync_changes_' || replace(OLD.vault_id, '-', '_');

    -- Drop partition if it exists
    IF EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = partition_name AND n.nspname = 'public'
    ) THEN
        EXECUTE format('DROP TABLE public.%I', partition_name);
        RAISE NOTICE 'Dropped partition % for deleted vault %', partition_name, OLD.vault_id;
    END IF;

    RETURN OLD;
END;
$$ LANGUAGE plpgsql SET search_path = '';

-- Create trigger to drop partition when vault is deleted (idempotent)
DROP TRIGGER IF EXISTS drop_partition_on_vault_delete ON vault_keys;
CREATE TRIGGER drop_partition_on_vault_delete
    BEFORE DELETE ON vault_keys
    FOR EACH ROW
    EXECUTE FUNCTION drop_sync_changes_partition();

-- Ensure RLS policies exist on all partitions (idempotent - runs on every startup)
-- This handles partitions that were created before policies were added
DO $$
DECLARE
    partition_rec RECORD;
    policy_exists BOOLEAN;
BEGIN
    -- Find all partitions of sync_changes
    FOR partition_rec IN
        SELECT c.relname AS partition_name
        FROM pg_inherits i
        JOIN pg_class c ON c.oid = i.inhrelid
        JOIN pg_class p ON p.oid = i.inhparent
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE p.relname = 'sync_changes' AND n.nspname = 'public'
    LOOP
        -- Check if SELECT policy exists
        SELECT EXISTS (
            SELECT 1 FROM pg_policy pol
            JOIN pg_class c ON c.oid = pol.polrelid
            WHERE c.relname = partition_rec.partition_name
            AND pol.polname = 'Users can only access their own sync changes'
        ) INTO policy_exists;

        IF NOT policy_exists THEN
            EXECUTE format(
                'CREATE POLICY "Users can only access their own sync changes" ON public.%I FOR SELECT USING ((select auth.uid()) = user_id)',
                partition_rec.partition_name
            );
            RAISE NOTICE 'Added SELECT policy to partition %', partition_rec.partition_name;
        END IF;

        -- Check if INSERT policy exists
        SELECT EXISTS (
            SELECT 1 FROM pg_policy pol
            JOIN pg_class c ON c.oid = pol.polrelid
            WHERE c.relname = partition_rec.partition_name
            AND pol.polname = 'Users can only insert their own sync changes'
        ) INTO policy_exists;

        IF NOT policy_exists THEN
            EXECUTE format(
                'CREATE POLICY "Users can only insert their own sync changes" ON public.%I FOR INSERT WITH CHECK ((select auth.uid()) = user_id)',
                partition_rec.partition_name
            );
            RAISE NOTICE 'Added INSERT policy to partition %', partition_rec.partition_name;
        END IF;
    END LOOP;
END $$;

-- =============================================
-- SHARED SPACES PARTITIONING
-- =============================================

-- Auto-create partition when a space is created
CREATE OR REPLACE FUNCTION create_space_partition()
RETURNS TRIGGER AS $$
DECLARE
  partition_name TEXT;
  safe_space_id TEXT;
BEGIN
  safe_space_id := replace(NEW.id::text, '-', '_');
  partition_name := 'sync_changes_space_' || safe_space_id;

  IF NOT EXISTS (
    SELECT 1 FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relname = partition_name AND n.nspname = 'public'
  ) THEN
    EXECUTE format(
      'CREATE TABLE public.%I PARTITION OF public.sync_changes FOR VALUES IN (%L)',
      partition_name, NEW.id::text
    );

    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', partition_name);

    -- SELECT: any space member can read
    EXECUTE format(
      'CREATE POLICY space_select ON public.%I FOR SELECT USING (
        EXISTS (
          SELECT 1 FROM public.space_members
          WHERE space_id = %L AND user_id = (SELECT auth.uid())
        )
      )', partition_name, NEW.id::text
    );

    -- INSERT: member or admin can write
    EXECUTE format(
      'CREATE POLICY space_insert ON public.%I FOR INSERT WITH CHECK (
        EXISTS (
          SELECT 1 FROM public.space_members
          WHERE space_id = %L AND user_id = (SELECT auth.uid())
          AND role IN (''member'', ''admin'')
        )
      )', partition_name, NEW.id::text
    );

    -- UPDATE: member or admin can update (record ownership checked at application level)
    EXECUTE format(
      'CREATE POLICY space_update ON public.%I FOR UPDATE USING (
        EXISTS (
          SELECT 1 FROM public.space_members
          WHERE space_id = %L AND user_id = (SELECT auth.uid())
          AND role IN (''member'', ''admin'')
        )
      )', partition_name, NEW.id::text
    );

    EXECUTE format('ALTER TABLE public.%I REPLICA IDENTITY FULL', partition_name);

    IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
      EXECUTE format('ALTER PUBLICATION supabase_realtime ADD TABLE public.%I', partition_name);
    END IF;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = '';

-- Drop and recreate trigger to be idempotent
DROP TRIGGER IF EXISTS create_space_partition_trigger ON spaces;
CREATE TRIGGER create_space_partition_trigger
  AFTER INSERT ON spaces
  FOR EACH ROW
  EXECUTE FUNCTION create_space_partition();

-- Auto-drop partition when space is deleted
CREATE OR REPLACE FUNCTION drop_space_partition()
RETURNS TRIGGER AS $$
DECLARE
  partition_name TEXT;
BEGIN
  partition_name := 'sync_changes_space_' || replace(OLD.id::text, '-', '_');
  EXECUTE format('DROP TABLE IF EXISTS public.%I', partition_name);
  RETURN OLD;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = '';

DROP TRIGGER IF EXISTS drop_space_partition_trigger ON spaces;
CREATE TRIGGER drop_space_partition_trigger
  BEFORE DELETE ON spaces
  FOR EACH ROW
  EXECUTE FUNCTION drop_space_partition();

-- ============================================================================
-- Realtime Broadcast Trigger
-- ============================================================================
-- Instead of using postgres_changes (which requires each partition to be in
-- the supabase_realtime publication and causes cache staleness issues),
-- we use realtime.broadcast_changes() which writes to realtime.messages.
-- This table is ALWAYS in the Realtime publication — no restart needed.
--
-- PostgreSQL 15+ automatically clones row triggers on partitioned parent
-- tables to ALL existing and future child partitions.
-- ============================================================================

-- Create broadcast trigger that inserts directly into realtime.messages.
-- We use a direct INSERT instead of realtime.broadcast_changes() because
-- broadcast_changes() sets private=true which requires additional RLS
-- configuration that varies across environments. Direct INSERT with
-- private=false works universally with any authenticated Realtime client.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'realtime' AND c.relname = 'messages'
    ) THEN
        -- Create trigger function that inserts into realtime.messages directly
        CREATE OR REPLACE FUNCTION public.broadcast_sync_changes()
        RETURNS trigger
        SECURITY DEFINER SET search_path = ''
        AS $fn$
        BEGIN
            -- Only send a minimal notification — no record data.
            -- The app uses this purely as a trigger to pull changes
            -- from the server. All actual data is E2E-encrypted and
            -- delivered via the pull endpoint.
            INSERT INTO realtime.messages (topic, extension, event, payload, private)
            VALUES (
                'sync:' || COALESCE(NEW.vault_id, OLD.vault_id)::text,
                'broadcast',
                TG_OP,
                jsonb_build_object('op', TG_OP),
                true
            );
            RETURN NULL;
        END;
        $fn$ LANGUAGE plpgsql;

        -- Create trigger on parent table (auto-cloned to all partitions by PG15)
        DROP TRIGGER IF EXISTS broadcast_sync_changes_trigger ON public.sync_changes;
        CREATE TRIGGER broadcast_sync_changes_trigger
            AFTER INSERT OR UPDATE OR DELETE ON public.sync_changes
            FOR EACH ROW
            EXECUTE FUNCTION public.broadcast_sync_changes();

        RAISE NOTICE 'Realtime broadcast trigger created on sync_changes';

        -- Helper function for broadcast authorization.
        -- SECURITY DEFINER bypasses RLS on vault_keys/space_members
        -- to avoid infinite recursion (space_members has its own RLS
        -- that self-references, causing recursion when called from
        -- another RLS policy).
        CREATE OR REPLACE FUNCTION public.can_access_sync_channel(
            p_user_id uuid,
            p_channel_topic text
        ) RETURNS boolean
        SECURITY DEFINER SET search_path = 'public'
        AS $authfn$
        DECLARE
            v_vault_id text;
        BEGIN
            v_vault_id := split_part(p_channel_topic, ':', 2);
            IF v_vault_id = '' OR v_vault_id IS NULL THEN
                RETURN false;
            END IF;

            -- Check 1: personal vault ownership
            IF EXISTS (
                SELECT 1 FROM vault_keys
                WHERE user_id = p_user_id
                AND vault_id = v_vault_id
            ) THEN
                RETURN true;
            END IF;

            -- Check 2: shared space membership (via identity → space_members)
            IF EXISTS (
                SELECT 1 FROM identities i
                JOIN space_members sm ON sm.public_key = i.public_key
                WHERE i.supabase_user_id = p_user_id
                AND sm.space_id = v_vault_id::uuid
            ) THEN
                RETURN true;
            END IF;

            RETURN false;
        EXCEPTION
            -- uuid cast may fail for non-uuid vault_ids (personal vaults)
            WHEN invalid_text_representation THEN
                RETURN false;
        END;
        $authfn$ LANGUAGE plpgsql;

        -- RLS policy for private broadcast channels.
        -- Uses the SECURITY DEFINER helper to avoid RLS recursion.
        DROP POLICY IF EXISTS "authenticated can receive broadcasts" ON realtime.messages;
        DROP POLICY IF EXISTS "vault owner can receive sync broadcasts" ON realtime.messages;
        DROP POLICY IF EXISTS "sync participant can receive broadcasts" ON realtime.messages;
        CREATE POLICY "sync participant can receive broadcasts"
            ON realtime.messages FOR SELECT TO authenticated
            USING (
                realtime.messages.extension = 'broadcast'
                AND public.can_access_sync_channel(
                    (select auth.uid()),
                    realtime.topic()
                )
            );
    ELSE
        RAISE NOTICE 'Skipping broadcast trigger: realtime.messages table not available';
    END IF;
END
$$;
