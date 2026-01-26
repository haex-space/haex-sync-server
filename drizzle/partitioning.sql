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
    CREATE POLICY "Users can only access their own sync changes" ON "sync_changes_default" FOR SELECT USING (auth.uid() = user_id);
    CREATE POLICY "Users can only insert their own sync changes" ON "sync_changes_default" FOR INSERT WITH CHECK (auth.uid() = user_id);

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
        USING (auth.uid() = user_id);

    CREATE POLICY "Users can only insert their own sync changes"
        ON sync_changes FOR INSERT
        WITH CHECK (auth.uid() = user_id);

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
        -- Create new partition
        EXECUTE format(
            'CREATE TABLE %I PARTITION OF sync_changes FOR VALUES IN (%L)',
            partition_name,
            NEW.vault_id
        );

        -- Enable RLS on the new partition
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', partition_name);

        -- Create RLS policies on partition (policies are NOT inherited from parent!)
        EXECUTE format(
            'CREATE POLICY "Users can only access their own sync changes" ON %I FOR SELECT USING (auth.uid() = user_id)',
            partition_name
        );
        EXECUTE format(
            'CREATE POLICY "Users can only insert their own sync changes" ON %I FOR INSERT WITH CHECK (auth.uid() = user_id)',
            partition_name
        );

        -- Configure Realtime for the new partition
        EXECUTE format('ALTER TABLE %I REPLICA IDENTITY FULL', partition_name);

        -- Add to supabase_realtime publication if it exists
        IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
            EXECUTE format('ALTER PUBLICATION supabase_realtime ADD TABLE %I', partition_name);
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
        EXECUTE format('DROP TABLE %I', partition_name);
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
                'CREATE POLICY "Users can only access their own sync changes" ON %I FOR SELECT USING (auth.uid() = user_id)',
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
                'CREATE POLICY "Users can only insert their own sync changes" ON %I FOR INSERT WITH CHECK (auth.uid() = user_id)',
                partition_rec.partition_name
            );
            RAISE NOTICE 'Added INSERT policy to partition %', partition_rec.partition_name;
        END IF;
    END LOOP;
END $$;
