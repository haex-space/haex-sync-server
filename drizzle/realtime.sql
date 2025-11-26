-- Enable Supabase Realtime for sync_changes table and all its partitions
-- This file is idempotent and can be re-run after schema changes or new partitions
--
-- For partitioned tables, Realtime events are fired from the partitions, not the parent table.
-- This script configures both the parent table and all existing partitions.

-- Set REPLICA IDENTITY to FULL on parent table (inherited by new partitions in some cases)
ALTER TABLE "sync_changes" REPLICA IDENTITY FULL;

-- Configure all partitions for Realtime
DO $$
DECLARE
    partition_record RECORD;
BEGIN
    -- Loop through all partitions of sync_changes
    FOR partition_record IN
        SELECT c.relname as partition_name
        FROM pg_inherits i
        JOIN pg_class c ON c.oid = i.inhrelid
        JOIN pg_class p ON p.oid = i.inhparent
        WHERE p.relname = 'sync_changes'
    LOOP
        -- Set REPLICA IDENTITY FULL on each partition
        EXECUTE format('ALTER TABLE %I REPLICA IDENTITY FULL', partition_record.partition_name);
        RAISE NOTICE 'Set REPLICA IDENTITY FULL on partition %', partition_record.partition_name;

        -- Add partition to publication if not already added
        IF NOT EXISTS (
            SELECT 1 FROM pg_publication_tables
            WHERE pubname = 'supabase_realtime'
            AND tablename = partition_record.partition_name
        ) THEN
            EXECUTE format('ALTER PUBLICATION supabase_realtime ADD TABLE %I', partition_record.partition_name);
            RAISE NOTICE 'Added partition % to supabase_realtime publication', partition_record.partition_name;
        END IF;
    END LOOP;
END $$;
