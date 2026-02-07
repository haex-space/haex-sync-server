-- Enable Row Level Security on sync tables and all partitions
-- This file is idempotent and can be re-run after schema changes or new partitions
--
-- For partitioned tables, RLS policies on the parent table are automatically
-- inherited by partitions, but RLS must be explicitly enabled on each partition.

ALTER TABLE vault_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE sync_changes ENABLE ROW LEVEL SECURITY;

-- Drop existing policies if any (to allow re-running this file)
DROP POLICY IF EXISTS "Users can only access their own vault keys" ON vault_keys;
DROP POLICY IF EXISTS "Users can only insert their own vault keys" ON vault_keys;
DROP POLICY IF EXISTS "Users can only update their own vault keys" ON vault_keys;
DROP POLICY IF EXISTS "Users can only delete their own vault keys" ON vault_keys;
DROP POLICY IF EXISTS "Users can only access their own sync changes" ON sync_changes;
DROP POLICY IF EXISTS "Users can only insert their own sync changes" ON sync_changes;

-- Vault Keys Policies
CREATE POLICY "Users can only access their own vault keys"
  ON vault_keys
  FOR SELECT
  USING ((select auth.uid()) = user_id);

CREATE POLICY "Users can only insert their own vault keys"
  ON vault_keys
  FOR INSERT
  WITH CHECK ((select auth.uid()) = user_id);

CREATE POLICY "Users can only update their own vault keys"
  ON vault_keys
  FOR UPDATE
  USING ((select auth.uid()) = user_id)
  WITH CHECK ((select auth.uid()) = user_id);

CREATE POLICY "Users can only delete their own vault keys"
  ON vault_keys
  FOR DELETE
  USING ((select auth.uid()) = user_id);

-- Sync Changes Policies (on parent table - inherited by partitions)
CREATE POLICY "Users can only access their own sync changes"
  ON sync_changes
  FOR SELECT
  USING ((select auth.uid()) = user_id);

CREATE POLICY "Users can only insert their own sync changes"
  ON sync_changes
  FOR INSERT
  WITH CHECK ((select auth.uid()) = user_id);

-- Note: No UPDATE or DELETE policies for sync_changes - they are append-only

-- Enable RLS on all sync_changes partitions
DO $$
DECLARE
    partition_record RECORD;
BEGIN
    FOR partition_record IN
        SELECT c.relname as partition_name
        FROM pg_inherits i
        JOIN pg_class c ON c.oid = i.inhrelid
        JOIN pg_class p ON p.oid = i.inhparent
        WHERE p.relname = 'sync_changes'
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', partition_record.partition_name);
        RAISE NOTICE 'Enabled RLS on partition %', partition_record.partition_name;
    END LOOP;
END $$;

-- ============================================
-- USER STORAGE CREDENTIALS RLS
-- ============================================

ALTER TABLE user_storage_credentials ENABLE ROW LEVEL SECURITY;

-- Drop existing policies if any
DROP POLICY IF EXISTS "Users can read their own credentials" ON user_storage_credentials;
DROP POLICY IF EXISTS "Service role can manage credentials" ON user_storage_credentials;

-- Users can only read their own credentials
CREATE POLICY "Users can read their own credentials"
  ON user_storage_credentials
  FOR SELECT
  USING ((select auth.uid()) = user_id);

-- Service role can manage all credentials (for creation via sync-server)
CREATE POLICY "Service role can manage credentials"
  ON user_storage_credentials
  FOR ALL
  USING (auth.role() = 'service_role');
