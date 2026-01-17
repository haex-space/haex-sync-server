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
-- STORAGE QUOTA TABLES RLS
-- ============================================

ALTER TABLE storage_tiers ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_storage_quotas ENABLE ROW LEVEL SECURITY;

-- Drop existing policies if any
DROP POLICY IF EXISTS "Anyone can read storage tiers" ON storage_tiers;
DROP POLICY IF EXISTS "Users can read their own quota" ON user_storage_quotas;
DROP POLICY IF EXISTS "Service role can manage quotas" ON user_storage_quotas;

-- Storage Tiers: Public read access (anyone can see available tiers)
CREATE POLICY "Anyone can read storage tiers"
  ON storage_tiers
  FOR SELECT
  USING (true);

-- User Storage Quotas: Users can only read their own quota
CREATE POLICY "Users can read their own quota"
  ON user_storage_quotas
  FOR SELECT
  USING ((select auth.uid()) = user_id);

-- Service role can manage all quotas (for admin and auto-creation)
CREATE POLICY "Service role can manage quotas"
  ON user_storage_quotas
  FOR ALL
  USING (auth.role() = 'service_role');

-- ============================================
-- STORAGE TIERS SEED DATA
-- ============================================

-- Insert default storage tiers (idempotent via ON CONFLICT)
INSERT INTO storage_tiers (name, slug, quota_bytes, price_monthly_euro_cents, is_default, sort_order) VALUES
  ('Free', 'free', 10737418240, NULL, TRUE, 0),            -- 10 GB
  ('Basic', 'basic', 53687091200, NULL, FALSE, 1),         -- 50 GB
  ('Standard', 'standard', 107374182400, NULL, FALSE, 2),  -- 100 GB
  ('Plus', 'plus', 214748364800, NULL, FALSE, 3),          -- 200 GB
  ('Pro', 'pro', 536870912000, NULL, FALSE, 4),            -- 500 GB
  ('Business', 'business', 1099511627776, NULL, FALSE, 5), -- 1 TB
  ('Enterprise', 'enterprise', 2199023255552, NULL, FALSE, 6) -- 2 TB
ON CONFLICT (slug) DO NOTHING;
