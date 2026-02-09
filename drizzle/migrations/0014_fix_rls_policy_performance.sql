-- Fix RLS policy performance issues
-- 1. Wrap auth.uid() and auth.role() in (select ...) for better query planning
-- 2. Fix multiple permissive policies on user_storage_credentials

-- ============================================
-- FIX user_storage_credentials POLICIES
-- ============================================

-- Drop old policies
DROP POLICY IF EXISTS "Users can read their own credentials" ON user_storage_credentials;
DROP POLICY IF EXISTS "Service role can manage credentials" ON user_storage_credentials;
DROP POLICY IF EXISTS "Service role can insert credentials" ON user_storage_credentials;
DROP POLICY IF EXISTS "Service role can update credentials" ON user_storage_credentials;
DROP POLICY IF EXISTS "Service role can delete credentials" ON user_storage_credentials;

-- Create optimized policies (no overlap between user and service role for same action)
CREATE POLICY "Users can read their own credentials"
  ON user_storage_credentials
  FOR SELECT
  USING ((select auth.uid()) = user_id OR (select auth.role()) = 'service_role');

CREATE POLICY "Service role can insert credentials"
  ON user_storage_credentials
  FOR INSERT
  WITH CHECK ((select auth.role()) = 'service_role');

CREATE POLICY "Service role can update credentials"
  ON user_storage_credentials
  FOR UPDATE
  USING ((select auth.role()) = 'service_role');

CREATE POLICY "Service role can delete credentials"
  ON user_storage_credentials
  FOR DELETE
  USING ((select auth.role()) = 'service_role');

-- ============================================
-- FIX sync_changes_default PARTITION POLICIES
-- ============================================

-- Drop and recreate policies on default partition with (select ...) wrapper
DROP POLICY IF EXISTS "Users can only access their own sync changes" ON sync_changes_default;
DROP POLICY IF EXISTS "Users can only insert their own sync changes" ON sync_changes_default;

CREATE POLICY "Users can only access their own sync changes"
  ON sync_changes_default
  FOR SELECT
  USING ((select auth.uid()) = user_id);

CREATE POLICY "Users can only insert their own sync changes"
  ON sync_changes_default
  FOR INSERT
  WITH CHECK ((select auth.uid()) = user_id);

-- ============================================
-- FIX ALL sync_changes PARTITIONS
-- ============================================

-- Update policies on all partitions to use (select auth.uid())
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
        -- Drop old policies
        EXECUTE format(
            'DROP POLICY IF EXISTS "Users can only access their own sync changes" ON public.%I',
            partition_rec.partition_name
        );
        EXECUTE format(
            'DROP POLICY IF EXISTS "Users can only insert their own sync changes" ON public.%I',
            partition_rec.partition_name
        );

        -- Create optimized policies
        EXECUTE format(
            'CREATE POLICY "Users can only access their own sync changes" ON public.%I FOR SELECT USING ((select auth.uid()) = user_id)',
            partition_rec.partition_name
        );
        EXECUTE format(
            'CREATE POLICY "Users can only insert their own sync changes" ON public.%I FOR INSERT WITH CHECK ((select auth.uid()) = user_id)',
            partition_rec.partition_name
        );

        RAISE NOTICE 'Fixed RLS policies on partition %', partition_rec.partition_name;
    END LOOP;
END $$;
