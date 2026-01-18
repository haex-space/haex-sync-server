-- Storage Bucket Setup for haex Cloud Storage
-- This file is idempotent and can be re-run after changes
--
-- NOTE: With MinIO backend, we don't need Supabase storage bucket configuration.
-- The sync-server handles bucket creation via MinIO Admin API.
-- This file is kept for compatibility but does minimal setup.

-- ============================================
-- HELPER FUNCTIONS (for compatibility)
-- ============================================

-- Function: Get user's bucket name (used by quota API)
CREATE OR REPLACE FUNCTION public.get_user_bucket_name(p_user_id UUID)
RETURNS TEXT AS $$
  SELECT 'user-' || p_user_id::text;
$$ LANGUAGE sql IMMUTABLE;

-- Function: Get user storage quota info (simplified - returns fixed 10GB quota)
-- Actual enforcement is done by MinIO bucket quotas
CREATE OR REPLACE FUNCTION public.get_user_storage_quota(p_user_id UUID)
RETURNS TABLE(
  used_bytes BIGINT,
  quota_bytes BIGINT,
  tier_name TEXT,
  tier_slug TEXT
) AS $$
BEGIN
  -- Return fixed quota (MinIO handles actual enforcement)
  -- used_bytes will be fetched from MinIO via sync-server API
  RETURN QUERY SELECT
    0::BIGINT as used_bytes,
    10737418240::BIGINT as quota_bytes,  -- 10 GB
    'Free'::TEXT as tier_name,
    'free'::TEXT as tier_slug;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- ============================================
-- PERMISSIONS
-- ============================================

-- Grant execute on functions
GRANT EXECUTE ON FUNCTION public.get_user_bucket_name(UUID) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.get_user_storage_quota(UUID) TO authenticated, service_role;
