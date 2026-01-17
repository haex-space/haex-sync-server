-- Storage Bucket Setup for haex Cloud Storage
-- This file is idempotent and can be re-run after changes
--
-- Creates the user-files bucket and configures RLS policies
-- for quota enforcement on uploads

-- ============================================
-- STORAGE BUCKET
-- ============================================

-- Create bucket for user files (if not exists)
INSERT INTO storage.buckets (id, name, public, file_size_limit)
VALUES ('user-files', 'user-files', FALSE, 52428800)  -- 50MB per file
ON CONFLICT (id) DO NOTHING;

-- ============================================
-- HELPER FUNCTIONS
-- ============================================

-- Function: Calculate used bytes from storage.objects
CREATE OR REPLACE FUNCTION public.calculate_user_storage_usage(p_user_id UUID)
RETURNS BIGINT AS $$
  SELECT COALESCE(SUM((metadata->>'size')::BIGINT), 0)
  FROM storage.objects
  WHERE bucket_id = 'user-files'
    AND (storage.foldername(name))[1] = p_user_id::text;
$$ LANGUAGE sql STABLE SECURITY DEFINER;

-- Function: Check if upload is allowed (for RLS policy)
CREATE OR REPLACE FUNCTION public.check_storage_quota(p_user_id UUID, p_file_size BIGINT)
RETURNS BOOLEAN AS $$
DECLARE
  v_quota BIGINT;
  v_used BIGINT;
BEGIN
  -- Get quota (admin_override takes priority)
  SELECT COALESCE(usq.admin_override_bytes, st.quota_bytes)
  INTO v_quota
  FROM public.user_storage_quotas usq
  JOIN public.storage_tiers st ON st.id = usq.tier_id
  WHERE usq.user_id = p_user_id;

  -- If no quota record exists, use default tier quota
  IF v_quota IS NULL THEN
    SELECT quota_bytes INTO v_quota
    FROM public.storage_tiers
    WHERE is_default = TRUE;
  END IF;

  -- Fallback to 10GB if still NULL
  IF v_quota IS NULL THEN
    v_quota := 10737418240; -- 10 GB
  END IF;

  -- Get current usage
  v_used := public.calculate_user_storage_usage(p_user_id);

  -- Check if upload fits
  RETURN (v_used + COALESCE(p_file_size, 0)) <= v_quota;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- Function: Get user quota info (for API)
CREATE OR REPLACE FUNCTION public.get_user_storage_quota(p_user_id UUID)
RETURNS TABLE(
  used_bytes BIGINT,
  quota_bytes BIGINT,
  tier_name TEXT,
  tier_slug TEXT
) AS $$
DECLARE
  v_quota_bytes BIGINT;
  v_tier_name TEXT;
  v_tier_slug TEXT;
BEGIN
  -- Get quota info
  SELECT
    COALESCE(usq.admin_override_bytes, st.quota_bytes),
    st.name,
    st.slug
  INTO v_quota_bytes, v_tier_name, v_tier_slug
  FROM public.user_storage_quotas usq
  JOIN public.storage_tiers st ON st.id = usq.tier_id
  WHERE usq.user_id = p_user_id;

  -- If no record, use default tier
  IF v_quota_bytes IS NULL THEN
    SELECT st.quota_bytes, st.name, st.slug
    INTO v_quota_bytes, v_tier_name, v_tier_slug
    FROM public.storage_tiers st
    WHERE st.is_default = TRUE;
  END IF;

  -- Return result
  RETURN QUERY SELECT
    public.calculate_user_storage_usage(p_user_id),
    COALESCE(v_quota_bytes, 10737418240::BIGINT),
    COALESCE(v_tier_name, 'Free'),
    COALESCE(v_tier_slug, 'free');
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- ============================================
-- TRIGGERS
-- ============================================

-- Trigger function: Auto-create quota for new users
CREATE OR REPLACE FUNCTION public.create_default_storage_quota()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.user_storage_quotas (user_id, tier_id)
  SELECT NEW.id, id FROM public.storage_tiers WHERE is_default = TRUE
  ON CONFLICT DO NOTHING;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create trigger on auth.users (drop first if exists)
DROP TRIGGER IF EXISTS on_auth_user_created_storage ON auth.users;
CREATE TRIGGER on_auth_user_created_storage
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.create_default_storage_quota();

-- ============================================
-- STORAGE BUCKET RLS POLICIES
-- ============================================

-- Drop existing policies first
DROP POLICY IF EXISTS "user_upload_with_quota" ON storage.objects;
DROP POLICY IF EXISTS "user_read" ON storage.objects;
DROP POLICY IF EXISTS "user_delete" ON storage.objects;
DROP POLICY IF EXISTS "user_update" ON storage.objects;

-- Upload: only if quota not exceeded
-- Files must be stored in user's folder: {user_id}/...
-- Note: Supabase Storage passes file size in metadata during upload
CREATE POLICY "user_upload_with_quota" ON storage.objects
FOR INSERT WITH CHECK (
  bucket_id = 'user-files'
  AND (storage.foldername(name))[1] = auth.uid()::text
  AND public.check_storage_quota(auth.uid(), COALESCE((metadata->>'size')::BIGINT, 0))
);

-- Read: own files only
CREATE POLICY "user_read" ON storage.objects
FOR SELECT USING (
  bucket_id = 'user-files'
  AND (storage.foldername(name))[1] = auth.uid()::text
);

-- Delete: own files only
CREATE POLICY "user_delete" ON storage.objects
FOR DELETE USING (
  bucket_id = 'user-files'
  AND (storage.foldername(name))[1] = auth.uid()::text
);

-- Update: own files only (for metadata updates)
CREATE POLICY "user_update" ON storage.objects
FOR UPDATE USING (
  bucket_id = 'user-files'
  AND (storage.foldername(name))[1] = auth.uid()::text
);

-- ============================================
-- PERMISSIONS
-- ============================================

-- Grant execute on functions
GRANT EXECUTE ON FUNCTION public.calculate_user_storage_usage(UUID) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.check_storage_quota(UUID, BIGINT) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.get_user_storage_quota(UUID) TO authenticated, service_role;
