-- Storage Bucket Setup for haex Cloud Storage
-- This file is idempotent and can be re-run after changes
--
-- Per-User Buckets: Each user gets their own bucket: storage-{user_id}
-- This avoids naming conflicts and provides better isolation

-- ============================================
-- DEFAULT STORAGE TIER
-- ============================================

-- Insert default tier (only Free tier for now)
INSERT INTO public.storage_tiers (name, slug, quota_bytes, price_monthly_euro_cents, is_default, sort_order)
VALUES ('Free', 'free', 10737418240, NULL, TRUE, 0)  -- 10 GB
ON CONFLICT (slug) DO NOTHING;

-- ============================================
-- RLS FOR QUOTA TABLES
-- ============================================

ALTER TABLE public.storage_tiers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_storage_quotas ENABLE ROW LEVEL SECURITY;

-- Everyone can read tiers
DROP POLICY IF EXISTS "public_read_tiers" ON public.storage_tiers;
CREATE POLICY "public_read_tiers" ON public.storage_tiers
FOR SELECT USING (true);

-- Users can only read their own quota
DROP POLICY IF EXISTS "user_read_own_quota" ON public.user_storage_quotas;
CREATE POLICY "user_read_own_quota" ON public.user_storage_quotas
FOR SELECT USING (auth.uid() = user_id);

-- Grant permissions on quota tables
GRANT SELECT ON public.storage_tiers TO anon, authenticated;
GRANT SELECT ON public.user_storage_quotas TO authenticated;

-- ============================================
-- HELPER FUNCTIONS
-- ============================================

-- Function: Get user's bucket name
CREATE OR REPLACE FUNCTION public.get_user_bucket_name(p_user_id UUID)
RETURNS TEXT AS $$
  SELECT 'storage-' || p_user_id::text;
$$ LANGUAGE sql IMMUTABLE;

-- Function: Calculate used bytes from storage.objects (for per-user bucket)
CREATE OR REPLACE FUNCTION public.calculate_user_storage_usage(p_user_id UUID)
RETURNS BIGINT AS $$
  SELECT COALESCE(SUM((metadata->>'size')::BIGINT), 0)
  FROM storage.objects
  WHERE bucket_id = public.get_user_bucket_name(p_user_id);
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

-- Function: Create user's storage bucket
CREATE OR REPLACE FUNCTION public.create_user_storage_bucket(p_user_id UUID)
RETURNS TEXT AS $$
DECLARE
  v_bucket_name TEXT;
BEGIN
  v_bucket_name := public.get_user_bucket_name(p_user_id);

  -- Create bucket if not exists
  INSERT INTO storage.buckets (id, name, public, file_size_limit)
  VALUES (v_bucket_name, v_bucket_name, FALSE, 52428800)  -- 50MB per file
  ON CONFLICT (id) DO NOTHING;

  RETURN v_bucket_name;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================
-- TRIGGERS
-- ============================================

-- Trigger function: Auto-create quota AND bucket for new users
CREATE OR REPLACE FUNCTION public.create_default_storage_quota()
RETURNS TRIGGER AS $$
BEGIN
  -- Create quota entry
  INSERT INTO public.user_storage_quotas (user_id, tier_id)
  SELECT NEW.id, id FROM public.storage_tiers WHERE is_default = TRUE
  ON CONFLICT DO NOTHING;

  -- Create user's storage bucket
  PERFORM public.create_user_storage_bucket(NEW.id);

  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create trigger on auth.users (drop first if exists)
DROP TRIGGER IF EXISTS on_auth_user_created_storage ON auth.users;
CREATE TRIGGER on_auth_user_created_storage
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.create_default_storage_quota();

-- Create quota and bucket for existing users who don't have one
INSERT INTO public.user_storage_quotas (user_id, tier_id)
SELECT u.id, st.id
FROM auth.users u
CROSS JOIN public.storage_tiers st
WHERE st.is_default = TRUE
  AND NOT EXISTS (
    SELECT 1 FROM public.user_storage_quotas usq WHERE usq.user_id = u.id
  )
ON CONFLICT DO NOTHING;

-- Create buckets for existing users
DO $$
DECLARE
  r RECORD;
BEGIN
  FOR r IN SELECT id FROM auth.users LOOP
    PERFORM public.create_user_storage_bucket(r.id);
  END LOOP;
END;
$$;

-- ============================================
-- STORAGE BUCKET RLS POLICIES
-- ============================================

-- Drop old user-files policies if they exist (migration from old system)
DROP POLICY IF EXISTS "user_upload_with_quota" ON storage.objects;
DROP POLICY IF EXISTS "user_read" ON storage.objects;
DROP POLICY IF EXISTS "user_delete" ON storage.objects;
DROP POLICY IF EXISTS "user_update" ON storage.objects;

-- Drop per-user bucket policies if they exist (for idempotent execution)
DROP POLICY IF EXISTS "user_upload_own_bucket" ON storage.objects;
DROP POLICY IF EXISTS "user_read_own_bucket" ON storage.objects;
DROP POLICY IF EXISTS "user_delete_own_bucket" ON storage.objects;
DROP POLICY IF EXISTS "user_update_own_bucket" ON storage.objects;

-- Per-user bucket policies
-- Upload: only to own bucket, check quota
CREATE POLICY "user_upload_own_bucket" ON storage.objects
FOR INSERT WITH CHECK (
  bucket_id = public.get_user_bucket_name(auth.uid())
  AND public.check_storage_quota(auth.uid(), COALESCE((metadata->>'size')::BIGINT, 0))
);

-- Read: own bucket only
CREATE POLICY "user_read_own_bucket" ON storage.objects
FOR SELECT USING (
  bucket_id = public.get_user_bucket_name(auth.uid())
);

-- Delete: own bucket only
CREATE POLICY "user_delete_own_bucket" ON storage.objects
FOR DELETE USING (
  bucket_id = public.get_user_bucket_name(auth.uid())
);

-- Update: own bucket only (for metadata updates)
CREATE POLICY "user_update_own_bucket" ON storage.objects
FOR UPDATE USING (
  bucket_id = public.get_user_bucket_name(auth.uid())
);

-- ============================================
-- PERMISSIONS
-- ============================================

-- Grant execute on functions
GRANT EXECUTE ON FUNCTION public.get_user_bucket_name(UUID) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.calculate_user_storage_usage(UUID) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.check_storage_quota(UUID, BIGINT) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.get_user_storage_quota(UUID) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.create_user_storage_bucket(UUID) TO service_role;
