-- ============================================================================
-- RLS Policies for spaces, identity, and tier tables
-- ============================================================================
-- All write operations go through the Hono server (service_role, bypasses RLS).
-- These policies protect against unauthorized PostgREST access.
-- This file is idempotent and can be re-run safely.
-- ============================================================================

-- ============================================================================
-- 1. TIERS — read-only reference data
-- ============================================================================

ALTER TABLE tiers ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Anyone can read tiers" ON tiers;
CREATE POLICY "Anyone can read tiers"
  ON tiers FOR SELECT
  USING (true);

-- No INSERT/UPDATE/DELETE policies = writes denied via PostgREST

-- ============================================================================
-- 2. AUTH_CHALLENGES — server-managed ephemeral nonces
-- ============================================================================

ALTER TABLE auth_challenges ENABLE ROW LEVEL SECURITY;

-- No policies: all access via service_role (server handles challenge flow)
-- PostgREST access fully blocked for both anon and authenticated

-- ============================================================================
-- 3. IDENTITIES — DID-based identity mappings
-- ============================================================================

ALTER TABLE identities ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can read their own identity" ON identities;
CREATE POLICY "Users can read their own identity"
  ON identities FOR SELECT
  USING ((select auth.uid()) = supabase_user_id);

-- No write policies: registration/updates handled by server

-- ============================================================================
-- 4. SPACES — central anchor for vaults and shared spaces
-- ============================================================================

ALTER TABLE spaces ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can read their own spaces" ON spaces;
CREATE POLICY "Users can read their own spaces"
  ON spaces FOR SELECT
  USING (owner_id = (select auth.uid()));

-- Note: shared space members who are NOT the owner cannot see the space
-- via PostgREST. This is intentional — the server API handles membership
-- lookups. If direct client access is needed later, add a membership-based
-- policy using a SECURITY DEFINER helper to avoid circular RLS references.

-- ============================================================================
-- 5. SPACE_MEMBERS — membership records
-- ============================================================================

ALTER TABLE space_members ENABLE ROW LEVEL SECURITY;

-- Helper function to check space membership without triggering RLS recursion.
-- SECURITY DEFINER runs as the function owner (superuser), bypassing RLS.
CREATE OR REPLACE FUNCTION is_space_member(p_space_id uuid)
RETURNS boolean
SECURITY DEFINER SET search_path = ''
AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1 FROM public.identities i
    JOIN public.space_members sm ON sm.public_key = i.public_key
    WHERE i.supabase_user_id = (SELECT auth.uid())
    AND sm.space_id = p_space_id
  );
END;
$$ LANGUAGE plpgsql;

DROP POLICY IF EXISTS "Members can read their space members" ON space_members;
CREATE POLICY "Members can read their space members"
  ON space_members FOR SELECT
  USING (is_space_member(space_id));

-- ============================================================================
-- 6. SPACE_KEY_GRANTS — encrypted space keys per member
-- ============================================================================

ALTER TABLE space_key_grants ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can read their own key grants" ON space_key_grants;
CREATE POLICY "Users can read their own key grants"
  ON space_key_grants FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM public.identities i
      WHERE i.supabase_user_id = (select auth.uid())
      AND i.public_key = space_key_grants.public_key
    )
  );

-- ============================================================================
-- 7. SPACE_ACCESS_TOKENS — scoped tokens for space access
-- ============================================================================

ALTER TABLE space_access_tokens ENABLE ROW LEVEL SECURITY;

-- Only space admins can view tokens (matches server-side authorization)
DROP POLICY IF EXISTS "Space admins can read tokens" ON space_access_tokens;
CREATE POLICY "Space admins can read tokens"
  ON space_access_tokens FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM public.identities i
      JOIN public.space_members sm ON sm.public_key = i.public_key
      WHERE i.supabase_user_id = (select auth.uid())
      AND sm.space_id = space_access_tokens.space_id
      AND sm.role = 'admin'
    )
  );
