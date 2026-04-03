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

-- owner_id is now a DID (text), not a Supabase UUID.
-- Direct PostgREST access is not used — the server API handles auth.
DROP POLICY IF EXISTS "Users can read their own spaces" ON spaces;

-- Note: shared space members who are NOT the owner cannot see the space
-- via PostgREST. This is intentional — the server API handles membership
-- lookups. If direct client access is needed later, add a membership-based
-- policy using a SECURITY DEFINER helper to avoid circular RLS references.

-- ============================================================================
-- 5. SPACE_MEMBERS — membership records
-- ============================================================================

ALTER TABLE space_members ENABLE ROW LEVEL SECURITY;

-- Membership check: uses DID from identities table linked to auth.uid()
CREATE OR REPLACE FUNCTION is_space_member(p_space_id uuid)
RETURNS boolean
SECURITY DEFINER SET search_path = ''
AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1 FROM public.identities i
    JOIN public.space_members sm ON sm.did = i.did
    WHERE i.supabase_user_id = (SELECT auth.uid())
    AND sm.space_id = p_space_id
  );
END;
$$ LANGUAGE plpgsql;

DROP POLICY IF EXISTS "Members can read their space members" ON space_members;
CREATE POLICY "Members can read their space members"
  ON space_members FOR SELECT
  USING (is_space_member(space_id));

-- Tables space_key_grants and space_access_tokens were removed in Phase 3
-- (replaced by MLS + UCAN). No RLS policies needed.

-- ============================================================================
-- 6. SPACE_INVITES — 2-step invite flow
-- ============================================================================

ALTER TABLE space_invites ENABLE ROW LEVEL SECURITY;

-- Members see all invites for their space; non-members see only their own
DROP POLICY IF EXISTS "Users can read relevant invites" ON space_invites;
CREATE POLICY "Users can read relevant invites"
  ON space_invites FOR SELECT
  USING (
    is_space_member(space_id)
    OR EXISTS (
      SELECT 1 FROM public.identities i
      WHERE i.supabase_user_id = (SELECT auth.uid())
      AND i.did = space_invites.invitee_did
    )
  );

-- ============================================================================
-- 7. MLS_KEY_PACKAGES — pre-published credentials (opaque blobs)
-- ============================================================================

ALTER TABLE mls_key_packages ENABLE ROW LEVEL SECURITY;

-- Only space members can see key packages for their space
DROP POLICY IF EXISTS "Members can read key packages" ON mls_key_packages;
CREATE POLICY "Members can read key packages"
  ON mls_key_packages FOR SELECT
  USING (is_space_member(space_id));

-- ============================================================================
-- 8. MLS_MESSAGES — ordered message queue (opaque blobs)
-- ============================================================================

ALTER TABLE mls_messages ENABLE ROW LEVEL SECURITY;

-- Only space members can read messages
DROP POLICY IF EXISTS "Members can read MLS messages" ON mls_messages;
CREATE POLICY "Members can read MLS messages"
  ON mls_messages FOR SELECT
  USING (is_space_member(space_id));

-- ============================================================================
-- 9. MLS_WELCOME_MESSAGES — targeted welcome messages (opaque blobs)
-- ============================================================================

ALTER TABLE mls_welcome_messages ENABLE ROW LEVEL SECURITY;

-- Only the recipient can read their welcome messages
DROP POLICY IF EXISTS "Recipients can read their welcomes" ON mls_welcome_messages;
CREATE POLICY "Recipients can read their welcomes"
  ON mls_welcome_messages FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM public.identities i
      WHERE i.supabase_user_id = (SELECT auth.uid())
      AND i.public_key = mls_welcome_messages.recipient_public_key
    )
  );

-- ============================================================================
-- 10. SPACE_INVITE_TOKENS — server-managed invite tokens
-- ============================================================================

ALTER TABLE space_invite_tokens ENABLE ROW LEVEL SECURITY;

-- No policies: all access via service_role (server handles token lifecycle)
-- PostgREST access fully blocked for both anon and authenticated

-- ============================================================================
-- 11. FEDERATION_SERVERS — known federated server identities
-- ============================================================================

ALTER TABLE federation_servers ENABLE ROW LEVEL SECURITY;

-- No policies: all access via service_role (server handles federation)
-- PostgREST access fully blocked for both anon and authenticated

-- ============================================================================
-- 12. FEDERATION_LINKS — active federation relationships
-- ============================================================================

ALTER TABLE federation_links ENABLE ROW LEVEL SECURITY;

-- No policies: all access via service_role (server handles federation)
-- PostgREST access fully blocked for both anon and authenticated

-- ============================================================================
-- 13. FEDERATION_EVENTS — federation audit trail
-- ============================================================================

ALTER TABLE federation_events ENABLE ROW LEVEL SECURITY;

-- No policies: all access via service_role (server handles federation)
-- PostgREST access fully blocked for both anon and authenticated
