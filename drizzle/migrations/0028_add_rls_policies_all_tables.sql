-- Add RLS policies to all public tables that had RLS enabled but no policies
-- Fixes security advisory: rls_enabled_no_policy

-- ============================================
-- user_keypairs
-- ============================================
DROP POLICY IF EXISTS user_keypairs_select ON user_keypairs;
DROP POLICY IF EXISTS user_keypairs_insert ON user_keypairs;
DROP POLICY IF EXISTS user_keypairs_update ON user_keypairs;
DROP POLICY IF EXISTS user_keypairs_delete ON user_keypairs;

-- Anyone can read public keys (needed for inviting others to spaces)
CREATE POLICY user_keypairs_select ON user_keypairs
  FOR SELECT USING (true);
--> statement-breakpoint
CREATE POLICY user_keypairs_insert ON user_keypairs
  FOR INSERT WITH CHECK (user_id = (SELECT auth.uid()));
--> statement-breakpoint
CREATE POLICY user_keypairs_update ON user_keypairs
  FOR UPDATE USING (user_id = (SELECT auth.uid()));
--> statement-breakpoint
CREATE POLICY user_keypairs_delete ON user_keypairs
  FOR DELETE USING (user_id = (SELECT auth.uid()));

-- ============================================
-- identities: users can read their own, service_role manages
-- ============================================
--> statement-breakpoint
CREATE POLICY identities_select ON identities
  FOR SELECT USING (supabase_user_id = (SELECT auth.uid()) OR (SELECT auth.role()) = 'service_role');
--> statement-breakpoint
CREATE POLICY identities_insert ON identities
  FOR INSERT WITH CHECK ((SELECT auth.role()) = 'service_role');
--> statement-breakpoint
CREATE POLICY identities_update ON identities
  FOR UPDATE USING ((SELECT auth.role()) = 'service_role');
--> statement-breakpoint
CREATE POLICY identities_delete ON identities
  FOR DELETE USING ((SELECT auth.role()) = 'service_role');

-- ============================================
-- auth_challenges: only service_role (server-side DID auth)
-- ============================================
--> statement-breakpoint
CREATE POLICY auth_challenges_all ON auth_challenges
  FOR ALL USING ((SELECT auth.role()) = 'service_role');

-- ============================================
-- tiers: everyone can read, only service_role can write
-- ============================================
--> statement-breakpoint
CREATE POLICY tiers_select ON tiers
  FOR SELECT USING (true);
--> statement-breakpoint
CREATE POLICY tiers_modify ON tiers
  FOR ALL USING ((SELECT auth.role()) = 'service_role');

-- ============================================
-- spaces: owner/members can read, service_role manages
-- ============================================
--> statement-breakpoint
CREATE POLICY spaces_select ON spaces
  FOR SELECT USING (
    owner_id = (SELECT auth.uid())
    OR EXISTS (
      SELECT 1 FROM space_members
      WHERE space_id = spaces.id
      AND public_key = (SELECT public_key FROM user_keypairs WHERE user_id = (SELECT auth.uid()))
    )
    OR (SELECT auth.role()) = 'service_role'
  );
--> statement-breakpoint
CREATE POLICY spaces_insert ON spaces
  FOR INSERT WITH CHECK ((SELECT auth.role()) = 'service_role');
--> statement-breakpoint
CREATE POLICY spaces_update ON spaces
  FOR UPDATE USING ((SELECT auth.role()) = 'service_role');
--> statement-breakpoint
CREATE POLICY spaces_delete ON spaces
  FOR DELETE USING ((SELECT auth.role()) = 'service_role');

-- ============================================
-- space_members: members can see their space's members
-- ============================================
--> statement-breakpoint
CREATE POLICY space_members_select ON space_members
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM space_members sm
      WHERE sm.space_id = space_members.space_id
      AND sm.public_key = (SELECT public_key FROM user_keypairs WHERE user_id = (SELECT auth.uid()))
    )
    OR (SELECT auth.role()) = 'service_role'
  );
--> statement-breakpoint
CREATE POLICY space_members_modify ON space_members
  FOR ALL USING ((SELECT auth.role()) = 'service_role');

-- ============================================
-- space_key_grants: grantee can read their own grants
-- ============================================
--> statement-breakpoint
CREATE POLICY space_key_grants_select ON space_key_grants
  FOR SELECT USING (
    public_key = (SELECT public_key FROM user_keypairs WHERE user_id = (SELECT auth.uid()))
    OR (SELECT auth.role()) = 'service_role'
  );
--> statement-breakpoint
CREATE POLICY space_key_grants_modify ON space_key_grants
  FOR ALL USING ((SELECT auth.role()) = 'service_role');

-- ============================================
-- space_access_tokens: service_role only
-- ============================================
--> statement-breakpoint
CREATE POLICY space_access_tokens_select ON space_access_tokens
  FOR SELECT USING ((SELECT auth.role()) = 'service_role');
--> statement-breakpoint
CREATE POLICY space_access_tokens_modify ON space_access_tokens
  FOR ALL USING ((SELECT auth.role()) = 'service_role');
