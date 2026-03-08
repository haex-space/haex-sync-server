ALTER TABLE user_keypairs ENABLE ROW LEVEL SECURITY;

-- Drop existing policies if any (to allow re-running this file)
DROP POLICY IF EXISTS user_keypairs_select ON user_keypairs;
DROP POLICY IF EXISTS user_keypairs_insert ON user_keypairs;
DROP POLICY IF EXISTS user_keypairs_update ON user_keypairs;
DROP POLICY IF EXISTS user_keypairs_delete ON user_keypairs;

-- Anyone can read public keys (needed for inviting others)
CREATE POLICY user_keypairs_select ON user_keypairs
  FOR SELECT USING (true);

-- Users can only manage their own keypair
CREATE POLICY user_keypairs_insert ON user_keypairs
  FOR INSERT WITH CHECK (user_id = (SELECT auth.uid()));

CREATE POLICY user_keypairs_update ON user_keypairs
  FOR UPDATE USING (user_id = (SELECT auth.uid()));

CREATE POLICY user_keypairs_delete ON user_keypairs
  FOR DELETE USING (user_id = (SELECT auth.uid()));
