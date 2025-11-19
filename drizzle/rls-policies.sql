-- Enable Row Level Security on sync tables
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
  USING (auth.uid() = user_id);

CREATE POLICY "Users can only insert their own vault keys"
  ON vault_keys
  FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can only update their own vault keys"
  ON vault_keys
  FOR UPDATE
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- Sync Changes Policies
CREATE POLICY "Users can only access their own sync changes"
  ON sync_changes
  FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can only insert their own sync changes"
  ON sync_changes
  FOR INSERT
  WITH CHECK (auth.uid() = user_id);

-- Note: No UPDATE or DELETE policies for sync_changes - they are append-only
