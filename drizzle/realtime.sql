-- Enable Supabase Realtime for sync_changes table
-- This file is idempotent and can be re-run after schema changes

-- Set REPLICA IDENTITY to FULL so that UPDATE events include the full new row
-- Without this, UPDATE payloads only contain the primary key, not the changed data
ALTER TABLE "sync_changes" REPLICA IDENTITY FULL;

-- Enable the table for Supabase Realtime (idempotent)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_publication_tables
    WHERE pubname = 'supabase_realtime'
    AND tablename = 'sync_changes'
  ) THEN
    ALTER PUBLICATION supabase_realtime ADD TABLE "sync_changes";
  END IF;
END $$;
