-- Fix FK constraints so deleting a Supabase user cascades to all related data.
-- Previously spaces.owner_id and space_access_tokens.issued_by had NO ACTION,
-- which blocked or silently prevented the cascade chain.

ALTER TABLE "spaces"
  DROP CONSTRAINT IF EXISTS "spaces_owner_id_users_id_fk",
  ADD CONSTRAINT "spaces_owner_id_users_id_fk"
    FOREIGN KEY ("owner_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;
--> statement-breakpoint

-- issued_by is audit info only — SET NULL so tokens survive the user deletion
ALTER TABLE "space_access_tokens"
  DROP CONSTRAINT IF EXISTS "space_access_tokens_issued_by_users_id_fk",
  ADD CONSTRAINT "space_access_tokens_issued_by_users_id_fk"
    FOREIGN KEY ("issued_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;
