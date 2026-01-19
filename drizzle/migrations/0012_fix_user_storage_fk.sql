-- Fix FK constraint on user_storage_credentials to reference auth.users instead of public.users
-- This can happen when db:push was used instead of db:migrate

-- Drop the incorrect FK constraint if it exists (referencing public.users)
DO $$ BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'user_storage_credentials_user_id_users_id_fk'
    AND conrelid = 'user_storage_credentials'::regclass
  ) THEN
    ALTER TABLE "user_storage_credentials" DROP CONSTRAINT "user_storage_credentials_user_id_users_id_fk";
  END IF;
END $$;
--> statement-breakpoint
-- Add the correct FK constraint referencing auth.users
DO $$ BEGIN
  ALTER TABLE "user_storage_credentials" ADD CONSTRAINT "user_storage_credentials_user_id_users_id_fk"
    FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;
