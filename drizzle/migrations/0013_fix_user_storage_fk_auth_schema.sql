-- Fix FK constraint on user_storage_credentials to correctly reference auth.users
-- This migration fixes an issue where db:push or a previous buggy migration
-- created the constraint referencing public.users instead of auth.users

-- First, drop the incorrect constraint if it exists
ALTER TABLE "user_storage_credentials" DROP CONSTRAINT IF EXISTS "user_storage_credentials_user_id_users_id_fk";

-- Re-add the constraint with correct reference to auth.users schema
ALTER TABLE "user_storage_credentials" ADD CONSTRAINT "user_storage_credentials_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE cascade ON UPDATE no action;
