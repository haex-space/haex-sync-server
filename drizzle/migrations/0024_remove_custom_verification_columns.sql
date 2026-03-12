-- Remove custom email verification columns from identities table.
-- Email verification is now handled by GoTrue (auth.users.email_confirmed_at).

ALTER TABLE "identities" DROP COLUMN IF EXISTS "email_verified";
ALTER TABLE "identities" DROP COLUMN IF EXISTS "verification_code";
ALTER TABLE "identities" DROP COLUMN IF EXISTS "verification_code_expires_at";
