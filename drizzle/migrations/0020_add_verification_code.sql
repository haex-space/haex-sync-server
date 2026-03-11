-- Add verification code columns to identities table for OTP-based email verification

ALTER TABLE "identities" ADD COLUMN IF NOT EXISTS "verification_code" text;
ALTER TABLE "identities" ADD COLUMN IF NOT EXISTS "verification_code_expires_at" timestamp with time zone;
