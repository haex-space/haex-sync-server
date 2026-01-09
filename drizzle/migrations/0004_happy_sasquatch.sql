-- Migration 0003 already handles the column rename and additions
-- This migration only removes the DEFAULT values that were added in 0003
-- Delete all existing vault keys (they need to be recreated with encrypted vault names)
DELETE FROM "vault_keys";--> statement-breakpoint
ALTER TABLE "vault_keys" ALTER COLUMN "encrypted_vault_name" DROP DEFAULT;--> statement-breakpoint
ALTER TABLE "vault_keys" ALTER COLUMN "vault_name_nonce" DROP DEFAULT;