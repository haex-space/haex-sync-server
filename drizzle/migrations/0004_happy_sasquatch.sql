-- Delete all existing vault keys (they need to be recreated with encrypted vault names)
DELETE FROM "vault_keys";--> statement-breakpoint
ALTER TABLE "vault_keys" RENAME COLUMN "nonce" TO "vault_key_nonce";--> statement-breakpoint
ALTER TABLE "vault_keys" ADD COLUMN "encrypted_vault_name" text NOT NULL;--> statement-breakpoint
ALTER TABLE "vault_keys" ADD COLUMN "vault_name_nonce" text NOT NULL;