ALTER TABLE "vault_keys" RENAME COLUMN "nonce" TO "vault_key_nonce";--> statement-breakpoint
ALTER TABLE "vault_keys" ADD COLUMN "encrypted_vault_name" text NOT NULL;--> statement-breakpoint
ALTER TABLE "vault_keys" ADD COLUMN "vault_name_nonce" text NOT NULL;