ALTER TABLE "vault_keys" DISABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "vault_keys" RENAME COLUMN "nonce" TO "vault_key_nonce";--> statement-breakpoint
ALTER TABLE "vault_keys" ADD COLUMN "encrypted_vault_name" text NOT NULL DEFAULT '';--> statement-breakpoint
ALTER TABLE "vault_keys" ADD COLUMN "vault_name_nonce" text NOT NULL DEFAULT '';
