ALTER TABLE "vault_keys" RENAME COLUMN "salt" TO "vault_key_salt";--> statement-breakpoint
ALTER TABLE "vault_keys" ADD COLUMN "vault_name_salt" text NOT NULL;