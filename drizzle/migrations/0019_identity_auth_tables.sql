-- Identity-based challenge-response auth tables

CREATE TABLE IF NOT EXISTS "identities" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "did" text NOT NULL UNIQUE,
  "public_key" text NOT NULL UNIQUE,
  "supabase_user_id" uuid REFERENCES "auth"."users"("id") ON DELETE CASCADE,
  "email" text,
  "email_verified" boolean NOT NULL DEFAULT false,
  "tier" text NOT NULL DEFAULT 'free',
  "encrypted_private_key" text,
  "private_key_nonce" text,
  "private_key_salt" text,
  "created_at" timestamp with time zone NOT NULL DEFAULT now(),
  "updated_at" timestamp with time zone NOT NULL DEFAULT now()
);
--> statement-breakpoint

CREATE TABLE IF NOT EXISTS "auth_challenges" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "did" text NOT NULL,
  "nonce" text NOT NULL UNIQUE,
  "expires_at" timestamp with time zone NOT NULL,
  "used_at" timestamp with time zone,
  "created_at" timestamp with time zone NOT NULL DEFAULT now()
);
--> statement-breakpoint

CREATE TABLE IF NOT EXISTS "tiers" (
  "name" text PRIMARY KEY NOT NULL,
  "max_storage_bytes" text NOT NULL,
  "max_spaces" integer NOT NULL DEFAULT 3,
  "description" text
);
