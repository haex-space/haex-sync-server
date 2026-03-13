CREATE TABLE "auth_challenges" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"did" text NOT NULL,
	"nonce" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"used_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "auth_challenges_nonce_unique" UNIQUE("nonce")
);
--> statement-breakpoint
CREATE TABLE "identities" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"did" text NOT NULL,
	"public_key" text NOT NULL,
	"supabase_user_id" uuid,
	"email" text,
	"tier" text DEFAULT 'free' NOT NULL,
	"encrypted_private_key" text,
	"private_key_nonce" text,
	"private_key_salt" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "identities_did_unique" UNIQUE("did"),
	CONSTRAINT "identities_public_key_unique" UNIQUE("public_key"),
	CONSTRAINT "identities_email_unique" UNIQUE("email")
);
--> statement-breakpoint
CREATE TABLE "tiers" (
	"name" text PRIMARY KEY NOT NULL,
	"max_storage_bytes" text NOT NULL,
	"max_spaces" integer DEFAULT 3 NOT NULL,
	"description" text
);
--> statement-breakpoint
ALTER TABLE "user_keypairs" DISABLE ROW LEVEL SECURITY;--> statement-breakpoint
DROP TABLE "user_keypairs" CASCADE;--> statement-breakpoint
ALTER TABLE "space_key_grants" RENAME COLUMN "user_id" TO "public_key";--> statement-breakpoint
ALTER TABLE "vault_keys" RENAME COLUMN "vault_name_salt" TO "ephemeral_public_key";--> statement-breakpoint
ALTER TABLE "space_key_grants" DROP CONSTRAINT "space_key_grants_user_id_users_id_fk";
--> statement-breakpoint
ALTER TABLE "space_key_grants" DROP CONSTRAINT "space_key_grants_granted_by_users_id_fk";
--> statement-breakpoint
ALTER TABLE "space_members" DROP CONSTRAINT "space_members_user_id_users_id_fk";
--> statement-breakpoint
ALTER TABLE "space_members" DROP CONSTRAINT "space_members_invited_by_users_id_fk";
--> statement-breakpoint
ALTER TABLE "space_key_grants" DROP CONSTRAINT "space_key_grants_space_id_user_id_generation_pk";--> statement-breakpoint
ALTER TABLE "space_members" DROP CONSTRAINT "space_members_space_id_user_id_pk";--> statement-breakpoint
ALTER TABLE "space_key_grants" ALTER COLUMN "granted_by" SET DATA TYPE text;--> statement-breakpoint
ALTER TABLE "space_members" ALTER COLUMN "invited_by" SET DATA TYPE text;--> statement-breakpoint
ALTER TABLE "space_key_grants" ADD CONSTRAINT "space_key_grants_space_id_public_key_generation_pk" PRIMARY KEY("space_id","public_key","generation");--> statement-breakpoint
ALTER TABLE "space_members" ADD CONSTRAINT "space_members_space_id_public_key_pk" PRIMARY KEY("space_id","public_key");--> statement-breakpoint
ALTER TABLE "space_members" ADD COLUMN "public_key" text NOT NULL;--> statement-breakpoint
ALTER TABLE "space_members" ADD COLUMN "label" text NOT NULL;--> statement-breakpoint
ALTER TABLE "identities" ADD CONSTRAINT "identities_supabase_user_id_users_id_fk" FOREIGN KEY ("supabase_user_id") REFERENCES "auth"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "space_members" DROP COLUMN "user_id";