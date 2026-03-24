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
CREATE TABLE "space_access_tokens" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"space_id" uuid NOT NULL,
	"token" text NOT NULL,
	"public_key" text NOT NULL,
	"role" text NOT NULL,
	"label" text,
	"issued_by" uuid,
	"revoked" boolean DEFAULT false NOT NULL,
	"revoked_at" timestamp with time zone,
	"revoked_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_used_at" timestamp with time zone,
	CONSTRAINT "space_access_tokens_token_unique" UNIQUE("token")
);
--> statement-breakpoint
CREATE TABLE "space_key_grants" (
	"space_id" uuid NOT NULL,
	"public_key" text NOT NULL,
	"generation" integer NOT NULL,
	"encrypted_space_key" text NOT NULL,
	"key_nonce" text NOT NULL,
	"ephemeral_public_key" text NOT NULL,
	"granted_by" text,
	"granted_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "space_key_grants_space_id_public_key_generation_pk" PRIMARY KEY("space_id","public_key","generation")
);
--> statement-breakpoint
CREATE TABLE "space_members" (
	"space_id" uuid NOT NULL,
	"public_key" text NOT NULL,
	"label" text NOT NULL,
	"role" text NOT NULL,
	"invited_by" text,
	"joined_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "space_members_space_id_public_key_pk" PRIMARY KEY("space_id","public_key")
);
--> statement-breakpoint
CREATE TABLE "spaces" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"type" text DEFAULT 'shared' NOT NULL,
	"owner_id" uuid NOT NULL,
	"encrypted_name" text,
	"name_nonce" text,
	"current_key_generation" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "sync_changes" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"space_id" uuid NOT NULL,
	"table_name" text NOT NULL,
	"row_pks" text NOT NULL,
	"column_name" text,
	"hlc_timestamp" text NOT NULL,
	"device_id" text,
	"encrypted_value" text,
	"nonce" text,
	"signature" text,
	"signed_by" text,
	"record_owner" text,
	"collaborative" boolean DEFAULT false,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "tiers" (
	"name" text PRIMARY KEY NOT NULL,
	"max_storage_bytes" text NOT NULL,
	"max_spaces" integer DEFAULT 3 NOT NULL,
	"description" text
);
--> statement-breakpoint
CREATE TABLE "user_storage_credentials" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"access_key_id" text NOT NULL,
	"encrypted_secret_key" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "user_storage_credentials_user_id_unique" UNIQUE("user_id"),
	CONSTRAINT "user_storage_credentials_access_key_id_unique" UNIQUE("access_key_id")
);
--> statement-breakpoint
CREATE TABLE "vault_keys" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"space_id" uuid NOT NULL,
	"encrypted_vault_key" text NOT NULL,
	"encrypted_vault_name" text NOT NULL,
	"vault_key_salt" text NOT NULL,
	"ephemeral_public_key" text NOT NULL,
	"vault_key_nonce" text NOT NULL,
	"vault_name_nonce" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "identities" ADD CONSTRAINT "identities_supabase_user_id_users_id_fk" FOREIGN KEY ("supabase_user_id") REFERENCES "auth"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "space_access_tokens" ADD CONSTRAINT "space_access_tokens_space_id_spaces_id_fk" FOREIGN KEY ("space_id") REFERENCES "public"."spaces"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "space_access_tokens" ADD CONSTRAINT "space_access_tokens_issued_by_users_id_fk" FOREIGN KEY ("issued_by") REFERENCES "auth"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "space_key_grants" ADD CONSTRAINT "space_key_grants_space_id_spaces_id_fk" FOREIGN KEY ("space_id") REFERENCES "public"."spaces"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "space_members" ADD CONSTRAINT "space_members_space_id_spaces_id_fk" FOREIGN KEY ("space_id") REFERENCES "public"."spaces"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "spaces" ADD CONSTRAINT "spaces_owner_id_users_id_fk" FOREIGN KEY ("owner_id") REFERENCES "auth"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sync_changes" ADD CONSTRAINT "sync_changes_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sync_changes" ADD CONSTRAINT "sync_changes_space_id_spaces_id_fk" FOREIGN KEY ("space_id") REFERENCES "public"."spaces"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_storage_credentials" ADD CONSTRAINT "user_storage_credentials_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vault_keys" ADD CONSTRAINT "vault_keys_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vault_keys" ADD CONSTRAINT "vault_keys_space_id_spaces_id_fk" FOREIGN KEY ("space_id") REFERENCES "public"."spaces"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "sync_changes_unique_cell" ON "sync_changes" USING btree ("space_id","table_name","row_pks","column_name");--> statement-breakpoint
CREATE INDEX "sync_changes_user_space_idx" ON "sync_changes" USING btree ("user_id","space_id");--> statement-breakpoint
CREATE INDEX "sync_changes_hlc_idx" ON "sync_changes" USING btree ("hlc_timestamp");--> statement-breakpoint
CREATE INDEX "sync_changes_updated_idx" ON "sync_changes" USING btree ("updated_at");--> statement-breakpoint
CREATE INDEX "sync_changes_device_idx" ON "sync_changes" USING btree ("device_id");--> statement-breakpoint
CREATE INDEX "user_storage_credentials_access_key_idx" ON "user_storage_credentials" USING btree ("access_key_id");--> statement-breakpoint
CREATE UNIQUE INDEX "vault_keys_user_space_idx" ON "vault_keys" USING btree ("user_id","space_id");--> statement-breakpoint
CREATE INDEX "vault_keys_user_idx" ON "vault_keys" USING btree ("user_id");