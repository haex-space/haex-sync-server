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
ALTER TABLE "user_storage_credentials" ADD CONSTRAINT "user_storage_credentials_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "user_storage_credentials_access_key_idx" ON "user_storage_credentials" USING btree ("access_key_id");