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
ALTER TABLE "space_access_tokens" ADD CONSTRAINT "space_access_tokens_space_id_spaces_id_fk" FOREIGN KEY ("space_id") REFERENCES "public"."spaces"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "space_access_tokens" ADD CONSTRAINT "space_access_tokens_issued_by_users_id_fk" FOREIGN KEY ("issued_by") REFERENCES "auth"."users"("id") ON DELETE no action ON UPDATE no action;