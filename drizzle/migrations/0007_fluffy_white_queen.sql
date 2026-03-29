CREATE TABLE "space_invite_tokens" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"space_id" uuid NOT NULL,
	"created_by_did" text NOT NULL,
	"capability" text DEFAULT 'space/write' NOT NULL,
	"max_uses" integer DEFAULT 1 NOT NULL,
	"used_count" integer DEFAULT 0 NOT NULL,
	"label" text,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "space_invites" ADD COLUMN "token_id" uuid;--> statement-breakpoint
ALTER TABLE "space_invites" ADD COLUMN "expires_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "space_invite_tokens" ADD CONSTRAINT "space_invite_tokens_space_id_spaces_id_fk" FOREIGN KEY ("space_id") REFERENCES "public"."spaces"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "space_invite_tokens_space_idx" ON "space_invite_tokens" USING btree ("space_id");--> statement-breakpoint
ALTER TABLE "space_invites" ADD CONSTRAINT "space_invites_token_id_space_invite_tokens_id_fk" FOREIGN KEY ("token_id") REFERENCES "public"."space_invite_tokens"("id") ON DELETE set null ON UPDATE no action;