CREATE TABLE "space_invites" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"space_id" uuid NOT NULL,
	"inviter_public_key" text NOT NULL,
	"invitee_did" text NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"include_history" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"responded_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "space_invites" ADD CONSTRAINT "space_invites_space_id_spaces_id_fk" FOREIGN KEY ("space_id") REFERENCES "public"."spaces"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "space_invites_unique_idx" ON "space_invites" USING btree ("space_id","invitee_did");--> statement-breakpoint
CREATE INDEX "space_invites_invitee_idx" ON "space_invites" USING btree ("invitee_did");