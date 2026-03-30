CREATE TABLE "federation_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"federation_link_id" uuid NOT NULL,
	"event_type" text NOT NULL,
	"metadata" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "federation_links" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"space_id" uuid NOT NULL,
	"server_id" uuid NOT NULL,
	"ucan_token" text NOT NULL,
	"ucan_expires_at" timestamp with time zone NOT NULL,
	"role" text DEFAULT 'relay' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "federation_servers" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"did" text NOT NULL,
	"url" text NOT NULL,
	"public_key" text NOT NULL,
	"name" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "federation_servers_did_unique" UNIQUE("did")
);
--> statement-breakpoint
ALTER TABLE "federation_events" ADD CONSTRAINT "federation_events_federation_link_id_federation_links_id_fk" FOREIGN KEY ("federation_link_id") REFERENCES "public"."federation_links"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "federation_links" ADD CONSTRAINT "federation_links_space_id_spaces_id_fk" FOREIGN KEY ("space_id") REFERENCES "public"."spaces"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "federation_links" ADD CONSTRAINT "federation_links_server_id_federation_servers_id_fk" FOREIGN KEY ("server_id") REFERENCES "public"."federation_servers"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "federation_events_link_idx" ON "federation_events" USING btree ("federation_link_id");--> statement-breakpoint
CREATE INDEX "federation_events_created_idx" ON "federation_events" USING btree ("created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "federation_links_space_server_idx" ON "federation_links" USING btree ("space_id","server_id");--> statement-breakpoint
CREATE INDEX "federation_links_space_idx" ON "federation_links" USING btree ("space_id");