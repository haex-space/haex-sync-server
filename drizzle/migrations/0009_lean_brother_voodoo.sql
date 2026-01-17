CREATE TABLE "storage_tiers" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"slug" text NOT NULL,
	"quota_bytes" bigint NOT NULL,
	"price_monthly_euro_cents" integer,
	"is_default" boolean DEFAULT false,
	"sort_order" integer DEFAULT 0,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "storage_tiers_name_unique" UNIQUE("name"),
	CONSTRAINT "storage_tiers_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE "user_storage_quotas" (
	"user_id" uuid PRIMARY KEY NOT NULL,
	"tier_id" uuid NOT NULL,
	"admin_override_bytes" bigint,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "user_storage_quotas" ADD CONSTRAINT "user_storage_quotas_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_storage_quotas" ADD CONSTRAINT "user_storage_quotas_tier_id_storage_tiers_id_fk" FOREIGN KEY ("tier_id") REFERENCES "public"."storage_tiers"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "user_storage_quotas_tier_idx" ON "user_storage_quotas" USING btree ("tier_id");