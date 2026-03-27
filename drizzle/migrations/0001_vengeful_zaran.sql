CREATE TABLE "mls_key_packages" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"space_id" uuid NOT NULL,
	"identity_public_key" text NOT NULL,
	"key_package" "bytea" NOT NULL,
	"consumed" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "mls_messages" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"space_id" uuid NOT NULL,
	"sender_public_key" text NOT NULL,
	"message_type" text NOT NULL,
	"payload" "bytea" NOT NULL,
	"epoch" bigint,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "mls_welcome_messages" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"space_id" uuid NOT NULL,
	"recipient_public_key" text NOT NULL,
	"payload" "bytea" NOT NULL,
	"consumed" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "mls_key_packages" ADD CONSTRAINT "mls_key_packages_space_id_spaces_id_fk" FOREIGN KEY ("space_id") REFERENCES "public"."spaces"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "mls_messages" ADD CONSTRAINT "mls_messages_space_id_spaces_id_fk" FOREIGN KEY ("space_id") REFERENCES "public"."spaces"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "mls_welcome_messages" ADD CONSTRAINT "mls_welcome_messages_space_id_spaces_id_fk" FOREIGN KEY ("space_id") REFERENCES "public"."spaces"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "mls_key_packages_space_identity_idx" ON "mls_key_packages" USING btree ("space_id","identity_public_key");--> statement-breakpoint
CREATE INDEX "mls_messages_space_id_idx" ON "mls_messages" USING btree ("space_id","id");--> statement-breakpoint
CREATE INDEX "mls_welcome_recipient_idx" ON "mls_welcome_messages" USING btree ("space_id","recipient_public_key");