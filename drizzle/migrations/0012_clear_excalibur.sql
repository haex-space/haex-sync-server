CREATE TABLE "mls_group_info" (
	"space_id" uuid PRIMARY KEY NOT NULL,
	"payload" "bytea" NOT NULL,
	"epoch" bigint NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "mls_group_info" ADD CONSTRAINT "mls_group_info_space_id_spaces_id_fk" FOREIGN KEY ("space_id") REFERENCES "public"."spaces"("id") ON DELETE cascade ON UPDATE no action;