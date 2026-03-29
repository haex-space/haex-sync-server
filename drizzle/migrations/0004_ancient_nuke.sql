DROP TABLE "space_access_tokens" CASCADE;--> statement-breakpoint
DROP TABLE "space_key_grants" CASCADE;--> statement-breakpoint
ALTER TABLE "spaces" DROP COLUMN "current_key_generation";