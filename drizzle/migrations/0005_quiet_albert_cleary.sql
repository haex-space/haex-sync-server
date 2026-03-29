ALTER TABLE "spaces" DROP CONSTRAINT "spaces_owner_id_users_id_fk";
--> statement-breakpoint
ALTER TABLE "spaces" ALTER COLUMN "owner_id" SET DATA TYPE text;