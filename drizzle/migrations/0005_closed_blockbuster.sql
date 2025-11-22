ALTER TABLE "sync_changes" RENAME COLUMN "encrypted_data" TO "encrypted_value";--> statement-breakpoint
DROP INDEX "sync_changes_created_idx";--> statement-breakpoint
ALTER TABLE "sync_changes" ALTER COLUMN "nonce" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "sync_changes" ADD COLUMN "table_name" text NOT NULL;--> statement-breakpoint
ALTER TABLE "sync_changes" ADD COLUMN "row_pks" text NOT NULL;--> statement-breakpoint
ALTER TABLE "sync_changes" ADD COLUMN "column_name" text;--> statement-breakpoint
ALTER TABLE "sync_changes" ADD COLUMN "operation" text NOT NULL;--> statement-breakpoint
ALTER TABLE "sync_changes" ADD COLUMN "hlc_timestamp" text NOT NULL;--> statement-breakpoint
ALTER TABLE "sync_changes" ADD COLUMN "updated_at" timestamp DEFAULT now() NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "sync_changes_unique_cell" ON "sync_changes" USING btree ("vault_id","table_name","row_pks","column_name");--> statement-breakpoint
CREATE INDEX "sync_changes_hlc_idx" ON "sync_changes" USING btree ("hlc_timestamp");--> statement-breakpoint
CREATE INDEX "sync_changes_updated_idx" ON "sync_changes" USING btree ("updated_at");