ALTER TABLE "sync_changes" DISABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "vault_keys" DISABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "sync_changes" ADD COLUMN "device_id" text;--> statement-breakpoint
CREATE INDEX "sync_changes_device_idx" ON "sync_changes" USING btree ("device_id");