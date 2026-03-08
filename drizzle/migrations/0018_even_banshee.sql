ALTER TABLE "sync_changes" ADD COLUMN "signature" text;--> statement-breakpoint
ALTER TABLE "sync_changes" ADD COLUMN "signed_by" text;--> statement-breakpoint
ALTER TABLE "sync_changes" ADD COLUMN "record_owner" text;--> statement-breakpoint
ALTER TABLE "sync_changes" ADD COLUMN "collaborative" boolean DEFAULT false;