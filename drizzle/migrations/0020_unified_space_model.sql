-- Add is_personal column to spaces table for unified space model

ALTER TABLE "spaces" ADD COLUMN "is_personal" boolean NOT NULL DEFAULT false;
