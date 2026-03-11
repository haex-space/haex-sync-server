-- Migrate space_members from user_id-based to public_key-based membership
-- This enables federation: members are identified by public key, not local user account

-- Drop old foreign keys and primary key
ALTER TABLE "space_members" DROP CONSTRAINT IF EXISTS "space_members_user_id_users_id_fk";
ALTER TABLE "space_members" DROP CONSTRAINT IF EXISTS "space_members_invited_by_users_id_fk";
ALTER TABLE "space_members" DROP CONSTRAINT IF EXISTS "space_members_space_id_user_id_pk";

-- Drop old columns
ALTER TABLE "space_members" DROP COLUMN IF EXISTS "user_id";

-- Add new columns
ALTER TABLE "space_members" ADD COLUMN "public_key" text NOT NULL DEFAULT '';
ALTER TABLE "space_members" ADD COLUMN "label" text NOT NULL DEFAULT '';
ALTER TABLE "space_members" ADD COLUMN "can_invite" boolean NOT NULL DEFAULT false;

-- Change invited_by from uuid to text (public key of inviter)
ALTER TABLE "space_members" DROP COLUMN IF EXISTS "invited_by";
ALTER TABLE "space_members" ADD COLUMN "invited_by" text;

-- Remove defaults used for migration
ALTER TABLE "space_members" ALTER COLUMN "public_key" DROP DEFAULT;
ALTER TABLE "space_members" ALTER COLUMN "label" DROP DEFAULT;

-- Add new primary key
ALTER TABLE "space_members" ADD CONSTRAINT "space_members_space_id_public_key_pk" PRIMARY KEY ("space_id", "public_key");

--> statement-breakpoint

-- Migrate space_key_grants from user_id-based to public_key-based
ALTER TABLE "space_key_grants" DROP CONSTRAINT IF EXISTS "space_key_grants_user_id_users_id_fk";
ALTER TABLE "space_key_grants" DROP CONSTRAINT IF EXISTS "space_key_grants_granted_by_users_id_fk";
ALTER TABLE "space_key_grants" DROP CONSTRAINT IF EXISTS "space_key_grants_space_id_user_id_generation_pk";

-- Drop old columns
ALTER TABLE "space_key_grants" DROP COLUMN IF EXISTS "user_id";

-- Add new column
ALTER TABLE "space_key_grants" ADD COLUMN "public_key" text NOT NULL DEFAULT '';
ALTER TABLE "space_key_grants" ALTER COLUMN "public_key" DROP DEFAULT;

-- Change granted_by from uuid to text (public key of granter)
ALTER TABLE "space_key_grants" DROP COLUMN IF EXISTS "granted_by";
ALTER TABLE "space_key_grants" ADD COLUMN "granted_by" text;

-- Add new primary key
ALTER TABLE "space_key_grants" ADD CONSTRAINT "space_key_grants_space_id_public_key_generation_pk" PRIMARY KEY ("space_id", "public_key", "generation");
