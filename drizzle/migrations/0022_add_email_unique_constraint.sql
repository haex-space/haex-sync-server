-- Add unique constraint on email in identities table
-- Ensures the same email address cannot be used by multiple DIDs
CREATE UNIQUE INDEX IF NOT EXISTS "identities_email_unique" ON "identities" ("email");
