import { defineConfig, type Config } from "drizzle-kit";

export default defineConfig({
  schema: "./src/db/schema.ts",
  out: "./drizzle/migrations",
  dialect: "postgresql",
  dbCredentials: {
    url: process.env.DATABASE_URL || "",
  },
  // Only include our tables, exclude auth.users (managed by Supabase)
  tablesFilter: ["vault_keys", "sync_changes", "user_storage_credentials", "spaces", "space_members", "space_key_grants", "space_access_tokens", "identities", "auth_challenges", "tiers", "mls_key_packages", "mls_messages", "mls_welcome_messages", "space_invites"],
}) satisfies Config;
