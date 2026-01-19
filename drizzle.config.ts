import { defineConfig, type Config } from "drizzle-kit";

export default defineConfig({
  schema: "./src/db/schema.ts",
  out: "./drizzle/migrations",
  dialect: "postgresql",
  dbCredentials: {
    url: process.env.DATABASE_URL || "",
  },
  // Only include our tables, exclude auth.users (managed by Supabase)
  tablesFilter: ["vault_keys", "sync_changes", "user_storage_credentials"],
}) satisfies Config;
