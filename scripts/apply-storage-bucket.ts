/**
 * Apply Storage Bucket policies and functions to Supabase database
 * Run with: bun run scripts/apply-storage-bucket.ts
 */

import { readFileSync } from "fs";
import postgres from "postgres";

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error("❌ DATABASE_URL environment variable is not set");
  process.exit(1);
}

async function applyStorageBucketAsync() {
  console.log("📦 Applying Storage Bucket configuration to Supabase...");

  // Read SQL file
  const sql = readFileSync("./drizzle/storage-bucket.sql", "utf-8");

  // Connect to database
  const db = postgres(DATABASE_URL);

  try {
    // Execute SQL
    await db.unsafe(sql);
    console.log("✅ Storage Bucket configuration applied successfully!");
  } catch (error) {
    console.error("❌ Failed to apply Storage Bucket configuration:", error);
    process.exit(1);
  } finally {
    await db.end();
  }
}

applyStorageBucketAsync();
