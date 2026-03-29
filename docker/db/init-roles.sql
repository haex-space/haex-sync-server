-- Create all Supabase internal roles with passwords
-- This runs before Supabase's own init scripts

-- Auth admin (for GoTrue)
DO $$ BEGIN CREATE ROLE supabase_auth_admin WITH LOGIN PASSWORD 'postgres' NOINHERIT CREATEROLE; EXCEPTION WHEN duplicate_object THEN ALTER ROLE supabase_auth_admin WITH LOGIN PASSWORD 'postgres'; END $$;

-- Storage admin
DO $$ BEGIN CREATE ROLE supabase_storage_admin WITH LOGIN PASSWORD 'postgres' NOINHERIT; EXCEPTION WHEN duplicate_object THEN ALTER ROLE supabase_storage_admin WITH LOGIN PASSWORD 'postgres'; END $$;

-- Replication admin
DO $$ BEGIN CREATE ROLE supabase_replication_admin WITH LOGIN PASSWORD 'postgres' REPLICATION; EXCEPTION WHEN duplicate_object THEN ALTER ROLE supabase_replication_admin WITH LOGIN PASSWORD 'postgres'; END $$;

-- Read-only user
DO $$ BEGIN CREATE ROLE supabase_read_only_user WITH LOGIN PASSWORD 'postgres'; EXCEPTION WHEN duplicate_object THEN ALTER ROLE supabase_read_only_user WITH LOGIN PASSWORD 'postgres'; END $$;

-- Authenticated role (used by GoTrue for RLS policies)
DO $$ BEGIN CREATE ROLE authenticated NOLOGIN NOINHERIT; EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Anon role (used by PostgREST for anonymous access)
DO $$ BEGIN CREATE ROLE anon NOLOGIN NOINHERIT; EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Service role (for Supabase service_role key, bypasses RLS)
DO $$ BEGIN CREATE ROLE service_role NOLOGIN NOINHERIT BYPASSRLS; EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Authenticator (PostgREST connects as this, then switches to anon/authenticated/service_role)
DO $$ BEGIN CREATE ROLE authenticator NOINHERIT LOGIN PASSWORD 'postgres'; EXCEPTION WHEN duplicate_object THEN ALTER ROLE authenticator WITH LOGIN PASSWORD 'postgres'; END $$;
GRANT anon TO authenticator;
GRANT authenticated TO authenticator;
GRANT service_role TO authenticator;

-- Schemas
CREATE SCHEMA IF NOT EXISTS auth;
CREATE SCHEMA IF NOT EXISTS _realtime;
CREATE SCHEMA IF NOT EXISTS extensions;

-- Grant auth schema to auth admin
GRANT ALL ON SCHEMA auth TO supabase_auth_admin;
ALTER ROLE supabase_auth_admin SET search_path = 'auth';

-- Grant extensions to public
GRANT USAGE ON SCHEMA extensions TO PUBLIC;
