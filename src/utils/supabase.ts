import { createClient } from '@supabase/supabase-js'

const supabaseUrl = process.env.SUPABASE_URL
const supabaseServiceKey = process.env.SUPABASE_SERVICE_KEY

if (!supabaseUrl || !supabaseServiceKey) {
  throw new Error('SUPABASE_URL and SUPABASE_SERVICE_KEY must be set in environment variables')
}

// Admin client with service role key (bypasses RLS).
// The service-role key bypasses RLS regardless of any Authorization header,
// so we intentionally do NOT expose a "per-user" helper here. Callers that
// need RLS enforcement must use a client initialised with the anon key and
// the user's access token — otherwise RLS will silently be bypassed.
export const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey, {
  auth: {
    autoRefreshToken: false,
    persistSession: false
  }
})
