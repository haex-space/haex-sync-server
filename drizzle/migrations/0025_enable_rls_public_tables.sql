-- Enable Row Level Security on all public tables
-- service_role bypasses RLS automatically, so no policies are needed.
-- This blocks direct PostgREST access via anon/authenticated JWT.
ALTER TABLE public.spaces ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE public.space_access_tokens ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE public.user_keypairs ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE public.auth_challenges ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE public.tiers ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE public.identities ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE public.space_members ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE public.space_key_grants ENABLE ROW LEVEL SECURITY;
