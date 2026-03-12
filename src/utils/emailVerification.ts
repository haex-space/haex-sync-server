import { supabaseAdmin } from './supabase'

/**
 * Check if a Supabase user's email is confirmed by querying auth.users.
 * Single source of truth — no more emailVerified column in identities.
 */
export async function isEmailVerifiedAsync(supabaseUserId: string): Promise<boolean> {
  const { data, error } = await supabaseAdmin.auth.admin.getUserById(supabaseUserId)
  if (error || !data?.user) return false
  return !!data.user.email_confirmed_at
}

/**
 * Send a 6-digit OTP code to the user's email via GoTrue SMTP.
 * GoTrue handles code generation, storage, rate limiting, and email delivery.
 */
export async function sendOtpAsync(email: string): Promise<void> {
  const { error } = await supabaseAdmin.auth.signInWithOtp({ email })
  if (error) {
    console.error(`[OTP] Failed to send OTP to ${email}:`, error.message)
    throw new Error(`Failed to send verification code: ${error.message}`)
  }
  console.log(`[OTP] Verification code sent to ${email}`)
}

/**
 * Verify a 6-digit OTP code via GoTrue.
 * On success, GoTrue confirms the user's email (sets email_confirmed_at)
 * and returns a session.
 */
export async function verifyOtpAsync(email: string, token: string): Promise<{
  access_token: string
  refresh_token: string
  expires_in: number
  expires_at: number
} | null> {
  const { data, error } = await supabaseAdmin.auth.verifyOtp({
    email,
    token,
    type: 'email',
  })

  if (error) {
    console.error(`[OTP] Verification failed for ${email}:`, error.message)
    return null
  }

  if (!data.session) return null

  return {
    access_token: data.session.access_token,
    refresh_token: data.session.refresh_token,
    expires_in: data.session.expires_in,
    expires_at: data.session.expires_at ?? 0,
  }
}
