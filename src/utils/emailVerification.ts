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
 * Check if the last OTP for this email was already consumed (verified/used).
 * Compares last_sign_in_at with confirmation_sent_at in auth.users.
 * If the user signed in AFTER the OTP was sent, the code was consumed.
 */
async function isOtpConsumedAsync(email: string): Promise<boolean> {
  const { data } = await supabaseAdmin.auth.admin.listUsers()
  const user = data?.users?.find(u => u.email === email)
  if (!user) return false

  const sentAt = user.confirmation_sent_at ? new Date(user.confirmation_sent_at).getTime() : 0
  const signedInAt = user.last_sign_in_at ? new Date(user.last_sign_in_at).getTime() : 0

  return signedInAt > sentAt
}

/**
 * Send a 6-digit OTP code to the user's email via GoTrue SMTP.
 * GoTrue handles code generation, storage, rate limiting, and email delivery.
 *
 * If rate-limited AND the previous code was already consumed (checked via DB),
 * uses the Admin API to invalidate the old token and send a fresh one.
 * If the previous code is still unused, respects the TTL.
 */
export async function sendOtpAsync(email: string): Promise<void> {
  const { error } = await supabaseAdmin.auth.signInWithOtp({ email })
  if (error) {
    if (error.status === 429 || error.message.includes('security purposes')) {
      if (await isOtpConsumedAsync(email)) {
        // Previous code was consumed — bypass rate limit via admin API
        console.log(`[OTP] Previous code consumed for ${email} — bypassing rate limit`)
        await supabaseAdmin.auth.admin.generateLink({ type: 'magiclink', email })
        const { error: retryError } = await supabaseAdmin.auth.signInWithOtp({ email })
        if (retryError) {
          console.log(`[OTP] Retry still limited for ${email} — admin link generated as fallback`)
        } else {
          console.log(`[OTP] New verification code sent to ${email} (after consumed-bypass)`)
        }
        return
      }
      console.log(`[OTP] Rate limited for ${email} — existing OTP still valid`)
      return
    }
    // If SMTP is not configured (e.g., AUTOCONFIRM mode), the email send fails
    // but the user is already confirmed. Don't throw — just log.
    if (error.message.includes('sending') || error.message.includes('SMTP') || error.message.includes('magic link')) {
      console.warn(`[OTP] Email delivery failed for ${email} (SMTP may not be configured): ${error.message}`)
      return
    }
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
