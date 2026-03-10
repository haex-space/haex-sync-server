import { randomBytes } from 'crypto'
import { Hono } from 'hono'
import { eq, and, lt, isNull } from 'drizzle-orm'
import { importUserPublicKeyAsync } from '@haex-space/vault-sdk'
import { supabaseAdmin } from '../utils/supabase'
import { db, identities, authChallenges } from '../db'
import { authMiddleware } from '../middleware/auth'
import packageJson from '../../package.json'

interface SignedClaimPresentation {
  did: string
  publicKey: string
  claims: Record<string, string>
  timestamp: string
  signature: string
}

const app = new Hono()

// ── Helpers ──────────────────────────────────────────────────────────

const PRESENTATION_MAX_AGE_MS = 5 * 60 * 1000 // 5 minutes
const CHALLENGE_TTL_MS = 60 * 1000 // 60 seconds

/**
 * Verify a SignedClaimPresentation's ECDSA signature.
 * Canonical form: did\0timestamp\0type1=value1\0type2=value2\0...
 * (claims sorted alphabetically by type, matching vault-sdk)
 */
async function verifyClaimPresentation(presentation: SignedClaimPresentation): Promise<boolean> {
  try {
    const { did, publicKey: pubKeyBase64, claims, timestamp, signature } = presentation

    const sortedEntries = Object.entries(claims).sort(([a], [b]) => a.localeCompare(b))
    const canonical = [did, timestamp, ...sortedEntries.map(([k, v]) => `${k}=${v}`)].join('\0')
    const data = new TextEncoder().encode(canonical)

    const publicKey = await importUserPublicKeyAsync(pubKeyBase64)
    const sigBytes = Uint8Array.from(atob(signature), ch => ch.charCodeAt(0))

    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      sigBytes,
      data,
    )
  } catch {
    return false
  }
}

function generateRandomPassword(): string {
  return randomBytes(32).toString('hex')
}

// ── Routes ───────────────────────────────────────────────────────────

/**
 * GET /identity-auth/requirements
 * Returns server name, required claims, and supported DID methods.
 */
app.get('/requirements', (c) => {
  return c.json({
    serverName: packageJson.name,
    claims: [
      { type: 'email', required: true, label: 'Email for verification' },
      { type: 'name', required: false, label: 'Display name' },
    ],
    didMethods: ['did:key'],
  })
})

/**
 * POST /identity-auth/register
 * Register a new identity using a signed claim presentation.
 */
app.post('/register', async (c) => {
  try {
    const body = await c.req.json<{
      presentation: SignedClaimPresentation
      encryptedPrivateKey?: string
      privateKeyNonce?: string
      privateKeySalt?: string
    }>()

    const { presentation } = body

    if (!presentation?.did || !presentation?.publicKey || !presentation?.claims || !presentation?.signature || !presentation?.timestamp) {
      return c.json({ error: 'Invalid presentation' }, 400)
    }

    // Check presentation age
    const presentationAge = Date.now() - new Date(presentation.timestamp).getTime()
    if (presentationAge < 0 || presentationAge > PRESENTATION_MAX_AGE_MS) {
      return c.json({ error: 'Presentation expired or timestamp in the future' }, 400)
    }

    // Verify signature
    const valid = await verifyClaimPresentation(presentation)
    if (!valid) {
      return c.json({ error: 'Invalid presentation signature' }, 400)
    }

    // Check required claims
    const email = presentation.claims.email
    if (!email) {
      return c.json({ error: 'Email claim is required' }, 400)
    }

    // Check if DID or email already registered
    const existingByDid = await db.select({ id: identities.id })
      .from(identities)
      .where(eq(identities.did, presentation.did))
      .limit(1)

    if (existingByDid.length > 0) {
      return c.json({ error: 'DID already registered' }, 409)
    }

    const existingByEmail = await db.select({ id: identities.id })
      .from(identities)
      .where(eq(identities.email, email))
      .limit(1)

    if (existingByEmail.length > 0) {
      return c.json({ error: 'Email already registered' }, 409)
    }

    // Create Supabase shadow user (random password, unconfirmed email)
    const { data: userData, error: createError } = await supabaseAdmin.auth.admin.createUser({
      email,
      password: generateRandomPassword(),
      email_confirm: false,
    })

    if (createError || !userData.user) {
      console.error('Failed to create shadow user:', createError?.message)
      return c.json({ error: 'Failed to create user' }, 500)
    }

    // Store identity mapping
    const [identity] = await db.insert(identities).values({
      did: presentation.did,
      publicKey: presentation.publicKey,
      supabaseUserId: userData.user.id,
      email,
      emailVerified: false,
      encryptedPrivateKey: body.encryptedPrivateKey,
      privateKeyNonce: body.privateKeyNonce,
      privateKeySalt: body.privateKeySalt,
    }).returning({ id: identities.id })

    // Send verification email via magiclink (doesn't overwrite shadow user password)
    const { error: linkError } = await supabaseAdmin.auth.admin.generateLink({
      type: 'magiclink',
      email,
    })

    if (linkError) {
      console.error('Failed to send verification email:', linkError.message)
      // Don't fail registration, email can be resent
    }

    return c.json({
      identityId: identity!.id,
      status: 'verification_pending',
    }, 201)
  } catch (error) {
    console.error('Register error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * POST /identity-auth/verify-email
 * Verify email using the OTP token from the verification email.
 */
app.post('/verify-email', async (c) => {
  try {
    const { token } = await c.req.json<{ token: string }>()

    if (!token) {
      return c.json({ error: 'Token is required' }, 400)
    }

    const { data, error } = await supabaseAdmin.auth.verifyOtp({
      token_hash: token,
      type: 'email',
    })

    if (error || !data.user) {
      return c.json({ error: 'Invalid or expired token' }, 400)
    }

    // Mark identity as verified
    await db.update(identities)
      .set({ emailVerified: true, updatedAt: new Date() })
      .where(eq(identities.supabaseUserId, data.user.id))

    return c.json({ status: 'verified' })
  } catch (error) {
    console.error('Verify email error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * POST /identity-auth/resend-verification
 * Resend the verification email for a DID.
 */
app.post('/resend-verification', async (c) => {
  try {
    const { did } = await c.req.json<{ did: string }>()

    if (!did) {
      return c.json({ error: 'DID is required' }, 400)
    }

    const [identity] = await db.select()
      .from(identities)
      .where(eq(identities.did, did))
      .limit(1)

    if (!identity || !identity.email) {
      return c.json({ error: 'Identity not found' }, 404)
    }

    if (identity.emailVerified) {
      return c.json({ error: 'Email already verified' }, 400)
    }

    const { error } = await supabaseAdmin.auth.admin.generateLink({
      type: 'magiclink',
      email: identity.email,
    })

    if (error) {
      console.error('Failed to resend verification email:', error.message)
      return c.json({ error: 'Failed to send verification email' }, 500)
    }

    return c.json({ status: 'verification_sent' })
  } catch (error) {
    console.error('Resend verification error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * POST /identity-auth/challenge
 * Request a challenge nonce for login.
 */
app.post('/challenge', async (c) => {
  try {
    const { did } = await c.req.json<{ did: string }>()

    if (!did) {
      return c.json({ error: 'DID is required' }, 400)
    }

    // Check identity exists and is verified
    const [identity] = await db.select({ id: identities.id, emailVerified: identities.emailVerified })
      .from(identities)
      .where(eq(identities.did, did))
      .limit(1)

    if (!identity) {
      return c.json({ error: 'Identity not found' }, 404)
    }

    if (!identity.emailVerified) {
      return c.json({ error: 'Email not verified' }, 403)
    }

    // Generate nonce
    const nonce = randomBytes(32).toString('hex')
    const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MS)

    // Store challenge
    await db.insert(authChallenges).values({
      did,
      nonce,
      expiresAt,
    })

    // Clean up old challenges for this DID
    await db.delete(authChallenges)
      .where(and(
        eq(authChallenges.did, did),
        lt(authChallenges.expiresAt, new Date()),
      ))

    return c.json({ nonce, expiresAt: expiresAt.toISOString() })
  } catch (error) {
    console.error('Challenge error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * POST /identity-auth/verify
 * Verify a challenge response and create a session.
 */
app.post('/verify', async (c) => {
  try {
    const { did, nonce, signature } = await c.req.json<{
      did: string
      nonce: string
      signature: string
    }>()

    if (!did || !nonce || !signature) {
      return c.json({ error: 'did, nonce, and signature are required' }, 400)
    }

    // Find challenge
    const [challenge] = await db.select()
      .from(authChallenges)
      .where(and(
        eq(authChallenges.did, did),
        eq(authChallenges.nonce, nonce),
        isNull(authChallenges.usedAt),
      ))
      .limit(1)

    if (!challenge) {
      return c.json({ error: 'Challenge not found or already used' }, 400)
    }

    // Check expiry
    if (new Date() > challenge.expiresAt) {
      return c.json({ error: 'Challenge expired' }, 400)
    }

    // Find identity
    const [identity] = await db.select()
      .from(identities)
      .where(eq(identities.did, did))
      .limit(1)

    if (!identity) {
      return c.json({ error: 'Identity not found' }, 404)
    }

    // Verify ECDSA signature over the nonce
    const publicKey = await importUserPublicKeyAsync(identity.publicKey)
    const data = new TextEncoder().encode(nonce)
    const sigBytes = Uint8Array.from(atob(signature), ch => ch.charCodeAt(0))

    const valid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      sigBytes,
      data,
    )

    if (!valid) {
      return c.json({ error: 'Invalid signature' }, 401)
    }

    // Mark challenge as used
    await db.update(authChallenges)
      .set({ usedAt: new Date() })
      .where(eq(authChallenges.id, challenge.id))

    // Create Supabase session via magiclink flow
    if (!identity.email || !identity.supabaseUserId) {
      return c.json({ error: 'Identity has no linked email' }, 500)
    }

    const { data: linkData, error: linkError } = await supabaseAdmin.auth.admin.generateLink({
      type: 'magiclink',
      email: identity.email,
    })

    if (linkError || !linkData.properties?.hashed_token) {
      console.error('Failed to generate magiclink:', linkError?.message)
      return c.json({ error: 'Failed to create session' }, 500)
    }

    const { data: sessionData, error: sessionError } = await supabaseAdmin.auth.verifyOtp({
      token_hash: linkData.properties.hashed_token,
      type: 'magiclink',
    })

    if (sessionError || !sessionData.session) {
      console.error('Failed to verify magiclink:', sessionError?.message)
      return c.json({ error: 'Failed to create session' }, 500)
    }

    return c.json({
      access_token: sessionData.session.access_token,
      refresh_token: sessionData.session.refresh_token,
      expires_in: sessionData.session.expires_in,
      expires_at: sessionData.session.expires_at ?? 0,
      identity: {
        id: identity.id,
        did: identity.did,
        tier: identity.tier,
      },
    })
  } catch (error) {
    console.error('Verify error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * POST /identity-auth/update-recovery
 * Update encrypted private key backup (requires JWT auth).
 */
app.post('/update-recovery', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const { encryptedPrivateKey, privateKeyNonce, privateKeySalt } = await c.req.json<{
      encryptedPrivateKey: string
      privateKeyNonce: string
      privateKeySalt: string
    }>()

    if (!encryptedPrivateKey || !privateKeyNonce || !privateKeySalt) {
      return c.json({ error: 'encryptedPrivateKey, privateKeyNonce, and privateKeySalt are required' }, 400)
    }

    const result = await db.update(identities)
      .set({
        encryptedPrivateKey,
        privateKeyNonce,
        privateKeySalt,
        updatedAt: new Date(),
      })
      .where(eq(identities.supabaseUserId, user.userId))
      .returning({ id: identities.id })

    if (result.length === 0) {
      return c.json({ error: 'Identity not found' }, 404)
    }

    return c.json({ status: 'updated' })
  } catch (error) {
    console.error('Update recovery error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * POST /identity-auth/recover
 * Initiate key recovery for an email.
 * Always returns success to avoid revealing account existence.
 */
app.post('/recover', async (c) => {
  try {
    const { email } = await c.req.json<{ email: string }>()

    if (!email) {
      return c.json({ error: 'Email is required' }, 400)
    }

    // Look up identity (don't reveal if it exists)
    const [identity] = await db.select({ id: identities.id })
      .from(identities)
      .where(eq(identities.email, email))
      .limit(1)

    if (identity) {
      // TODO: Send email with encrypted key data
      console.log(`Recovery requested for identity ${identity.id}`)
    }

    return c.json({ status: 'recovery_sent' })
  } catch (error) {
    console.error('Recover error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

export default app
