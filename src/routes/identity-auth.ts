import { randomBytes, createHash } from 'crypto'
import { Hono } from 'hono'
import { eq, and, lt, isNull } from 'drizzle-orm'
import { importUserPublicKeyAsync, verifyClaimPresentationAsync } from '@haex-space/vault-sdk'
import type { SignedClaimPresentation } from '@haex-space/vault-sdk'
import { supabaseAdmin } from '../utils/supabase'
import { db, identities, authChallenges } from '../db'
import { authMiddleware } from '../middleware/auth'
import packageJson from '../../package.json'

const app = new Hono()

// ── Helpers ──────────────────────────────────────────────────────────

const PRESENTATION_MAX_AGE_MS = 5 * 60 * 1000 // 5 minutes
const CHALLENGE_TTL_MS = 60 * 1000 // 60 seconds
const VERIFICATION_CODE_TTL_MS = 10 * 60 * 1000 // 10 minutes

function generateRandomPassword(): string {
  return randomBytes(32).toString('hex')
}

function generateVerificationCode(): string {
  const num = parseInt(randomBytes(4).toString('hex'), 16) % 1_000_000
  return num.toString().padStart(6, '0')
}

function hashVerificationCode(code: string): string {
  return createHash('sha256').update(code).digest('hex')
}

async function storeAndLogVerificationCode(did: string, email: string): Promise<void> {
  const code = generateVerificationCode()
  const codeHash = hashVerificationCode(code)
  const expiresAt = new Date(Date.now() + VERIFICATION_CODE_TTL_MS)

  await db.update(identities)
    .set({
      verificationCode: codeHash,
      verificationCodeExpiresAt: expiresAt,
      updatedAt: new Date(),
    })
    .where(eq(identities.did, did))

  // In dev mode, log the code to console
  console.log(`[VERIFICATION] Code for ${email} (DID ${did.slice(0, 30)}...): ${code}`)

  // TODO: In prod, send via email (GoTrue/Supabase email templates)
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
    const valid = await verifyClaimPresentationAsync(presentation)
    if (!valid) {
      return c.json({ error: 'Invalid presentation signature' }, 400)
    }

    // Check required claims
    const email = presentation.claims.email
    if (!email) {
      return c.json({ error: 'Email claim is required' }, 400)
    }

    // Check if DID already registered
    const [existingByDid] = await db.select({
      id: identities.id,
      did: identities.did,
      email: identities.email,
      emailVerified: identities.emailVerified,
      supabaseUserId: identities.supabaseUserId,
    })
      .from(identities)
      .where(eq(identities.did, presentation.did))
      .limit(1)

    if (existingByDid) {
      const emailChanged = existingByDid.email !== email

      if (emailChanged) {
        // Email changed — update and require re-verification
        await db.update(identities)
          .set({
            email,
            emailVerified: false,
            updatedAt: new Date(),
          })
          .where(eq(identities.did, presentation.did))

        // Update Supabase shadow user email if we have one
        if (existingByDid.supabaseUserId) {
          await supabaseAdmin.auth.admin.updateUserById(existingByDid.supabaseUserId, {
            email,
            email_confirm: false,
          })
        }

        await storeAndLogVerificationCode(existingByDid.did, email)
        return c.json({
          identityId: existingByDid.id,
          did: existingByDid.did,
          status: 'verification_pending',
        }, 200)
      }

      if (existingByDid.emailVerified) {
        // Same email, already verified — proceed to login
        return c.json({ error: 'DID already registered', did: existingByDid.did }, 409)
      }

      // Same email, not verified yet — resend verification code
      await storeAndLogVerificationCode(existingByDid.did, existingByDid.email!)
      return c.json({
        identityId: existingByDid.id,
        did: existingByDid.did,
        status: 'verification_pending',
      }, 200)
    }

    // Check if email is used by a different DID
    const existingByEmail = await db.select({ id: identities.id })
      .from(identities)
      .where(eq(identities.email, email))
      .limit(1)

    if (existingByEmail.length > 0) {
      return c.json({ error: 'Email already registered by another identity' }, 409)
    }

    // Create Supabase shadow user (random password, unconfirmed email)
    let supabaseUserId: string

    const { data: userData, error: createError } = await supabaseAdmin.auth.admin.createUser({
      email,
      password: generateRandomPassword(),
      email_confirm: false,
    })

    if (createError || !userData.user) {
      // User may already exist in Supabase auth (orphaned after identity cleanup)
      if (createError?.status === 422 || createError?.message?.includes('already been registered')) {
        const { data: linkData } = await supabaseAdmin.auth.admin.generateLink({
          type: 'magiclink',
          email,
        })
        if (linkData?.user?.id) {
          console.log(`[REGISTER] Reusing existing Supabase user for ${email}`)
          supabaseUserId = linkData.user.id
        } else {
          console.error('Failed to create or find shadow user:', createError?.message)
          return c.json({ error: 'Failed to create user' }, 500)
        }
      } else {
        console.error('Failed to create shadow user:', createError?.message)
        return c.json({ error: 'Failed to create user' }, 500)
      }
    } else {
      supabaseUserId = userData.user.id
    }

    // Store identity mapping
    const [identity] = await db.insert(identities).values({
      did: presentation.did,
      publicKey: presentation.publicKey,
      supabaseUserId,
      email,
      emailVerified: false,
      encryptedPrivateKey: body.encryptedPrivateKey,
      privateKeyNonce: body.privateKeyNonce,
      privateKeySalt: body.privateKeySalt,
    }).returning({ id: identities.id })

    // Generate and store verification code
    await storeAndLogVerificationCode(presentation.did, email)

    return c.json({
      identityId: identity!.id,
      did: presentation.did,
      status: 'verification_pending',
    }, 201)
  } catch (error) {
    console.error('Register error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * POST /identity-auth/verify-email
 * Verify email using a 6-digit OTP code.
 */
app.post('/verify-email', async (c) => {
  try {
    const { did, code } = await c.req.json<{ did: string; code: string }>()

    if (!did || !code) {
      return c.json({ error: 'did and code are required' }, 400)
    }

    const [identity] = await db.select()
      .from(identities)
      .where(eq(identities.did, did))
      .limit(1)

    if (!identity) {
      return c.json({ error: 'Identity not found' }, 404)
    }

    if (identity.emailVerified) {
      return c.json({ status: 'already_verified' })
    }

    if (!identity.verificationCode || !identity.verificationCodeExpiresAt) {
      return c.json({ error: 'No verification code pending' }, 400)
    }

    if (new Date() > identity.verificationCodeExpiresAt) {
      return c.json({ error: 'Verification code expired' }, 400)
    }

    const codeHash = hashVerificationCode(code)
    if (codeHash !== identity.verificationCode) {
      return c.json({ error: 'Invalid verification code' }, 400)
    }

    // Mark as verified, clear the code
    await db.update(identities)
      .set({
        emailVerified: true,
        verificationCode: null,
        verificationCodeExpiresAt: null,
        updatedAt: new Date(),
      })
      .where(eq(identities.id, identity.id))

    // Also confirm the Supabase shadow user's email
    if (identity.supabaseUserId) {
      await supabaseAdmin.auth.admin.updateUserById(identity.supabaseUserId, {
        email_confirm: true,
      })
    }

    return c.json({ status: 'verified' })
  } catch (error) {
    console.error('Verify email error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * POST /identity-auth/resend-verification
 * Resend the verification code for a DID.
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

    await storeAndLogVerificationCode(did, identity.email)

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
