# GoTrue OTP Migration — Remove Custom Verification Logic

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace custom OTP code generation/storage/verification with GoTrue's native OTP, and remove `emailVerified`/`verificationCode`/`verificationCodeExpiresAt` from the `identities` table — single source of truth is `auth.users.email_confirmed_at`.

**Architecture:** The sync server currently generates its own 6-digit codes, stores SHA-256 hashes in the `identities` table, and never actually sends them (just console.log). We replace this with `supabaseAdmin.auth.signInWithOtp({ email })` to send codes via GoTrue's SMTP, and `supabaseAdmin.auth.verifyOtp()` to verify them. Email verification status is read from Supabase `auth.users` via the admin API — no more `emailVerified` column.

**Tech Stack:** Supabase JS v2 (`@supabase/supabase-js`), Drizzle ORM, Hono, PostgreSQL, Bun

**Affected Repos:**
- `haex-sync-server` — server-side OTP logic + schema
- `haex-vault` — client-side verify-email call (minor: request body change)

---

## Task 1: Add `isEmailVerifiedAsync` helper

Replace all `identity.emailVerified` checks with a helper that queries Supabase `auth.users` via the admin API.

**Files:**
- Create: `src/utils/emailVerification.ts`

**Step 1: Create the helper module**

```typescript
// src/utils/emailVerification.ts
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
```

**Step 2: Commit**

```bash
git add src/utils/emailVerification.ts
git commit -m "feat: add GoTrue OTP helpers for email verification"
```

---

## Task 2: Rewrite `identity-auth.ts` — registration flow

Replace custom OTP with GoTrue OTP in the `/register` endpoint.

**Files:**
- Modify: `src/routes/identity-auth.ts`

**Step 1: Remove old helpers, add new imports**

Remove these from the top of the file:
- `VERIFICATION_CODE_TTL_MS` constant
- `generateVerificationCode()` function
- `hashVerificationCode()` function
- `storeAndLogVerificationCode()` function

Add import:
```typescript
import { isEmailVerifiedAsync, sendOtpAsync } from '../utils/emailVerification'
```

**Step 2: Update `/register` endpoint**

Replace all `storeAndLogVerificationCode(did, email)` calls with `await sendOtpAsync(email)`.

Replace all `emailVerified: false` in `db.insert`/`db.update` — remove these since the column won't exist.

Replace `if (existingByDid.emailVerified)` check with:
```typescript
if (existingByDid.supabaseUserId && await isEmailVerifiedAsync(existingByDid.supabaseUserId)) {
```

In the `db.insert(identities).values(...)` for new registrations, remove:
- `emailVerified: false`

In the `db.select(...)` for existing DID check, remove:
- `emailVerified: identities.emailVerified`

For the email-changed branch, remove:
```typescript
await db.update(identities).set({ emailVerified: false, ... })
```
Keep only the `email` and `updatedAt` update. The `email_confirm: false` on the Supabase user already handles the unverified state.

For the "same email, not verified yet" branch, replace:
```typescript
// Old: check emailVerified field
if (existingByDid.emailVerified) { ... }
// Same email, not verified yet — resend verification code
await storeAndLogVerificationCode(...)
```
With:
```typescript
if (existingByDid.supabaseUserId && await isEmailVerifiedAsync(existingByDid.supabaseUserId)) {
  // Same email, already verified — proceed to login
  return c.json({ error: 'DID already registered', did: existingByDid.did }, 409)
}
// Same email, not verified yet — resend OTP
await sendOtpAsync(existingByDid.email!)
```

**Step 3: Commit**

```bash
git add src/routes/identity-auth.ts
git commit -m "feat: replace custom OTP with GoTrue in register flow"
```

---

## Task 3: Rewrite `verify-email` endpoint

**Files:**
- Modify: `src/routes/identity-auth.ts`

**Step 1: Rewrite the endpoint**

Replace the entire `/verify-email` handler. The new version:
- Looks up identity by DID to get the email
- Calls `verifyOtpAsync(email, code)` — GoTrue handles all validation
- No more manual hash comparison, expiry check, or `emailVerified` update
- No more `email_confirm: true` admin call (GoTrue does this automatically on OTP verify)

```typescript
app.post('/verify-email', async (c) => {
  try {
    const { did, code } = await c.req.json<{ did: string; code: string }>()

    if (!did || !code) {
      return c.json({ error: 'did and code are required' }, 400)
    }

    const [identity] = await db.select({
      id: identities.id,
      email: identities.email,
      supabaseUserId: identities.supabaseUserId,
    })
      .from(identities)
      .where(eq(identities.did, did))
      .limit(1)

    if (!identity || !identity.email) {
      return c.json({ error: 'Identity not found' }, 404)
    }

    if (identity.supabaseUserId && await isEmailVerifiedAsync(identity.supabaseUserId)) {
      return c.json({ status: 'already_verified' })
    }

    const session = await verifyOtpAsync(identity.email, code)
    if (!session) {
      return c.json({ error: 'Invalid or expired verification code' }, 400)
    }

    return c.json({ status: 'verified' })
  } catch (error) {
    console.error('Verify email error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})
```

**Step 2: Commit**

```bash
git add src/routes/identity-auth.ts
git commit -m "feat: verify-email now uses GoTrue OTP verification"
```

---

## Task 4: Rewrite `resend-verification` endpoint

**Files:**
- Modify: `src/routes/identity-auth.ts`

**Step 1: Rewrite the endpoint**

```typescript
app.post('/resend-verification', async (c) => {
  try {
    const { did } = await c.req.json<{ did: string }>()

    if (!did) {
      return c.json({ error: 'DID is required' }, 400)
    }

    const [identity] = await db.select({
      email: identities.email,
      supabaseUserId: identities.supabaseUserId,
    })
      .from(identities)
      .where(eq(identities.did, did))
      .limit(1)

    if (!identity || !identity.email) {
      return c.json({ error: 'Identity not found' }, 404)
    }

    if (identity.supabaseUserId && await isEmailVerifiedAsync(identity.supabaseUserId)) {
      return c.json({ error: 'Email already verified' }, 400)
    }

    await sendOtpAsync(identity.email)

    return c.json({ status: 'verification_sent' })
  } catch (error) {
    console.error('Resend verification error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})
```

**Step 2: Commit**

```bash
git add src/routes/identity-auth.ts
git commit -m "feat: resend-verification now uses GoTrue OTP"
```

---

## Task 5: Rewrite `challenge` endpoint

**Files:**
- Modify: `src/routes/identity-auth.ts`

**Step 1: Replace `emailVerified` check**

In the `/challenge` endpoint, replace:
```typescript
const [identity] = await db.select({ id: identities.id, emailVerified: identities.emailVerified })
  ...
if (!identity.emailVerified) {
```

With:
```typescript
const [identity] = await db.select({
  id: identities.id,
  supabaseUserId: identities.supabaseUserId,
})
  .from(identities)
  .where(eq(identities.did, did))
  .limit(1)

if (!identity) {
  return c.json({ error: 'Identity not found' }, 404)
}

if (!identity.supabaseUserId || !await isEmailVerifiedAsync(identity.supabaseUserId)) {
  return c.json({ error: 'Email not verified' }, 403)
}
```

**Step 2: Commit**

```bash
git add src/routes/identity-auth.ts
git commit -m "feat: challenge endpoint checks email via GoTrue"
```

---

## Task 6: Rewrite `recover-request` and `recover-verify`

**Files:**
- Modify: `src/routes/identity-auth.ts`

**Step 1: Rewrite `recover-request`**

```typescript
app.post('/recover-request', async (c) => {
  try {
    const { email } = await c.req.json<{ email: string }>()

    if (!email) {
      return c.json({ error: 'Email is required' }, 400)
    }

    const [identity] = await db.select({
      id: identities.id,
      supabaseUserId: identities.supabaseUserId,
    })
      .from(identities)
      .where(eq(identities.email, email))
      .limit(1)

    if (identity?.supabaseUserId && await isEmailVerifiedAsync(identity.supabaseUserId)) {
      await sendOtpAsync(email)
    }

    // Always return success to avoid revealing account existence
    return c.json({ status: 'otp_sent' })
  } catch (error) {
    console.error('Recover request error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})
```

**Step 2: Rewrite `recover-verify`**

Replace custom hash verification with GoTrue OTP verification:

```typescript
app.post('/recover-verify', async (c) => {
  try {
    const { email, code } = await c.req.json<{ email: string; code: string }>()

    if (!email || !code) {
      return c.json({ error: 'email and code are required' }, 400)
    }

    // Verify OTP via GoTrue
    const otpSession = await verifyOtpAsync(email, code)
    if (!otpSession) {
      return c.json({ error: 'Invalid verification code' }, 400)
    }

    // Look up identity by email
    const [identity] = await db.select()
      .from(identities)
      .where(eq(identities.email, email))
      .limit(1)

    if (!identity) {
      return c.json({ error: 'Invalid verification code' }, 400)
    }

    // Check if recovery key data exists
    if (!identity.encryptedPrivateKey || !identity.privateKeyNonce || !identity.privateKeySalt) {
      return c.json({ error: 'No recovery key stored for this account' }, 404)
    }

    // Use the session from OTP verification directly (user proved identity)
    return c.json({
      did: identity.did,
      publicKey: identity.publicKey,
      encryptedPrivateKey: identity.encryptedPrivateKey,
      privateKeyNonce: identity.privateKeyNonce,
      privateKeySalt: identity.privateKeySalt,
      session: otpSession,
      identity: {
        id: identity.id,
        did: identity.did,
        tier: identity.tier,
      },
    })
  } catch (error) {
    console.error('Recover verify error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})
```

Note: The old `recover-verify` generated a magiclink session manually. The new version gets a session for free from `verifyOtpAsync` — cleaner.

**Step 3: Commit**

```bash
git add src/routes/identity-auth.ts
git commit -m "feat: recovery flow now uses GoTrue OTP"
```

---

## Task 7: Remove `emailVerified` + verification columns from schema

**Files:**
- Modify: `src/db/schema.ts`
- Create: `drizzle/migrations/0024_remove_custom_verification_columns.sql`

**Step 1: Update Drizzle schema**

In `src/db/schema.ts`, remove these three fields from the `identities` table:

```typescript
// REMOVE these lines:
emailVerified: boolean('email_verified').notNull().default(false),
verificationCode: text('verification_code'),
verificationCodeExpiresAt: timestamp('verification_code_expires_at', { withTimezone: true }),
```

**Step 2: Create SQL migration**

```sql
-- Remove custom email verification columns from identities table.
-- Email verification is now handled by GoTrue (auth.users.email_confirmed_at).

ALTER TABLE "identities" DROP COLUMN IF EXISTS "email_verified";
ALTER TABLE "identities" DROP COLUMN IF EXISTS "verification_code";
ALTER TABLE "identities" DROP COLUMN IF EXISTS "verification_code_expires_at";
```

**Step 3: Commit**

```bash
git add src/db/schema.ts drizzle/migrations/0024_remove_custom_verification_columns.sql
git commit -m "feat: remove emailVerified and verification columns from identities"
```

---

## Task 8: Verify no remaining references to removed fields

**Step 1: Grep for removed fields**

```bash
grep -rn 'emailVerified\|verificationCode\|verificationCodeExpiresAt\|email_verified\|verification_code\|storeAndLogVerification\|generateVerificationCode\|hashVerificationCode' src/
```

Expected: zero matches.

**Step 2: Grep for old helper references**

```bash
grep -rn 'VERIFICATION_CODE_TTL_MS' src/
```

Expected: zero matches.

**Step 3: Type-check**

```bash
bun run build 2>&1 || bunx tsc --noEmit
```

Expected: no type errors related to removed fields.

---

## Task 9: Client-side update (haex-vault)

The API contract for `/verify-email`, `/resend-verification`, `/recover-request`, `/recover-verify` stays the same (same request/response shapes). But verify the client still works.

**Files:**
- Review (no changes expected): `src/composables/useCreateSyncConnection.ts`
- Review (no changes expected): `src/composables/useIdentityRecovery.ts`

**Step 1: Verify client compatibility**

The client sends:
- `POST /verify-email` with `{ did, code }` — server still accepts this ✓
- `POST /resend-verification` with `{ did }` — unchanged ✓
- `POST /recover-request` with `{ email }` — unchanged ✓
- `POST /recover-verify` with `{ email, code }` — unchanged ✓

No client changes needed. The API contracts are preserved.

**Step 2: Commit (if any changes needed)**

Only if something breaks during testing.

---

## Task 10: Deploy and verify

**Step 1: Build and push Docker image**

Ensure CI passes, image is built, Watchtower picks it up (or manual deploy).

**Step 2: Run migration on production DB**

```bash
ssh haex@haex.space
cd haex-sync-server
docker exec haex-sync-server-haex-sync-server-1 \
  psql "$DATABASE_URL" -f /app/drizzle/migrations/0024_remove_custom_verification_columns.sql
```

Or if migrations run automatically on container start, just redeploy.

**Step 3: Test end-to-end**

1. Register a new identity → should receive OTP email from GoTrue
2. Enter OTP → should verify successfully
3. Recovery flow → should send OTP and return encrypted key after verification
4. Re-login with verified identity → challenge should work

---

## Risk Notes

- **GoTrue rate limiting**: GoTrue has built-in rate limits for OTP (default 60s between sends). This is a feature, not a bug — prevents abuse. But the client should handle 429 responses gracefully.
- **GoTrue OTP format**: GoTrue sends 6-digit numeric codes by default, same as the old custom implementation. No client UI changes needed.
- **`signInWithOtp` behavior**: If `DISABLE_SIGNUP=false`, calling `signInWithOtp` for a non-existent email may create a new Supabase user. Since we always create the shadow user first in `/register`, this shouldn't be an issue. But worth monitoring.
- **Email template**: GoTrue uses its default OTP email template. Can be customized via GoTrue config or Supabase dashboard if needed later.
