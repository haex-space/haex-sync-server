/**
 * Tests for the listUsers pagination fix (5.1).
 *
 * The original `isOtpConsumedAsync` issued a single `listUsers()` call, which
 * returns only 50 rows by default. Users beyond that page were silently
 * invisible, which short-circuited the "consumed OTP" check and allowed the
 * rate-limit bypass path to become a sinkhole (retries always hit the
 * "treat as not consumed" branch).
 *
 * We exercise the real `isOtpConsumedAsync` via `sendOtpAsync` — the only
 * mock is Supabase's admin client, because we can't call a real GoTrue here.
 *
 * `isOtpConsumedAsync` isn't exported from the module, so we test the
 * behaviour through the public `sendOtpAsync` which drives it.
 */

import { describe, test, expect, mock, beforeAll, beforeEach } from 'bun:test'

// ── Mutable harness state (controlled per test) ─────────────────────────

interface FakeUser {
  email: string
  confirmation_sent_at: string | null
  last_sign_in_at: string | null
}

let usersByPage: FakeUser[][] = []
let signInWithOtpBehavior: 'ok' | 'rate-limit' | 'smtp-error' = 'ok'
let adminGenerateLinkCalls = 0
let adminListPages: Array<{ page: number; perPage: number }> = []

mock.module('../src/utils/supabase', () => ({
  supabaseAdmin: {
    auth: {
      signInWithOtp: async () => {
        if (signInWithOtpBehavior === 'rate-limit') {
          return { error: { status: 429, message: 'security purposes' } }
        }
        if (signInWithOtpBehavior === 'smtp-error') {
          return { error: { status: 500, message: 'error sending email' } }
        }
        return { error: null }
      },
      admin: {
        listUsers: async ({ page, perPage }: { page: number; perPage: number } = { page: 1, perPage: 50 }) => {
          adminListPages.push({ page, perPage })
          const batch = usersByPage[page - 1] ?? []
          return { data: { users: batch }, error: null }
        },
        generateLink: async () => {
          adminGenerateLinkCalls++
          return { data: { properties: {} }, error: null }
        },
      },
    },
  },
}))

let sendOtpAsync: (email: string) => Promise<void>

beforeAll(async () => {
  ({ sendOtpAsync } = await import('../src/utils/emailVerification'))
})

beforeEach(() => {
  usersByPage = []
  signInWithOtpBehavior = 'ok'
  adminGenerateLinkCalls = 0
  adminListPages = []
})

// ── Tests ───────────────────────────────────────────────────────────────

describe('sendOtpAsync — listUsers pagination (fix 5.1)', () => {
  test('happy path: signInWithOtp succeeds, no listUsers call needed', async () => {
    signInWithOtpBehavior = 'ok'
    await sendOtpAsync('alice@example.com')
    expect(adminListPages.length).toBe(0)
  })

  test('rate-limited: finds user on first page and treats consumed OTP as not-consumed', async () => {
    signInWithOtpBehavior = 'rate-limit'
    usersByPage = [[
      {
        email: 'alice@example.com',
        confirmation_sent_at: new Date(Date.now() - 60_000).toISOString(),
        last_sign_in_at: null,
      },
    ]]

    await sendOtpAsync('alice@example.com')
    // Unconsumed OTP branch: no admin.generateLink call (respects TTL).
    expect(adminGenerateLinkCalls).toBe(0)
    expect(adminListPages.length).toBeGreaterThanOrEqual(1)
  })

  test('rate-limited: paginates past page 1 to find user and detect consumed OTP', async () => {
    signInWithOtpBehavior = 'rate-limit'
    // Fill first 2 pages with unrelated users, put our target on page 3.
    const fillerPage: FakeUser[] = Array.from({ length: 200 }, (_, i) => ({
      email: `unrelated${i}@example.com`,
      confirmation_sent_at: null,
      last_sign_in_at: null,
    }))
    const consumedTarget: FakeUser = {
      email: 'bob@example.com',
      confirmation_sent_at: new Date(Date.now() - 60_000).toISOString(),
      last_sign_in_at: new Date(Date.now() - 30_000).toISOString(), // signed in AFTER sent
    }
    usersByPage = [fillerPage, fillerPage, [consumedTarget]]

    await sendOtpAsync('bob@example.com')

    // Consumed-OTP branch: admin.generateLink was called to bypass rate limit.
    expect(adminGenerateLinkCalls).toBe(1)
    // Pagination actually advanced across pages.
    expect(adminListPages.length).toBe(3)
    expect(adminListPages.map(p => p.page)).toEqual([1, 2, 3])
  })

  test('rate-limited: returns not-consumed if user is in DB but OTP still fresh', async () => {
    signInWithOtpBehavior = 'rate-limit'
    usersByPage = [[
      {
        email: 'charlie@example.com',
        confirmation_sent_at: new Date().toISOString(),
        last_sign_in_at: new Date(Date.now() - 10 * 60_000).toISOString(), // signed in BEFORE sent
      },
    ]]

    await sendOtpAsync('charlie@example.com')
    expect(adminGenerateLinkCalls).toBe(0)
  })

  test('rate-limited: unknown email (never existed) — bails cleanly without error', async () => {
    signInWithOtpBehavior = 'rate-limit'
    usersByPage = [[
      { email: 'someone-else@example.com', confirmation_sent_at: null, last_sign_in_at: null },
    ]]

    await sendOtpAsync('unknown@example.com')
    expect(adminGenerateLinkCalls).toBe(0)
  })

  test('rate-limited: pagination stops at last partial page (no infinite loop)', async () => {
    signInWithOtpBehavior = 'rate-limit'
    // Provide 2 pages, second is short so loop must terminate.
    usersByPage = [
      Array.from({ length: 200 }, () => ({ email: 'x@y', confirmation_sent_at: null, last_sign_in_at: null })),
      [{ email: 'short-page@y', confirmation_sent_at: null, last_sign_in_at: null }],
    ]

    await sendOtpAsync('never-there@example.com')
    // Should have probed page 1 and page 2, then stopped (partial page).
    expect(adminListPages.length).toBe(2)
    expect(adminListPages[1]!.page).toBe(2)
  })

  test('rate-limited: pagination is capped (never iterates forever)', async () => {
    signInWithOtpBehavior = 'rate-limit'
    // Every page returns a full page so the natural break never triggers.
    const page: FakeUser[] = Array.from({ length: 200 }, () => ({
      email: 'never-matches@nope',
      confirmation_sent_at: null,
      last_sign_in_at: null,
    }))
    usersByPage = Array.from({ length: 100 }, () => page)

    await sendOtpAsync('search-target@example.com')
    // The implementation caps at 50 pages.
    expect(adminListPages.length).toBeLessThanOrEqual(50)
  })

  test('SMTP error (AUTOCONFIRM): swallowed, listUsers is not touched', async () => {
    signInWithOtpBehavior = 'smtp-error'
    await sendOtpAsync('smtp-off@example.com')
    expect(adminListPages.length).toBe(0)
  })
})
