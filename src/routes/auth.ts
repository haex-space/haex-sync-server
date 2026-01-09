import { Hono } from 'hono'
import { supabaseAdmin } from '../utils/supabase'
import { db } from '../db'
import { sql } from 'drizzle-orm'
import * as crypto from 'crypto'

const app = new Hono()

interface LoginRequest {
  email: string
  password: string
}

interface LoginResponse {
  access_token: string
  refresh_token: string
  expires_in: number
  expires_at: number
  user: {
    id: string
    email: string
  }
}

/**
 * Hash password using bcrypt-compatible format
 * GoTrue uses bcrypt, so we need to match that format for login to work
 */
async function hashPassword(password: string): Promise<string> {
  // Use pgcrypto's crypt function which is bcrypt-compatible
  const result = await db.execute(
    sql`SELECT extensions.crypt(${password}, extensions.gen_salt('bf')) as hash`
  )
  return (result as any)[0]?.hash || ''
}

/**
 * POST /auth/admin/create-user
 *
 * Admin-only endpoint to create users.
 * Requires the Supabase Service Role Key in the Authorization header.
 *
 * This is for:
 * - E2E tests that need to create test users
 * - Admin tooling
 *
 * Falls back to direct database insertion if GoTrue is not available.
 */
app.post('/admin/create-user', async (c) => {
  try {
    // Verify admin authorization via Service Role Key
    const authHeader = c.req.header('Authorization')
    const serviceKey = process.env.SUPABASE_SERVICE_KEY

    if (!serviceKey) {
      console.error('SUPABASE_SERVICE_KEY not configured')
      return c.json({ error: 'Server misconfigured' }, 500)
    }

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ error: 'Authorization header required' }, 401)
    }

    const providedKey = authHeader.substring(7) // Remove 'Bearer ' prefix
    if (providedKey !== serviceKey) {
      return c.json({ error: 'Invalid service key' }, 403)
    }

    const body = await c.req.json<{ email: string; password: string }>()

    if (!body.email || !body.password) {
      return c.json({ error: 'Email and password are required' }, 400)
    }

    if (body.password.length < 6) {
      return c.json({ error: 'Password must be at least 6 characters' }, 400)
    }

    // Try GoTrue first
    try {
      const { data, error } = await supabaseAdmin.auth.admin.createUser({
        email: body.email,
        password: body.password,
        email_confirm: true,
      })

      if (!error && data.user) {
        return c.json({
          user: {
            id: data.user.id,
            email: data.user.email ?? '',
          },
        }, 201)
      }

      // If GoTrue returned an error about existing user, return 409
      if (error?.message.includes('already') || error?.message.includes('exists')) {
        return c.json({ error: 'User with this email already exists' }, 409)
      }

      // Otherwise, fall through to direct DB insertion
      console.log('GoTrue createUser failed, falling back to direct DB:', error?.message)
    } catch (gotrueError) {
      console.log('GoTrue not available, falling back to direct DB insertion:', (gotrueError as Error).message)
    }

    // Fallback: Direct database insertion (for E2E tests without GoTrue)
    const userId = crypto.randomUUID()
    const now = new Date().toISOString()
    const hashedPassword = await hashPassword(body.password)

    // Check if user already exists
    const existingUser = await db.execute(
      sql`SELECT id FROM auth.users WHERE email = ${body.email}`
    )
    if ((existingUser as any[]).length > 0) {
      return c.json({ error: 'User with this email already exists' }, 409)
    }

    // Insert user directly into auth.users
    await db.execute(sql`
      INSERT INTO auth.users (
        id, email, encrypted_password, email_confirmed_at,
        created_at, updated_at, role, aud
      ) VALUES (
        ${userId}::uuid, ${body.email}, ${hashedPassword},
        ${now}::timestamptz, ${now}::timestamptz, ${now}::timestamptz,
        'authenticated', 'authenticated'
      )
    `)

    return c.json({
      user: {
        id: userId,
        email: body.email,
      },
    }, 201)
  } catch (error) {
    console.error('Admin create user endpoint error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * POST /auth/login
 *
 * Server-side login endpoint that bypasses Turnstile captcha.
 * Uses the Supabase Admin client to authenticate users.
 *
 * This is needed for desktop/mobile apps where Turnstile doesn't work.
 */
app.post('/login', async (c) => {
  try {
    const body = await c.req.json<LoginRequest>()

    if (!body.email || !body.password) {
      return c.json({ error: 'Email and password are required' }, 400)
    }

    // Use admin client to sign in (bypasses captcha)
    const { data, error } = await supabaseAdmin.auth.signInWithPassword({
      email: body.email,
      password: body.password,
    })

    if (error) {
      console.error('Login error:', error.message)
      return c.json({ error: error.message }, 401)
    }

    if (!data.session || !data.user) {
      return c.json({ error: 'Login failed - no session created' }, 401)
    }

    const response: LoginResponse = {
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
      expires_in: data.session.expires_in,
      expires_at: data.session.expires_at ?? 0,
      user: {
        id: data.user.id,
        email: data.user.email ?? '',
      },
    }

    return c.json(response)
  } catch (error) {
    console.error('Login endpoint error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * Verify password using bcrypt
 */
async function verifyPassword(password: string, hash: string): Promise<boolean> {
  const result = await db.execute(
    sql`SELECT extensions.crypt(${password}, ${hash}) = ${hash} as valid`
  )
  return (result as any)[0]?.valid === true
}

/**
 * Generate a simple JWT token for testing
 * In production, this would be handled by GoTrue
 */
function generateTestToken(userId: string, email: string): string {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')
  const now = Math.floor(Date.now() / 1000)
  const payload = Buffer.from(JSON.stringify({
    sub: userId,
    email: email,
    role: 'authenticated',
    aud: 'authenticated',
    iat: now,
    exp: now + 3600, // 1 hour
  })).toString('base64url')

  // Simple signature using service key
  const secret = process.env.SUPABASE_SERVICE_KEY || 'test-secret'
  const signature = crypto.createHmac('sha256', secret)
    .update(`${header}.${payload}`)
    .digest('base64url')

  return `${header}.${payload}.${signature}`
}

/**
 * POST /auth/admin/login
 *
 * Admin-only login endpoint for E2E tests.
 * Requires the Supabase Service Role Key in the Authorization header.
 * Uses direct database authentication, bypassing GoTrue.
 */
app.post('/admin/login', async (c) => {
  try {
    // Verify admin authorization via Service Role Key
    const authHeader = c.req.header('Authorization')
    const serviceKey = process.env.SUPABASE_SERVICE_KEY

    if (!serviceKey) {
      console.error('SUPABASE_SERVICE_KEY not configured')
      return c.json({ error: 'Server misconfigured' }, 500)
    }

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ error: 'Authorization header required' }, 401)
    }

    const providedKey = authHeader.substring(7)
    if (providedKey !== serviceKey) {
      return c.json({ error: 'Invalid service key' }, 403)
    }

    const body = await c.req.json<LoginRequest>()

    if (!body.email || !body.password) {
      return c.json({ error: 'Email and password are required' }, 400)
    }

    // Direct database authentication
    const result = await db.execute(
      sql`SELECT id, email, encrypted_password FROM auth.users WHERE email = ${body.email}`
    )

    const user = (result as any[])[0]
    if (!user) {
      return c.json({ error: 'Invalid email or password' }, 401)
    }

    const passwordValid = await verifyPassword(body.password, user.encrypted_password)
    if (!passwordValid) {
      return c.json({ error: 'Invalid email or password' }, 401)
    }

    // Generate tokens
    const accessToken = generateTestToken(user.id, user.email)
    const refreshToken = crypto.randomUUID()

    // Store refresh token
    await db.execute(sql`
      INSERT INTO auth.refresh_tokens (token, user_id, created_at, updated_at)
      VALUES (${refreshToken}, ${user.id}, now(), now())
    `)

    const response: LoginResponse = {
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: 3600,
      expires_at: Math.floor(Date.now() / 1000) + 3600,
      user: {
        id: user.id,
        email: user.email,
      },
    }

    return c.json(response)
  } catch (error) {
    console.error('Admin login endpoint error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * POST /auth/refresh
 *
 * Refresh an expired access token using a refresh token.
 */
app.post('/refresh', async (c) => {
  try {
    const body = await c.req.json<{ refresh_token: string }>()

    if (!body.refresh_token) {
      return c.json({ error: 'Refresh token is required' }, 400)
    }

    const { data, error } = await supabaseAdmin.auth.refreshSession({
      refresh_token: body.refresh_token,
    })

    if (error) {
      console.error('Refresh error:', error.message)
      return c.json({ error: error.message }, 401)
    }

    if (!data.session || !data.user) {
      return c.json({ error: 'Refresh failed - no session created' }, 401)
    }

    const response: LoginResponse = {
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
      expires_in: data.session.expires_in,
      expires_at: data.session.expires_at ?? 0,
      user: {
        id: data.user.id,
        email: data.user.email ?? '',
      },
    }

    return c.json(response)
  } catch (error) {
    console.error('Refresh endpoint error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

export default app
