import { Hono } from 'hono'
import { supabaseAdmin } from '../utils/supabase'

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
 * POST /auth/admin/create-user
 *
 * Admin-only endpoint to create users.
 * Requires the Supabase Service Role Key in the Authorization header.
 *
 * This is for:
 * - E2E tests that need to create test users
 * - Admin tooling
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

    // Use GoTrue to create user
    const { data, error } = await supabaseAdmin.auth.admin.createUser({
      email: body.email,
      password: body.password,
      email_confirm: true,
    })

    if (error) {
      // If GoTrue returned an error about existing user, return 409
      if (error.message.includes('already') || error.message.includes('exists')) {
        return c.json({ error: 'User with this email already exists' }, 409)
      }
      console.error('GoTrue createUser failed:', error.message)
      return c.json({ error: error.message }, 500)
    }

    if (!data.user) {
      return c.json({ error: 'User creation failed' }, 500)
    }

    return c.json({
      user: {
        id: data.user.id,
        email: data.user.email ?? '',
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
