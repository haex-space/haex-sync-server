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
