import { Hono } from 'hono'
import type {
  SyncServerLoginRequest,
  SyncServerLoginResponse,
  StorageConfig,
} from '@haex-space/vault-sdk'
import { supabaseAdmin } from '../utils/supabase'
import { getOrCreateStorageCredentials } from '../services/storageCredentials'

const app = new Hono()

/**
 * Creates the storage config for S3 proxy access.
 * Includes real S3 credentials that work with any S3-compatible client.
 */
async function createStorageConfig(serverUrl: string, userId: string): Promise<StorageConfig> {
  // Get or create S3 credentials for this user
  const credentials = await getOrCreateStorageCredentials(userId)

  return {
    endpoint: `${serverUrl.replace(/\/$/, '')}/storage/s3`,
    bucket: `storage-${userId}`,
    region: 'auto',
    accessKeyId: credentials.accessKeyId,
    secretAccessKey: credentials.secretAccessKey,
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
    const body = await c.req.json<SyncServerLoginRequest>()

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

    // Get server URL from request for storage config
    const serverUrl = new URL(c.req.url).origin

    const response: SyncServerLoginResponse = {
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
      expires_in: data.session.expires_in,
      expires_at: data.session.expires_at ?? 0,
      user: {
        id: data.user.id,
        email: data.user.email ?? '',
      },
      storage_config: await createStorageConfig(serverUrl, data.user.id),
    }

    return c.json(response)
  } catch (error) {
    console.error('Login endpoint error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * GET /auth/storage-credentials
 *
 * Get S3 storage credentials for the authenticated user.
 * Uses the Bearer token from the Authorization header.
 */
app.get('/storage-credentials', async (c) => {
  try {
    const authHeader = c.req.header('Authorization')

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ error: 'Authorization header required' }, 401)
    }

    const token = authHeader.substring(7)

    // Verify the token and get user
    const { data: { user }, error } = await supabaseAdmin.auth.getUser(token)

    if (error || !user) {
      return c.json({ error: 'Invalid or expired token' }, 401)
    }

    // Get server URL from request for storage config
    const serverUrl = new URL(c.req.url).origin

    const storageConfig = await createStorageConfig(serverUrl, user.id)

    return c.json(storageConfig)
  } catch (error) {
    console.error('Storage credentials endpoint error:', error)
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

    // Get server URL from request for storage config
    const serverUrl = new URL(c.req.url).origin

    const response: SyncServerLoginResponse = {
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
      expires_in: data.session.expires_in,
      expires_at: data.session.expires_at ?? 0,
      user: {
        id: data.user.id,
        email: data.user.email ?? '',
      },
      storage_config: await createStorageConfig(serverUrl, data.user.id),
    }

    return c.json(response)
  } catch (error) {
    console.error('Refresh endpoint error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

export default app
