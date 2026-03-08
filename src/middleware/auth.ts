import type { Context, Next } from 'hono'
import { createClient } from '@supabase/supabase-js'

const supabaseUrl = process.env.SUPABASE_URL
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY

if (!supabaseUrl || !supabaseAnonKey) {
  throw new Error('SUPABASE_URL and SUPABASE_ANON_KEY must be set in environment variables')
}

export interface UserContext {
  userId: string
  email?: string
  role?: string
}

// Extend Hono context with user info
declare module 'hono' {
  interface ContextVariableMap {
    user: UserContext
  }
}

/**
 * JWT Authentication Middleware
 * Verifies Supabase JWT token from Authorization header and attaches user to context
 */
export const authMiddleware = async (c: Context, next: Next) => {
  // Skip JWT auth if space token already validated by spaceTokenAuthMiddleware
  if (c.get('spaceToken')) {
    return next()
  }

  const authHeader = c.req.header('Authorization')

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ error: 'Unauthorized - Missing or invalid token' }, 401)
  }

  const token = authHeader.substring(7) // Remove 'Bearer ' prefix

  try {
    // Use Supabase client to verify the JWT and get user
    const supabase = createClient(supabaseUrl, supabaseAnonKey)

    const { data: { user }, error } = await supabase.auth.getUser(token)

    if (error || !user) {
      console.error('JWT verification error:', error)
      return c.json({ error: 'Unauthorized - Invalid token' }, 401)
    }

    // Attach user info to context
    c.set('user', {
      userId: user.id,
      email: user.email,
      role: user.role,
    })

    await next()
  } catch (error) {
    console.error('JWT verification error:', error)
    return c.json({ error: 'Unauthorized - Invalid token' }, 401)
  }
}
