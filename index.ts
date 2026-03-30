import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { logger } from 'hono/logger'
import authRoutes from './src/routes/auth'
import syncRoutes from './src/routes/sync'
import storageRoutes from './src/routes/storage'
import spacesRoutes from './src/routes/spaces'
import mlsRoutes from './src/routes/mls'
import identityAuthRoutes from './src/routes/identity-auth'
import federationRoutes from './src/routes/federation'
import { federationWsApp } from './src/routes/federation.ws'
import { wsApp, websocket } from './src/routes/ws'
import { syncTiersFromEnvAsync } from './src/services/tierConfig'
import { initializeServerIdentityAsync } from './src/services/serverIdentity'
import packageJson from './package.json'

const app = new Hono()

// Parse CORS origins from env
const corsOrigin = process.env.CORS_ORIGIN || '*'
const allowedOrigins = corsOrigin === '*' ? '*' : corsOrigin.split(',').map(o => o.trim())

// Middleware
app.use('*', logger())
app.use(
  '*',
  cors({
    origin: allowedOrigins,
    credentials: true,
  })
)

// Health check
app.get('/', (c) => {
  return c.json({
    name: packageJson.name,
    version: packageJson.version,
    status: 'ok',
    env: process.env.NODE_ENV || 'development',
    supabaseUrl: process.env.SUPABASE_PUBLIC_URL || process.env.SUPABASE_URL || 'not configured',
    supabaseAnonKey: process.env.SUPABASE_ANON_KEY || 'not configured',
  })
})

// Routes
// Identity-based challenge-response auth (public, no auth middleware)
app.route('/identity-auth', identityAuthRoutes)
// Auth routes for server-side login (bypasses Turnstile captcha for desktop/mobile apps)
app.route('/auth', authRoutes)
// Sync routes require authentication via JWT
app.route('/sync', syncRoutes)
// Storage proxy routes for S3-compatible file storage
app.route('/storage', storageRoutes)
// Space routes for shared encrypted spaces
app.route('/spaces', spacesRoutes)
// MLS Delivery Service routes (nested under /spaces/:spaceId/mls/*)
app.route('/spaces', mlsRoutes)
// WebSocket endpoint for real-time push notifications
app.route('/', wsApp)
// Federation endpoints (/.well-known/did.json, /federation/*)
app.route('/', federationRoutes)
// Federation WebSocket for server-to-server notifications
app.route('/', federationWsApp)

// 404 handler
app.notFound((c) => {
  return c.json({ error: 'Not Found' }, 404)
})

// Error handler
app.onError((err, c) => {
  console.error('Server error:', err)
  return c.json(
    {
      error: 'Internal Server Error',
      message: err.message,
    },
    500
  )
})

const port = parseInt(process.env.PORT || '3002')

console.log(`🚀 ${packageJson.name} v${packageJson.version} starting on port ${port}`)
console.log(`📝 Environment: ${process.env.NODE_ENV || 'development'}`)
console.log(`🌐 CORS Origins: ${corsOrigin}`)

// Sync tier configuration from environment variables on startup
syncTiersFromEnvAsync().catch(err => console.error('Failed to sync tiers from env:', err))

// Initialize federation server identity (if configured)
initializeServerIdentityAsync().catch(err => console.error('Failed to initialize federation identity:', err))

export default {
  port,
  fetch: app.fetch,
  websocket,
}
