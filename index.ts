import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { logger } from 'hono/logger'
import syncRoutes from './src/routes/sync'
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
    supabaseUrl: process.env.SUPABASE_URL || 'not configured',
    supabaseAnonKey: process.env.SUPABASE_ANON_KEY || 'not configured',
  })
})

// Routes
// Note: Auth is handled by Supabase directly from clients
// This server only provides sync endpoints that require authentication
app.route('/sync', syncRoutes)

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

const port = parseInt(process.env.PORT || '3000')

console.log(`🚀 ${packageJson.name} v${packageJson.version} starting on port ${port}`)
console.log(`📝 Environment: ${process.env.NODE_ENV || 'development'}`)
console.log(`🌐 CORS Origins: ${corsOrigin}`)

export default {
  port,
  fetch: app.fetch,
}
