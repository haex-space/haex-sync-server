import type { Context, Next } from 'hono'
import { didAuthMiddleware } from './didAuth'
import { ucanAuthMiddleware } from './ucanAuth'
import { federationAuthMiddleware } from './federationAuth'

/**
 * Auth Dispatcher
 *
 * Routes to the correct auth middleware based on the Authorization header scheme.
 * Supports: UCAN <token>, DID <payload>.<signature>, FEDERATION <payload>.<signature>
 */
export const authDispatcher = async (c: Context, next: Next) => {
  const authHeader = c.req.header('Authorization')

  if (!authHeader) {
    return c.json({ error: 'Authorization header required' }, 401)
  }

  if (authHeader.startsWith('UCAN ')) {
    return ucanAuthMiddleware(c, next)
  }

  if (authHeader.startsWith('DID ')) {
    return didAuthMiddleware(c, next)
  }

  if (authHeader.startsWith('FEDERATION ')) {
    return federationAuthMiddleware(c, next)
  }

  return c.json({ error: 'Unsupported authorization scheme. Use UCAN, DID, or FEDERATION.' }, 401)
}
