import { Hono } from 'hono'
import { createClient } from '@supabase/supabase-js'
import { type UserContext } from '../middleware/auth'
import { extractAccessKeyId, verifySignature } from '../utils/awsSignatureV4'
import { getCredentialsByAccessKeyId } from '../services/storageCredentials'

const storage = new Hono<{
  Variables: {
    user?: UserContext
  }
}>()

// Supabase configuration
const supabaseUrl = process.env.SUPABASE_URL
const supabaseServiceKey = process.env.SUPABASE_SERVICE_KEY

if (!supabaseUrl || !supabaseServiceKey) {
  throw new Error('SUPABASE_URL and SUPABASE_SERVICE_KEY must be set for storage proxy')
}

const storageS3Endpoint = `${supabaseUrl.replace(/\/$/, '')}/storage/v1/s3`

// Create Supabase client with service role for bucket operations
const supabase = createClient(supabaseUrl, supabaseServiceKey)

/**
 * Helper to get user's bucket name
 */
function getUserBucket(userId: string): string {
  return `storage-${userId}`
}

/**
 * Extract bucket name and key from path
 * Path format: /s3/{bucket}/{key} or /s3/{bucket}
 * Returns null if bucket doesn't match expected user bucket
 */
function extractBucketAndKey(path: string, userId: string): { bucket: string; key: string } | null {
  // Remove /storage prefix if present (from the full request path)
  let cleanPath = path.replace(/^\/storage/, '')

  // Remove /s3 prefix
  cleanPath = cleanPath.replace(/^\/s3\/?/, '')

  // If path is empty, this is a list request at bucket root
  if (!cleanPath) {
    return { bucket: getUserBucket(userId), key: '' }
  }

  // Split into parts: first part is bucket, rest is key
  const parts = cleanPath.split('/')
  const requestedBucket = parts[0]
  const key = parts.slice(1).join('/')

  // Validate that the requested bucket matches the user's bucket
  const expectedBucket = getUserBucket(userId)
  if (requestedBucket !== expectedBucket) {
    return null // Access denied - wrong bucket
  }

  return { bucket: requestedBucket, key }
}

/**
 * Extract user ID from Bearer token by verifying with Supabase
 */
async function extractUserIdFromBearerToken(token: string): Promise<string | null> {
  try {
    const { data: { user }, error } = await supabase.auth.getUser(token)
    if (error || !user) {
      return null
    }
    return user.id
  } catch {
    return null
  }
}

/**
 * Get all headers as a lowercase-keyed record
 */
function getHeadersRecord(headers: Headers): Record<string, string> {
  const result: Record<string, string> = {}
  headers.forEach((value, key) => {
    result[key.toLowerCase()] = value
  })
  return result
}

/**
 * Custom auth middleware that supports both:
 * - AWS Signature v4 (for S3 clients) - verifies signature cryptographically
 * - Bearer token (for direct HTTP calls) - verifies with Supabase
 */
async function storageAuthMiddleware(c: any, next: () => Promise<void>) {
  const authHeader = c.req.header('authorization')

  if (!authHeader) {
    return c.json({ error: 'Authorization required' }, 401)
  }

  let userId: string | null = null

  // Try AWS Signature v4 first (for S3 clients like rust-s3, rclone, etc.)
  if (authHeader.startsWith('AWS4-HMAC-SHA256')) {
    // Extract access key ID to look up credentials
    const accessKeyId = extractAccessKeyId(authHeader)
    if (!accessKeyId) {
      return c.json({ error: 'Invalid AWS credentials' }, 401)
    }

    // Look up credentials in database
    const credentials = await getCredentialsByAccessKeyId(accessKeyId)
    if (!credentials) {
      return c.json({ error: 'Invalid access key' }, 401)
    }

    // Verify the signature
    const headers = getHeadersRecord(c.req.raw.headers)
    const url = new URL(c.req.url)
    const isValid = verifySignature(
      authHeader,
      headers,
      c.req.method,
      url.pathname,
      url.search.substring(1), // Remove leading '?'
      credentials.secretAccessKey
    )

    if (!isValid) {
      return c.json({ error: 'Signature does not match' }, 403)
    }

    userId = credentials.userId
  }
  // Try Bearer token (for direct HTTP calls)
  else if (authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7)
    userId = await extractUserIdFromBearerToken(token)
    if (!userId) {
      return c.json({ error: 'Invalid or expired token' }, 401)
    }
  }
  else {
    return c.json({ error: 'Unsupported authorization method' }, 401)
  }

  // Set user in context
  c.set('user', { userId, email: '' })

  await next()
}

// Use our custom auth middleware for all storage routes
storage.use('/*', storageAuthMiddleware)

/**
 * Forward request to Supabase Storage S3
 * Uses Service Role Key for authentication
 */
async function forwardToSupabase(
  method: string,
  path: string,
  userId: string,
  body?: ReadableStream<Uint8Array> | null,
  headers?: Headers,
): Promise<Response> {
  const bucket = getUserBucket(userId)

  // Build the full Supabase S3 URL
  // Path format: /{bucket}/{key}
  const url = `${storageS3Endpoint}/${bucket}${path}`

  // Forward relevant headers, replace auth with service key
  const forwardHeaders = new Headers()

  if (headers) {
    // Forward content-type if present
    const contentType = headers.get('content-type')
    if (contentType) {
      forwardHeaders.set('content-type', contentType)
    }

    // Forward content-length if present
    const contentLength = headers.get('content-length')
    if (contentLength) {
      forwardHeaders.set('content-length', contentLength)
    }

    // Forward range header for partial downloads
    const range = headers.get('range')
    if (range) {
      forwardHeaders.set('range', range)
    }
  }

  // Use service key for Supabase auth
  forwardHeaders.set('authorization', `Bearer ${supabaseServiceKey}`)

  const response = await fetch(url, {
    method,
    headers: forwardHeaders,
    body: body,
    duplex: body ? 'half' : undefined,
  } as RequestInit)

  return response
}

/**
 * PUT /storage/s3/*
 * Upload a file to user's bucket
 * Path format: /storage/s3/{bucket}/{key}
 */
storage.put('/s3/*', async (c) => {
  const user = c.get('user')!
  const extracted = extractBucketAndKey(c.req.path, user.userId)

  if (!extracted) {
    return c.json({ error: 'Access denied: invalid bucket' }, 403)
  }

  if (!extracted.key) {
    return c.json({ error: 'Key is required' }, 400)
  }

  try {
    const response = await forwardToSupabase(
      'PUT',
      `/${extracted.key}`,
      user.userId,
      c.req.raw.body,
      c.req.raw.headers,
    )

    // Return the Supabase response
    return new Response(response.body, {
      status: response.status,
      headers: response.headers,
    })
  } catch (error) {
    console.error('Storage PUT error:', error)
    return c.json({ error: 'Failed to upload file' }, 500)
  }
})

/**
 * GET /storage/s3/*
 * Download a file or list bucket contents
 * Path format: /storage/s3/{bucket}/{key} or /storage/s3/{bucket}
 */
storage.get('/s3/*', async (c) => {
  const user = c.get('user')!
  const extracted = extractBucketAndKey(c.req.path, user.userId)

  if (!extracted) {
    return c.json({ error: 'Access denied: invalid bucket' }, 403)
  }

  // If no key, this is a list request
  if (!extracted.key) {
    return handleListRequest(c, user.userId)
  }

  try {
    const response = await forwardToSupabase(
      'GET',
      `/${extracted.key}`,
      user.userId,
      null,
      c.req.raw.headers,
    )

    return new Response(response.body, {
      status: response.status,
      headers: response.headers,
    })
  } catch (error) {
    console.error('Storage GET error:', error)
    return c.json({ error: 'Failed to download file' }, 500)
  }
})

/**
 * DELETE /storage/s3/*
 * Delete a file from user's bucket
 * Path format: /storage/s3/{bucket}/{key}
 */
storage.delete('/s3/*', async (c) => {
  const user = c.get('user')!
  const extracted = extractBucketAndKey(c.req.path, user.userId)

  if (!extracted) {
    return c.json({ error: 'Access denied: invalid bucket' }, 403)
  }

  if (!extracted.key) {
    return c.json({ error: 'Key is required' }, 400)
  }

  try {
    const response = await forwardToSupabase(
      'DELETE',
      `/${extracted.key}`,
      user.userId,
      null,
      c.req.raw.headers,
    )

    return new Response(response.body, {
      status: response.status,
      headers: response.headers,
    })
  } catch (error) {
    console.error('Storage DELETE error:', error)
    return c.json({ error: 'Failed to delete file' }, 500)
  }
})

/**
 * HEAD /storage/s3/*
 * Get file metadata
 * Path format: /storage/s3/{bucket}/{key}
 */
storage.on('HEAD', '/s3/*', async (c) => {
  const user = c.get('user')!
  const extracted = extractBucketAndKey(c.req.path, user.userId)

  if (!extracted) {
    return c.json({ error: 'Access denied: invalid bucket' }, 403)
  }

  if (!extracted.key) {
    return c.json({ error: 'Key is required' }, 400)
  }

  try {
    const response = await forwardToSupabase(
      'HEAD',
      `/${extracted.key}`,
      user.userId,
      null,
      c.req.raw.headers,
    )

    return new Response(null, {
      status: response.status,
      headers: response.headers,
    })
  } catch (error) {
    console.error('Storage HEAD error:', error)
    return c.json({ error: 'Failed to get file info' }, 500)
  }
})

/**
 * Handle list request for a bucket
 */
async function handleListRequest(c: any, userId: string): Promise<Response> {
  const prefix = c.req.query('prefix') || ''
  const delimiter = c.req.query('delimiter') || ''
  const maxKeys = c.req.query('max-keys') || '1000'
  const continuationToken = c.req.query('continuation-token') || ''

  try {
    // Build query string for S3 ListObjectsV2
    const params = new URLSearchParams()
    params.set('list-type', '2') // Use ListObjectsV2
    if (prefix) params.set('prefix', prefix)
    if (delimiter) params.set('delimiter', delimiter)
    if (maxKeys) params.set('max-keys', maxKeys)
    if (continuationToken) params.set('continuation-token', continuationToken)

    const bucket = getUserBucket(userId)
    const url = `${storageS3Endpoint}/${bucket}?${params.toString()}`

    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'authorization': `Bearer ${supabaseServiceKey}`,
      },
    })

    return new Response(response.body, {
      status: response.status,
      headers: response.headers,
    })
  } catch (error) {
    console.error('Storage LIST error:', error)
    return c.json({ error: 'Failed to list files' }, 500)
  }
}

/**
 * GET /storage/s3 (without trailing path)
 * List files in user's bucket (S3 ListObjects)
 * Supports ?prefix= and ?delimiter= query params
 */
storage.get('/s3', async (c) => {
  const user = c.get('user')!
  return handleListRequest(c, user.userId)
})

export default storage
