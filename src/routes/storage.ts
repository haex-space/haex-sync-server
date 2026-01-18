import { Hono } from 'hono'
import { authMiddleware } from '../middleware/auth'

const storage = new Hono()

// All storage routes require authentication
storage.use('/*', authMiddleware)

// Supabase Storage S3 endpoint
const supabaseUrl = process.env.SUPABASE_URL
const supabaseServiceKey = process.env.SUPABASE_SERVICE_KEY

if (!supabaseUrl || !supabaseServiceKey) {
  throw new Error('SUPABASE_URL and SUPABASE_SERVICE_KEY must be set for storage proxy')
}

const storageS3Endpoint = `${supabaseUrl.replace(/\/$/, '')}/storage/v1/s3`

/**
 * Helper to get user's bucket name
 */
function getUserBucket(userId: string): string {
  return `storage-${userId}`
}

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
 */
storage.put('/s3/*', async (c) => {
  const user = c.get('user')
  const key = c.req.path.replace('/storage/s3/', '')

  if (!key) {
    return c.json({ error: 'Key is required' }, 400)
  }

  try {
    const response = await forwardToSupabase(
      'PUT',
      `/${key}`,
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
 * Download a file from user's bucket
 */
storage.get('/s3/*', async (c) => {
  const user = c.get('user')
  const key = c.req.path.replace('/storage/s3/', '')

  if (!key) {
    return c.json({ error: 'Key is required' }, 400)
  }

  try {
    const response = await forwardToSupabase(
      'GET',
      `/${key}`,
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
 */
storage.delete('/s3/*', async (c) => {
  const user = c.get('user')
  const key = c.req.path.replace('/storage/s3/', '')

  if (!key) {
    return c.json({ error: 'Key is required' }, 400)
  }

  try {
    const response = await forwardToSupabase(
      'DELETE',
      `/${key}`,
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
 */
storage.on('HEAD', '/s3/*', async (c) => {
  const user = c.get('user')
  const key = c.req.path.replace('/storage/s3/', '')

  if (!key) {
    return c.json({ error: 'Key is required' }, 400)
  }

  try {
    const response = await forwardToSupabase(
      'HEAD',
      `/${key}`,
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
 * GET /storage/s3 (without trailing path)
 * List files in user's bucket (S3 ListObjects)
 * Supports ?prefix= and ?delimiter= query params
 */
storage.get('/s3', async (c) => {
  const user = c.get('user')
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

    const bucket = getUserBucket(user.userId)
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
})

export default storage
