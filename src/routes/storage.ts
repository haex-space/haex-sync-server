import { Hono } from 'hono'
import { createClient } from '@supabase/supabase-js'
import { type UserContext } from '../middleware/auth'
import { extractAccessKeyId, verifySignature } from '../utils/awsSignatureV4'
import { getCredentialsByAccessKeyId } from '../services/storageCredentials'
import { getUserBucket, provisionUserStorage } from '../services/minioAdmin'

const storage = new Hono<{
  Variables: {
    user?: UserContext
  }
}>()

// MinIO configuration
const minioEndpoint = process.env.MINIO_ENDPOINT
const minioRootUser = process.env.MINIO_ROOT_USER
const minioRootPassword = process.env.MINIO_ROOT_PASSWORD

// Log warning if MinIO is not configured (storage routes will return 503)
if (!minioEndpoint || !minioRootUser || !minioRootPassword) {
  console.warn('Warning: MinIO not configured. Storage routes will return 503 Service Unavailable.')
}

/**
 * Check if MinIO is configured
 */
function isMinioConfigured(): boolean {
  return !!(minioEndpoint && minioRootUser && minioRootPassword)
}

// Supabase for auth verification (Bearer token)
const supabaseUrl = process.env.SUPABASE_URL
const supabaseServiceKey = process.env.SUPABASE_SERVICE_KEY

if (!supabaseUrl || !supabaseServiceKey) {
  throw new Error('SUPABASE_URL and SUPABASE_SERVICE_KEY must be set for auth')
}

const supabase = createClient(supabaseUrl, supabaseServiceKey)

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
 * Create MinIO auth header using root credentials
 */
function getMinioAuthHeader(): string {
  if (!minioRootUser || !minioRootPassword) {
    throw new Error('MinIO credentials not configured')
  }
  return 'Basic ' + Buffer.from(`${minioRootUser}:${minioRootPassword}`).toString('base64')
}

/**
 * Upload a file to MinIO
 */
async function uploadToMinio(
  bucket: string,
  key: string,
  body: ReadableStream<Uint8Array> | null,
  contentType?: string,
): Promise<Response> {
  const url = `${minioEndpoint}/${bucket}/${key}`

  const headers: Record<string, string> = {
    'Authorization': getMinioAuthHeader(),
  }

  if (contentType) {
    headers['Content-Type'] = contentType
  }

  const response = await fetch(url, {
    method: 'PUT',
    headers,
    body: body,
    duplex: body ? 'half' : undefined,
  } as RequestInit)

  return response
}

/**
 * Download a file from MinIO
 */
async function downloadFromMinio(
  bucket: string,
  key: string,
  rangeHeader?: string,
): Promise<Response> {
  const url = `${minioEndpoint}/${bucket}/${key}`

  const headers: Record<string, string> = {
    'Authorization': getMinioAuthHeader(),
  }

  if (rangeHeader) {
    headers['Range'] = rangeHeader
  }

  const response = await fetch(url, {
    method: 'GET',
    headers,
  })

  return response
}

/**
 * Delete a file from MinIO
 */
async function deleteFromMinio(
  bucket: string,
  key: string,
): Promise<Response> {
  const url = `${minioEndpoint}/${bucket}/${key}`

  const response = await fetch(url, {
    method: 'DELETE',
    headers: {
      'Authorization': getMinioAuthHeader(),
    },
  })

  return response
}

/**
 * Get file metadata from MinIO
 */
async function headFromMinio(
  bucket: string,
  key: string,
): Promise<Response> {
  const url = `${minioEndpoint}/${bucket}/${key}`

  const response = await fetch(url, {
    method: 'HEAD',
    headers: {
      'Authorization': getMinioAuthHeader(),
    },
  })

  return response
}

/**
 * PUT /storage/s3/*
 * Upload a file to user's bucket
 * Path format: /storage/s3/{bucket}/{key}
 */
storage.put('/s3/*', async (c) => {
  if (!isMinioConfigured()) {
    return c.json({ error: 'Storage service not available' }, 503)
  }

  const user = c.get('user')!
  const extracted = extractBucketAndKey(c.req.path, user.userId)

  if (!extracted) {
    return c.json({ error: 'Access denied: invalid bucket' }, 403)
  }

  if (!extracted.key) {
    return c.json({ error: 'Key is required' }, 400)
  }

  try {
    // Ensure user's bucket exists (lazy provisioning)
    await provisionUserStorage(user.userId)

    const contentType = c.req.header('content-type')
    const response = await uploadToMinio(
      extracted.bucket,
      extracted.key,
      c.req.raw.body,
      contentType,
    )

    // Return S3-compatible response
    if (response.ok) {
      // S3 PUT returns 200 with ETag header
      const etag = response.headers.get('ETag') || `"${Date.now()}"`
      return new Response(null, {
        status: 200,
        headers: {
          'ETag': etag,
        },
      })
    }

    // Forward error response
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
  if (!isMinioConfigured()) {
    return c.json({ error: 'Storage service not available' }, 503)
  }

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
    const rangeHeader = c.req.header('range')
    const response = await downloadFromMinio(
      extracted.bucket,
      extracted.key,
      rangeHeader,
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
  if (!isMinioConfigured()) {
    return c.json({ error: 'Storage service not available' }, 503)
  }

  const user = c.get('user')!
  const extracted = extractBucketAndKey(c.req.path, user.userId)

  if (!extracted) {
    return c.json({ error: 'Access denied: invalid bucket' }, 403)
  }

  if (!extracted.key) {
    return c.json({ error: 'Key is required' }, 400)
  }

  try {
    const response = await deleteFromMinio(
      extracted.bucket,
      extracted.key,
    )

    // S3 DELETE returns 204 No Content on success
    if (response.ok) {
      return new Response(null, { status: 204 })
    }

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
  if (!isMinioConfigured()) {
    return c.json({ error: 'Storage service not available' }, 503)
  }

  const user = c.get('user')!
  const extracted = extractBucketAndKey(c.req.path, user.userId)

  if (!extracted) {
    return c.json({ error: 'Access denied: invalid bucket' }, 403)
  }

  if (!extracted.key) {
    return c.json({ error: 'Key is required' }, 400)
  }

  try {
    const response = await headFromMinio(
      extracted.bucket,
      extracted.key,
    )

    if (response.ok) {
      return new Response(null, {
        status: 200,
        headers: {
          'Content-Length': response.headers.get('Content-Length') || '0',
          'Content-Type': response.headers.get('Content-Type') || 'application/octet-stream',
          'Last-Modified': response.headers.get('Last-Modified') || new Date().toUTCString(),
          'ETag': response.headers.get('ETag') || '',
        },
      })
    }

    return new Response(null, {
      status: response.status,
    })
  } catch (error) {
    console.error('Storage HEAD error:', error)
    return c.json({ error: 'Failed to get file info' }, 500)
  }
})

/**
 * Handle list request for a bucket
 * Uses MinIO S3 API and returns S3 ListObjectsV2 XML response
 */
async function handleListRequest(c: any, userId: string): Promise<Response> {
  const prefix = c.req.query('prefix') || ''
  const delimiter = c.req.query('delimiter') || '/'
  const maxKeys = parseInt(c.req.query('max-keys') || '1000', 10)
  const continuationToken = c.req.query('continuation-token') || ''

  try {
    const bucket = getUserBucket(userId)

    // Build MinIO S3 list URL with query params
    const params = new URLSearchParams({
      'list-type': '2', // ListObjectsV2
      'max-keys': String(maxKeys),
    })

    if (prefix) {
      params.set('prefix', prefix)
    }
    if (delimiter) {
      params.set('delimiter', delimiter)
    }
    if (continuationToken) {
      params.set('continuation-token', continuationToken)
    }

    const url = `${minioEndpoint}/${bucket}?${params.toString()}`

    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Authorization': getMinioAuthHeader(),
      },
    })

    if (!response.ok) {
      // If bucket doesn't exist, return empty list
      if (response.status === 404) {
        return new Response(buildS3ListXml(bucket, prefix, [], []), {
          status: 200,
          headers: { 'Content-Type': 'application/xml' },
        })
      }
      return new Response(response.body, {
        status: response.status,
        headers: response.headers,
      })
    }

    // MinIO returns proper S3 XML, just forward it
    const xml = await response.text()
    return new Response(xml, {
      status: 200,
      headers: { 'Content-Type': 'application/xml' },
    })
  } catch (error) {
    console.error('Storage LIST error:', error)
    return c.json({ error: 'Failed to list files' }, 500)
  }
}

/**
 * Build S3 ListObjectsV2 XML response (fallback for empty buckets)
 */
function buildS3ListXml(
  bucket: string,
  prefix: string,
  objects: Array<{ key: string; size: number; lastModified: string }>,
  commonPrefixes: string[],
): string {
  const contentsXml = objects.map(obj => `
    <Contents>
      <Key>${escapeXml(obj.key)}</Key>
      <LastModified>${obj.lastModified}</LastModified>
      <Size>${obj.size}</Size>
      <StorageClass>STANDARD</StorageClass>
    </Contents>`).join('')

  const prefixesXml = commonPrefixes.map(p => `
    <CommonPrefixes>
      <Prefix>${escapeXml(p)}</Prefix>
    </CommonPrefixes>`).join('')

  return `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>${escapeXml(bucket)}</Name>
  <Prefix>${escapeXml(prefix)}</Prefix>
  <KeyCount>${objects.length}</KeyCount>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>${contentsXml}${prefixesXml}
</ListBucketResult>`
}

/**
 * Escape special XML characters
 */
function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')
}

/**
 * GET /storage/s3 (without trailing path)
 * List files in user's bucket (S3 ListObjects)
 * Supports ?prefix= and ?delimiter= query params
 */
storage.get('/s3', async (c) => {
  if (!isMinioConfigured()) {
    return c.json({ error: 'Storage service not available' }, 503)
  }

  const user = c.get('user')!
  return handleListRequest(c, user.userId)
})

export default storage
