import { Hono } from 'hono'
import { didToPublicKey } from '@haex-space/ucan'
import { eq } from 'drizzle-orm'
import { extractAccessKeyId, verifySignature } from '../utils/awsSignatureV4'
import { getCredentialsByAccessKeyId } from '../services/storageCredentials'
import { provisionUserStorage } from '../services/minioAdmin'
import { db, identities } from '../db'

// Re-export utilities from storageUtils for backwards compatibility
export {
  getUserBucket,
  extractBucketAndKey,
  getHeadersRecord,
  escapeXml,
  buildS3ListXml,
} from '../utils/storageUtils'
import {
  getUserBucket,
  extractBucketAndKey,
  getHeadersRecord,
  buildS3ListXml,
} from '../utils/storageUtils'

interface StorageUser {
  userId: string
}

const storage = new Hono<{
  Variables: {
    storageUser: StorageUser
    // When DID-Auth consumes the body for hash verification, the bytes are
    // kept here so PUT handlers can still forward them to MinIO.
    bufferedBody?: Uint8Array
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

/**
 * Resolve DID to userId for storage operations.
 */
async function resolveDidToUserId(did: string): Promise<string | null> {
  const [identity] = await db.select({ supabaseUserId: identities.supabaseUserId })
    .from(identities)
    .where(eq(identities.did, did))
    .limit(1)
  return identity?.supabaseUserId ?? null
}

function base64urlDecode(str: string): Uint8Array {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/')
  while (base64.length % 4 !== 0) base64 += '='
  const binary = atob(base64)
  return Uint8Array.from(binary, (ch) => ch.charCodeAt(0))
}

function base64urlEncode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

/**
 * Custom auth middleware that supports both:
 * - AWS Signature v4 (for S3 clients) - verifies signature cryptographically
 * - DID-Auth (for direct HTTP calls) - verifies Ed25519 signature
 *
 * Exported so integration tests can exercise the real code rather than
 * re-implementing the flow.
 */
export async function storageAuthMiddleware(c: any, next: () => Promise<void>) {
  const authHeader = c.req.header('authorization')

  if (!authHeader) {
    return c.json({ error: 'Authorization required' }, 401)
  }

  let userId: string | null = null

  // Try AWS Signature v4 first (for S3 clients like rust-s3, rclone, etc.)
  if (authHeader.startsWith('AWS4-HMAC-SHA256')) {
    const accessKeyId = extractAccessKeyId(authHeader)
    if (!accessKeyId) {
      return c.json({ error: 'Invalid AWS credentials' }, 401)
    }

    const credentials = await getCredentialsByAccessKeyId(accessKeyId)
    if (!credentials) {
      return c.json({ error: 'Invalid access key' }, 401)
    }

    const headers = getHeadersRecord(c.req.raw.headers)
    const url = new URL(c.req.url)
    const isValid = verifySignature(
      authHeader,
      headers,
      c.req.method,
      url.pathname,
      url.search.substring(1),
      credentials.secretAccessKey
    )

    if (!isValid) {
      return c.json({ error: 'Signature does not match' }, 403)
    }

    userId = credentials.userId
  }
  // DID-Auth (for direct HTTP calls from haex-vault)
  else if (authHeader.startsWith('DID ')) {
    const token = authHeader.substring(4)
    const dotIndex = token.indexOf('.')
    if (dotIndex === -1) return c.json({ error: 'Invalid DID auth format' }, 401)

    const payloadB64 = token.substring(0, dotIndex)
    const signatureB64 = token.substring(dotIndex + 1)

    let payload: { did: string; action: string; timestamp: number; bodyHash: string }
    try {
      payload = JSON.parse(new TextDecoder().decode(base64urlDecode(payloadB64)))
    } catch {
      return c.json({ error: 'Invalid DID auth payload' }, 401)
    }

    if (!payload.did || !payload.timestamp || !payload.bodyHash) {
      return c.json({ error: 'Missing DID auth fields' }, 401)
    }

    // Timestamp check (±30s)
    if (Math.abs(Date.now() - payload.timestamp) > 30_000) {
      return c.json({ error: 'DID auth timestamp expired' }, 401)
    }

    // Verify body hash to prevent request tampering / signature replay across bodies.
    // Reading the body here consumes c.req.raw.body, so we stash the bytes in
    // context for the PUT handler to forward to MinIO.
    const bodyBuffer = new Uint8Array(await c.req.raw.arrayBuffer())
    const bodyHashBuffer = await crypto.subtle.digest('SHA-256', bodyBuffer)
    const computedBodyHash = base64urlEncode(new Uint8Array(bodyHashBuffer))
    if (computedBodyHash !== payload.bodyHash) {
      return c.json({ error: 'Invalid body hash — request body was tampered' }, 401)
    }
    c.set('bufferedBody', bodyBuffer)

    // Verify Ed25519 signature
    try {
      const publicKeyBytes = didToPublicKey(payload.did)
      const publicKey = await crypto.subtle.importKey('raw', publicKeyBytes, { name: 'Ed25519' }, false, ['verify'])
      const valid = await crypto.subtle.verify('Ed25519', publicKey, base64urlDecode(signatureB64), new TextEncoder().encode(payloadB64))
      if (!valid) return c.json({ error: 'Invalid DID signature' }, 401)
    } catch {
      return c.json({ error: 'DID signature verification failed' }, 401)
    }

    userId = await resolveDidToUserId(payload.did)
    if (!userId) return c.json({ error: 'Identity not found' }, 401)
  }
  else {
    return c.json({ error: 'Unsupported authorization method. Use AWS4-HMAC-SHA256 or DID.' }, 401)
  }

  c.set('storageUser', { userId })

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

  const user = c.get('storageUser')
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
    // For DID-Auth, the auth middleware already buffered the body to verify
    // its hash — wrap those bytes back into a stream so the MinIO PUT can
    // forward them like an ordinary streamed upload.
    const buffered = c.get('bufferedBody')
    const uploadBody: ReadableStream<Uint8Array> | null = buffered
      ? new Response(buffered).body
      : c.req.raw.body
    const response = await uploadToMinio(
      extracted.bucket,
      extracted.key,
      uploadBody,
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

  const user = c.get('storageUser')
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

  const user = c.get('storageUser')
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

  const user = c.get('storageUser')
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
  const parsedMaxKeys = parseInt(c.req.query('max-keys') || '1000', 10)
  const maxKeys = Math.min(Number.isFinite(parsedMaxKeys) && parsedMaxKeys > 0 ? parsedMaxKeys : 1000, 1000)
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
 * GET /storage/s3 (without trailing path)
 * List files in user's bucket (S3 ListObjects)
 * Supports ?prefix= and ?delimiter= query params
 */
storage.get('/s3', async (c) => {
  if (!isMinioConfigured()) {
    return c.json({ error: 'Storage service not available' }, 503)
  }

  const user = c.get('storageUser')
  return handleListRequest(c, user.userId)
})

export default storage
