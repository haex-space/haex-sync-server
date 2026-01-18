/**
 * MinIO Admin Service
 *
 * Manages MinIO users, buckets, and policies for multi-tenant storage.
 * Uses MinIO Admin API to create per-user credentials and buckets.
 */

const MINIO_ENDPOINT = process.env.MINIO_ENDPOINT
const MINIO_ROOT_USER = process.env.MINIO_ROOT_USER
const MINIO_ROOT_PASSWORD = process.env.MINIO_ROOT_PASSWORD

if (!MINIO_ENDPOINT || !MINIO_ROOT_USER || !MINIO_ROOT_PASSWORD) {
  console.warn('Warning: MinIO admin credentials not configured. MinIO storage will not work.')
}

/**
 * Get user's bucket name
 */
export function getUserBucket(userId: string): string {
  return `user-${userId}`
}

/**
 * MinIO Admin API client using fetch
 * MinIO uses AWS Signature v4 for admin API, but we can use the mc (MinIO Client) REST endpoint
 */
async function minioAdminRequest(
  method: string,
  path: string,
  body?: object
): Promise<Response> {
  if (!MINIO_ENDPOINT || !MINIO_ROOT_USER || !MINIO_ROOT_PASSWORD) {
    throw new Error('MinIO admin credentials not configured')
  }

  const url = `${MINIO_ENDPOINT}${path}`
  const authHeader = 'Basic ' + Buffer.from(`${MINIO_ROOT_USER}:${MINIO_ROOT_PASSWORD}`).toString('base64')

  const response = await fetch(url, {
    method,
    headers: {
      'Authorization': authHeader,
      'Content-Type': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
  })

  return response
}

/**
 * Create a bucket for a user if it doesn't exist
 */
export async function ensureUserBucket(userId: string): Promise<void> {
  if (!MINIO_ENDPOINT) {
    throw new Error('MinIO not configured')
  }

  const bucket = getUserBucket(userId)
  const url = `${MINIO_ENDPOINT}/${bucket}`

  // Check if bucket exists (HEAD request)
  const checkResponse = await fetch(url, {
    method: 'HEAD',
    headers: {
      'Authorization': 'Basic ' + Buffer.from(`${MINIO_ROOT_USER}:${MINIO_ROOT_PASSWORD}`).toString('base64'),
    },
  })

  if (checkResponse.ok) {
    // Bucket already exists
    return
  }

  // Create bucket (PUT request)
  const createResponse = await fetch(url, {
    method: 'PUT',
    headers: {
      'Authorization': 'Basic ' + Buffer.from(`${MINIO_ROOT_USER}:${MINIO_ROOT_PASSWORD}`).toString('base64'),
    },
  })

  if (!createResponse.ok && createResponse.status !== 409) {
    // 409 = BucketAlreadyOwnedByYou (race condition, that's fine)
    const text = await createResponse.text()
    throw new Error(`Failed to create bucket: ${createResponse.status} - ${text}`)
  }
}

/**
 * Set quota on a user's bucket
 * Default: 10GB (10 * 1024 * 1024 * 1024 bytes)
 */
export async function setUserBucketQuota(
  userId: string,
  quotaBytes: number = 10 * 1024 * 1024 * 1024 // 10GB default
): Promise<void> {
  if (!MINIO_ENDPOINT || !MINIO_ROOT_USER || !MINIO_ROOT_PASSWORD) {
    throw new Error('MinIO admin credentials not configured')
  }

  const bucket = getUserBucket(userId)

  // MinIO quota is set via Admin API
  // PUT /minio/admin/v3/set-bucket-quota?bucket=<name>&quota=<bytes>
  const url = `${MINIO_ENDPOINT}/minio/admin/v3/set-bucket-quota?bucket=${bucket}&quota=${quotaBytes}`

  const response = await fetch(url, {
    method: 'PUT',
    headers: {
      'Authorization': 'Basic ' + Buffer.from(`${MINIO_ROOT_USER}:${MINIO_ROOT_PASSWORD}`).toString('base64'),
    },
  })

  if (!response.ok) {
    const text = await response.text()
    console.warn(`Failed to set bucket quota: ${response.status} - ${text}`)
    // Don't throw - quota is nice-to-have, not critical
  }
}

/**
 * Create a policy that allows access only to a specific user's bucket
 */
function createUserPolicy(userId: string): object {
  const bucket = getUserBucket(userId)
  return {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Action: [
          's3:GetObject',
          's3:PutObject',
          's3:DeleteObject',
          's3:ListBucket',
          's3:GetBucketLocation',
        ],
        Resource: [
          `arn:aws:s3:::${bucket}`,
          `arn:aws:s3:::${bucket}/*`,
        ],
      },
    ],
  }
}

/**
 * Provision storage for a new user:
 * 1. Create user bucket
 * 2. Set quota (10GB default)
 *
 * Note: The sync-server handles credentials separately in the database.
 * MinIO is accessed with service account credentials, and the sync-server
 * enforces bucket isolation based on authenticated user.
 */
export async function provisionUserStorage(userId: string): Promise<void> {
  // Create bucket
  await ensureUserBucket(userId)

  // Set quota (best effort)
  try {
    await setUserBucketQuota(userId)
  } catch (error) {
    console.warn(`Failed to set quota for user ${userId}:`, error)
  }
}
