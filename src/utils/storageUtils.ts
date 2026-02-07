/**
 * Pure utility functions for storage operations.
 * No environment dependencies - safe to import in tests.
 */

/**
 * Get user's bucket name
 */
export function getUserBucket(userId: string): string {
  return `user-${userId}`
}

/**
 * Extract bucket name and key from path
 * Path format: /s3/{bucket}/{key} or /s3/{bucket}
 * Returns null if bucket doesn't match expected user bucket
 */
export function extractBucketAndKey(path: string, userId: string): { bucket: string; key: string } | null {
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
 * Get all headers as a lowercase-keyed record
 */
export function getHeadersRecord(headers: Headers): Record<string, string> {
  const result: Record<string, string> = {}
  headers.forEach((value, key) => {
    result[key.toLowerCase()] = value
  })
  return result
}

/**
 * Escape special XML characters
 */
export function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')
}

/**
 * Build S3 ListObjectsV2 XML response (fallback for empty buckets)
 */
export function buildS3ListXml(
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
