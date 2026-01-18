/**
 * AWS Signature v4 Verification
 *
 * Implements server-side verification of AWS Signature Version 4 requests.
 * Based on AWS documentation and s3rver implementation (MIT licensed).
 *
 * @see https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html
 */

import { createHash, createHmac, timingSafeEqual as cryptoTimingSafeEqual } from 'crypto'

export interface ParsedAwsSignature {
  accessKeyId: string
  credentialScope: {
    date: string
    region: string
    service: string
  }
  signedHeaders: string[]
  signatureProvided: string
  timestamp: string
}

/**
 * Parse AWS Signature v4 Authorization header
 *
 * Format: AWS4-HMAC-SHA256 Credential=AKID/date/region/s3/aws4_request,
 *         SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=xyz
 */
export function parseAuthorizationHeader(
  authHeader: string,
  headers: Record<string, string>
): ParsedAwsSignature | null {
  if (!authHeader.startsWith('AWS4-HMAC-SHA256')) {
    return null
  }

  try {
    // Parse components from header
    const parts = authHeader.substring('AWS4-HMAC-SHA256 '.length).split(',')
    const components = new Map<string, string>()

    for (const part of parts) {
      const trimmed = part.trim()
      const eqIndex = trimmed.indexOf('=')
      if (eqIndex > 0) {
        components.set(trimmed.substring(0, eqIndex), trimmed.substring(eqIndex + 1))
      }
    }

    const credential = components.get('Credential')
    const signedHeaders = components.get('SignedHeaders')
    const signature = components.get('Signature')

    if (!credential || !signedHeaders || !signature) {
      return null
    }

    const credentialParts = credential.split('/')
    const accessKeyId = credentialParts[0] || ''
    const date = credentialParts[1] || ''
    const region = credentialParts[2] || ''
    const service = credentialParts[3] || ''
    const timestamp = headers['x-amz-date'] || headers['date'] || ''

    if (!accessKeyId || !date || !region || !service) {
      return null
    }

    // Security: Validate access key ID format (alphanumeric only, no special chars)
    // This prevents null-byte injection and other manipulation attacks
    if (!/^[A-Za-z0-9]+$/.test(accessKeyId)) {
      return null
    }

    // Security: Validate date format (YYYYMMDD)
    if (!/^\d{8}$/.test(date)) {
      return null
    }

    // Security: Validate region and service (alphanumeric and hyphens only)
    if (!/^[a-z0-9-]+$/.test(region) || !/^[a-z0-9]+$/.test(service)) {
      return null
    }

    // Security: Validate signature format (hex string)
    if (!/^[a-f0-9]{64}$/.test(signature)) {
      return null
    }

    return {
      accessKeyId,
      credentialScope: { date, region, service },
      signedHeaders: signedHeaders.split(';'),
      signatureProvided: signature,
      timestamp,
    }
  } catch {
    return null
  }
}

/**
 * Extract just the access key ID from an AWS Signature v4 Authorization header.
 */
export function extractAccessKeyId(authHeader: string): string | null {
  if (!authHeader.startsWith('AWS4-HMAC-SHA256')) {
    return null
  }

  const match = authHeader.match(/Credential=([^/]+)\//)
  return match?.[1] ?? null
}

/**
 * Derive the signing key for AWS Signature v4
 */
function getSigningKey(
  secretKey: string,
  date: string,
  region: string,
  service: string
): Buffer {
  const dateKey = createHmac('sha256', 'AWS4' + secretKey).update(date).digest()
  const regionKey = createHmac('sha256', dateKey).update(region).digest()
  const serviceKey = createHmac('sha256', regionKey).update(service).digest()
  return createHmac('sha256', serviceKey).update('aws4_request').digest()
}

/**
 * Verify an AWS Signature v4 signed request
 */
export function verifySignature(
  authHeader: string,
  headers: Record<string, string>,
  method: string,
  path: string,
  queryString: string,
  secretKey: string
): boolean {
  const parsed = parseAuthorizationHeader(authHeader, headers)
  if (!parsed) {
    return false
  }

  try {
    // Check time skew (15 minutes max)
    const requestTime = parseISO8601(parsed.timestamp)
    if (!requestTime || Math.abs(Date.now() - requestTime.getTime()) > 900000) {
      return false
    }

    // Build canonical headers
    const canonicalHeaders = parsed.signedHeaders
      .map((h) => `${h}:${(headers[h] || '').trim()}\n`)
      .join('')

    // Get content hash
    const contentHash = headers['x-amz-content-sha256'] || 'UNSIGNED-PAYLOAD'

    // Build canonical query string (sorted, excluding X-Amz-Signature)
    const canonicalQueryString = queryString
      ? queryString
          .split('&')
          .filter((p) => !p.startsWith('X-Amz-Signature='))
          .sort()
          .join('&')
      : ''

    // Build canonical request
    const canonicalRequest = [
      method,
      path,
      canonicalQueryString,
      canonicalHeaders,
      parsed.signedHeaders.join(';'),
      contentHash,
    ].join('\n')

    // Build string to sign
    const { date, region, service } = parsed.credentialScope
    const stringToSign = [
      'AWS4-HMAC-SHA256',
      parsed.timestamp,
      `${date}/${region}/${service}/aws4_request`,
      createHash('sha256').update(canonicalRequest).digest('hex'),
    ].join('\n')

    // Calculate signature
    const signingKey = getSigningKey(secretKey, date, region, service)
    const calculatedSignature = createHmac('sha256', signingKey)
      .update(stringToSign)
      .digest('hex')

    // Timing-safe comparison
    const sigA = Buffer.from(parsed.signatureProvided, 'utf8')
    const sigB = Buffer.from(calculatedSignature, 'utf8')

    return sigA.length === sigB.length && cryptoTimingSafeEqual(sigA, sigB)
  } catch {
    return false
  }
}

/**
 * Parse ISO8601 timestamp (format: YYYYMMDD'T'HHMMSS'Z')
 */
function parseISO8601(timestamp: string): Date | null {
  if (!timestamp) return null

  const match = timestamp.match(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/)
  if (match) {
    const year = match[1]
    const month = match[2]
    const day = match[3]
    const hour = match[4]
    const min = match[5]
    const sec = match[6]

    if (!year || !month || !day || !hour || !min || !sec) {
      return null
    }

    return new Date(
      Date.UTC(
        parseInt(year, 10),
        parseInt(month, 10) - 1,
        parseInt(day, 10),
        parseInt(hour, 10),
        parseInt(min, 10),
        parseInt(sec, 10)
      )
    )
  }

  return null
}
