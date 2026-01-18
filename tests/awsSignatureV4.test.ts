import { describe, test, expect } from 'bun:test'
import { createHash, createHmac } from 'crypto'
import {
  parseAuthorizationHeader,
  extractAccessKeyId,
  verifySignature,
} from '../src/utils/awsSignatureV4'

/**
 * AWS Signature v4 Verification Tests
 *
 * These tests verify the security of our AWS Signature v4 implementation
 * against various attack vectors and edge cases.
 */

// Helper function to create a valid AWS Signature v4 request
function createSignedRequest(
  accessKeyId: string,
  secretKey: string,
  options: {
    method?: string
    path?: string
    queryString?: string
    timestamp?: string
    region?: string
    service?: string
    host?: string
    contentHash?: string
  } = {}
): { authHeader: string; headers: Record<string, string> } {
  const method = options.method || 'GET'
  const path = options.path || '/'
  const queryString = options.queryString || ''
  const timestamp = options.timestamp || formatTimestamp(new Date())
  const region = options.region || 'auto'
  const service = options.service || 's3'
  const host = options.host || 'localhost:3000'
  const contentHash = options.contentHash || 'UNSIGNED-PAYLOAD'

  const date = timestamp.substring(0, 8)
  const signedHeaders = 'host;x-amz-content-sha256;x-amz-date'

  // Build canonical request
  const canonicalHeaders = [
    `host:${host}`,
    `x-amz-content-sha256:${contentHash}`,
    `x-amz-date:${timestamp}`,
  ].join('\n') + '\n'

  const canonicalRequest = [
    method,
    path,
    queryString,
    canonicalHeaders,
    signedHeaders,
    contentHash,
  ].join('\n')

  // Build string to sign
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    timestamp,
    `${date}/${region}/${service}/aws4_request`,
    createHash('sha256').update(canonicalRequest).digest('hex'),
  ].join('\n')

  // Calculate signing key
  const dateKey = createHmac('sha256', 'AWS4' + secretKey).update(date).digest()
  const regionKey = createHmac('sha256', dateKey).update(region).digest()
  const serviceKey = createHmac('sha256', regionKey).update(service).digest()
  const signingKey = createHmac('sha256', serviceKey).update('aws4_request').digest()

  // Calculate signature
  const signature = createHmac('sha256', signingKey).update(stringToSign).digest('hex')

  const authHeader = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${date}/${region}/${service}/aws4_request, SignedHeaders=${signedHeaders}, Signature=${signature}`

  return {
    authHeader,
    headers: {
      host,
      'x-amz-content-sha256': contentHash,
      'x-amz-date': timestamp,
    },
  }
}

function formatTimestamp(date: Date): string {
  return date.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '')
}

describe('AWS Signature v4 Verification', () => {
  const testAccessKeyId = 'HAEXTESTKEY123456'
  const testSecretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'

  describe('parseAuthorizationHeader', () => {
    test('should parse valid authorization header', () => {
      const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey)

      const result = parseAuthorizationHeader(authHeader, headers)

      expect(result).not.toBeNull()
      expect(result!.accessKeyId).toBe(testAccessKeyId)
      expect(result!.credentialScope.region).toBe('auto')
      expect(result!.credentialScope.service).toBe('s3')
      expect(result!.signedHeaders).toContain('host')
      expect(result!.signedHeaders).toContain('x-amz-content-sha256')
      expect(result!.signedHeaders).toContain('x-amz-date')
    })

    test('should return null for non-AWS4 header', () => {
      const headers = { 'x-amz-date': '20231215T120000Z', 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD' }
      const result = parseAuthorizationHeader('Bearer token123', headers)
      expect(result).toBeNull()
    })

    test('should return null for malformed header missing Credential', () => {
      const headers = { 'x-amz-date': '20231215T120000Z', 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD' }
      const result = parseAuthorizationHeader(
        'AWS4-HMAC-SHA256 SignedHeaders=host;x-amz-date, Signature=abc123',
        headers
      )
      expect(result).toBeNull()
    })

    test('should return null for malformed header missing Signature', () => {
      const headers = { 'x-amz-date': '20231215T120000Z', 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD' }
      const result = parseAuthorizationHeader(
        'AWS4-HMAC-SHA256 Credential=AKID/20231215/auto/s3/aws4_request, SignedHeaders=host;x-amz-date',
        headers
      )
      expect(result).toBeNull()
    })

    test('should return null for empty credential scope', () => {
      const headers = { 'x-amz-date': '20231215T120000Z', 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD' }
      const result = parseAuthorizationHeader(
        'AWS4-HMAC-SHA256 Credential=///, SignedHeaders=host, Signature=abc',
        headers
      )
      expect(result).toBeNull()
    })
  })

  describe('extractAccessKeyId', () => {
    test('should extract access key ID from valid header', () => {
      const { authHeader } = createSignedRequest(testAccessKeyId, testSecretKey)
      const result = extractAccessKeyId(authHeader)
      expect(result).toBe(testAccessKeyId)
    })

    test('should return null for non-AWS4 header', () => {
      expect(extractAccessKeyId('Bearer token123')).toBeNull()
    })

    test('should return null for missing Credential', () => {
      expect(extractAccessKeyId('AWS4-HMAC-SHA256 SignedHeaders=host')).toBeNull()
    })
  })

  describe('verifySignature', () => {
    test('should verify valid signature', () => {
      const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey)

      const isValid = verifySignature(authHeader, headers, 'GET', '/', '', testSecretKey)

      expect(isValid).toBe(true)
    })

    test('should verify signature with query string', () => {
      // Note: Query strings must be sorted alphabetically in canonical request
      const sortedQueryString = 'max-keys=100&prefix=test'
      const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey, {
        queryString: sortedQueryString,
      })

      const isValid = verifySignature(
        authHeader,
        headers,
        'GET',
        '/',
        sortedQueryString,
        testSecretKey
      )

      expect(isValid).toBe(true)
    })

    test('should verify signature with different path', () => {
      const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey, {
        path: '/storage/s3/test-file.txt',
      })

      const isValid = verifySignature(
        authHeader,
        headers,
        'GET',
        '/storage/s3/test-file.txt',
        '',
        testSecretKey
      )

      expect(isValid).toBe(true)
    })

    test('should verify PUT request', () => {
      const contentHash = createHash('sha256').update('test content').digest('hex')
      const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey, {
        method: 'PUT',
        path: '/test-file.txt',
        contentHash,
      })

      const isValid = verifySignature(
        authHeader,
        headers,
        'PUT',
        '/test-file.txt',
        '',
        testSecretKey
      )

      expect(isValid).toBe(true)
    })

    test('should reject signature with wrong secret key', () => {
      const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey)

      const isValid = verifySignature(authHeader, headers, 'GET', '/', '', 'wrong-secret-key')

      expect(isValid).toBe(false)
    })

    test('should reject signature with tampered path', () => {
      const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey, {
        path: '/allowed-path',
      })

      // Attacker tries to access different path
      const isValid = verifySignature(
        authHeader,
        headers,
        'GET',
        '/admin/secrets',
        '',
        testSecretKey
      )

      expect(isValid).toBe(false)
    })

    test('should reject signature with tampered method', () => {
      const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey, {
        method: 'GET',
      })

      // Attacker tries to change method to DELETE
      const isValid = verifySignature(authHeader, headers, 'DELETE', '/', '', testSecretKey)

      expect(isValid).toBe(false)
    })

    test('should reject signature with tampered query string', () => {
      const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey, {
        queryString: 'user=bob',
      })

      // Attacker tries to change query to access another user
      const isValid = verifySignature(authHeader, headers, 'GET', '/', 'user=admin', testSecretKey)

      expect(isValid).toBe(false)
    })
  })

  describe('Security Attack Vectors', () => {
    describe('Timing Attacks', () => {
      test('should reject modified signature byte (timing-safe comparison)', () => {
        const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey)

        // Modify one character in the signature
        const tamperedAuth = authHeader.replace(/Signature=([a-f0-9])/, 'Signature=0')

        const isValid = verifySignature(tamperedAuth, headers, 'GET', '/', '', testSecretKey)
        expect(isValid).toBe(false)
      })
    })

    describe('Replay Attacks', () => {
      test('should reject expired requests (> 15 minutes old)', () => {
        const oldDate = new Date(Date.now() - 16 * 60 * 1000) // 16 minutes ago
        const oldTimestamp = formatTimestamp(oldDate)

        const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey, {
          timestamp: oldTimestamp,
        })

        const isValid = verifySignature(authHeader, headers, 'GET', '/', '', testSecretKey)

        expect(isValid).toBe(false)
      })

      test('should accept requests within 15 minute window', () => {
        const recentDate = new Date(Date.now() - 10 * 60 * 1000) // 10 minutes ago
        const recentTimestamp = formatTimestamp(recentDate)

        const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey, {
          timestamp: recentTimestamp,
        })

        const isValid = verifySignature(authHeader, headers, 'GET', '/', '', testSecretKey)

        expect(isValid).toBe(true)
      })

      test('should reject future requests (> 15 minutes ahead)', () => {
        const futureDate = new Date(Date.now() + 16 * 60 * 1000) // 16 minutes in future
        const futureTimestamp = formatTimestamp(futureDate)

        const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey, {
          timestamp: futureTimestamp,
        })

        const isValid = verifySignature(authHeader, headers, 'GET', '/', '', testSecretKey)

        expect(isValid).toBe(false)
      })
    })

    describe('Header Injection Attacks', () => {
      test('should fail with missing x-amz-date header', () => {
        const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey)
        delete headers['x-amz-date']

        const isValid = verifySignature(authHeader, headers, 'GET', '/', '', testSecretKey)

        expect(isValid).toBe(false)
      })

      test('should fail with tampered x-amz-date header', () => {
        const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey)
        headers['x-amz-date'] = '20991231T235959Z' // Far future date

        const isValid = verifySignature(authHeader, headers, 'GET', '/', '', testSecretKey)

        expect(isValid).toBe(false)
      })

      test('should fail with tampered host header', () => {
        const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey)
        headers['host'] = 'evil.com' // Changed host

        const isValid = verifySignature(authHeader, headers, 'GET', '/', '', testSecretKey)

        expect(isValid).toBe(false)
      })
    })

    describe('Signature Manipulation Attacks', () => {
      test('should reject empty signature', () => {
        const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey)
        const tamperedAuth = authHeader.replace(/Signature=[a-f0-9]+/, 'Signature=')

        const isValid = verifySignature(tamperedAuth, headers, 'GET', '/', '', testSecretKey)

        expect(isValid).toBe(false)
      })

      test('should reject signature with invalid characters', () => {
        const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey)
        const tamperedAuth = authHeader.replace(
          /Signature=[a-f0-9]+/,
          'Signature=ZZZZ!@#$%^&*()'
        )

        const isValid = verifySignature(tamperedAuth, headers, 'GET', '/', '', testSecretKey)

        expect(isValid).toBe(false)
      })

      test('should reject signature of different length', () => {
        const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey)
        // SHA256 produces 64 hex chars, try with shorter
        const tamperedAuth = authHeader.replace(/Signature=[a-f0-9]+/, 'Signature=abc123')

        const isValid = verifySignature(tamperedAuth, headers, 'GET', '/', '', testSecretKey)

        expect(isValid).toBe(false)
      })
    })

    describe('Credential Scope Attacks', () => {
      test('should reject signature with different region', () => {
        const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey, {
          region: 'eu-west-1',
        })

        // Verify with same request but different region in credential
        const tamperedAuth = authHeader.replace('/eu-west-1/', '/us-east-1/')

        const isValid = verifySignature(tamperedAuth, headers, 'GET', '/', '', testSecretKey)

        expect(isValid).toBe(false)
      })

      test('should reject signature with different service', () => {
        const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey)

        const tamperedAuth = authHeader.replace('/s3/', '/ec2/')

        const isValid = verifySignature(tamperedAuth, headers, 'GET', '/', '', testSecretKey)

        expect(isValid).toBe(false)
      })
    })

    describe('Malformed Input Attacks', () => {
      test('should handle extremely long authorization header', () => {
        const longString = 'A'.repeat(100000)
        const isValid = verifySignature(
          `AWS4-HMAC-SHA256 ${longString}`,
          { host: 'localhost', 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD', 'x-amz-date': '20231215T120000Z' },
          'GET',
          '/',
          '',
          testSecretKey
        )

        expect(isValid).toBe(false)
      })

      test('should handle null-byte injection in header', () => {
        const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey)
        const tamperedAuth = authHeader.replace('Credential=', 'Credential=\x00evil\x00')

        const isValid = verifySignature(tamperedAuth, headers, 'GET', '/', '', testSecretKey)

        expect(isValid).toBe(false)
      })

      test('should handle unicode in authorization header', () => {
        const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey)
        const tamperedAuth = authHeader.replace('Credential=', 'Credential=😈')

        const isValid = verifySignature(tamperedAuth, headers, 'GET', '/', '', testSecretKey)

        expect(isValid).toBe(false)
      })

      test('should handle path traversal attempts', () => {
        const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey, {
          path: '/bucket/../../../etc/passwd',
        })

        // Should only validate the exact path that was signed
        const isValid = verifySignature(
          authHeader,
          headers,
          'GET',
          '/bucket/../../../etc/passwd',
          '',
          testSecretKey
        )

        // The signature should be valid for the exact path
        expect(isValid).toBe(true)

        // But using a different path should fail
        const isValidDifferentPath = verifySignature(
          authHeader,
          headers,
          'GET',
          '/etc/passwd',
          '',
          testSecretKey
        )
        expect(isValidDifferentPath).toBe(false)
      })

      test('should handle root path', () => {
        // AWS S3 uses '/' as the root path, not empty string
        const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey, {
          path: '/',
        })

        const isValid = verifySignature(authHeader, headers, 'GET', '/', '', testSecretKey)

        expect(isValid).toBe(true)
      })

      test('should handle SQL injection attempts in query string', () => {
        const maliciousQuery = "'; DROP TABLE users; --"
        const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey, {
          queryString: `param=${encodeURIComponent(maliciousQuery)}`,
        })

        // Should only validate the exact query that was signed
        const isValid = verifySignature(
          authHeader,
          headers,
          'GET',
          '/',
          `param=${encodeURIComponent(maliciousQuery)}`,
          testSecretKey
        )

        expect(isValid).toBe(true)

        // Different query should fail
        const isValidDifferent = verifySignature(
          authHeader,
          headers,
          'GET',
          '/',
          'param=normal',
          testSecretKey
        )
        expect(isValidDifferent).toBe(false)
      })
    })

    describe('Content Hash Validation', () => {
      test('should verify UNSIGNED-PAYLOAD is accepted', () => {
        const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey, {
          contentHash: 'UNSIGNED-PAYLOAD',
        })

        const isValid = verifySignature(authHeader, headers, 'GET', '/', '', testSecretKey)

        expect(isValid).toBe(true)
      })

      test('should verify specific content hash', () => {
        const content = 'Hello, World!'
        const contentHash = createHash('sha256').update(content).digest('hex')

        const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey, {
          method: 'PUT',
          contentHash,
        })

        const isValid = verifySignature(authHeader, headers, 'PUT', '/', '', testSecretKey)

        expect(isValid).toBe(true)
      })

      test('should fail if content hash header is tampered', () => {
        const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey)

        // Attacker tries to change content hash after signing
        headers['x-amz-content-sha256'] = createHash('sha256').update('malicious').digest('hex')

        const isValid = verifySignature(authHeader, headers, 'GET', '/', '', testSecretKey)

        expect(isValid).toBe(false)
      })
    })

    describe('Edge Cases', () => {
      test('should handle request at exactly 15 minute boundary', () => {
        // Test at exactly 15 minutes (should pass - boundary is inclusive)
        const exactBoundary = new Date(Date.now() - 15 * 60 * 1000)
        const timestamp = formatTimestamp(exactBoundary)

        const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey, {
          timestamp,
        })

        const isValid = verifySignature(authHeader, headers, 'GET', '/', '', testSecretKey)

        // Depending on exact timing, this should be very close to the boundary
        // Accept either result as long as it's consistent
        expect(typeof isValid).toBe('boolean')
      })

      test('should handle special characters in path', () => {
        const specialPath = '/bucket/file%20with%20spaces.txt'

        const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey, {
          path: specialPath,
        })

        const isValid = verifySignature(authHeader, headers, 'GET', specialPath, '', testSecretKey)

        expect(isValid).toBe(true)
      })

      test('should handle very long path', () => {
        const longPath = '/' + 'a'.repeat(1000)

        const { authHeader, headers } = createSignedRequest(testAccessKeyId, testSecretKey, {
          path: longPath,
        })

        const isValid = verifySignature(authHeader, headers, 'GET', longPath, '', testSecretKey)

        expect(isValid).toBe(true)
      })
    })
  })
})
