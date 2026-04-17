import { describe, test, expect, mock, beforeEach, afterEach } from 'bun:test'

// Mock the db module — validateOriginServerUrl doesn't touch the db, but
// federation.helpers.ts imports db at module level.
mock.module('../src/db', () => ({
  db: {},
  syncChanges: {},
  spaces: {},
  identities: {},
}))

// Mock vault-sdk so we don't pull network/crypto deps we don't need.
mock.module('@haex-space/vault-sdk', () => ({
  verifyRecordSignatureAsync: async () => true,
}))

// Controllable DNS mock — tests set the next-resolved addresses before calling.
let mockDnsResult: Array<{ address: string; family: number }> | Error = []

mock.module('dns/promises', () => ({
  lookup: async (_hostname: string, _opts: any) => {
    if (mockDnsResult instanceof Error) throw mockDnsResult
    return mockDnsResult
  },
}))

// Import AFTER mocks are in place
import { validateOriginServerUrl } from '../src/routes/federation.helpers'

function setDns(addresses: string[]) {
  mockDnsResult = addresses.map(a => ({ address: a, family: a.includes(':') ? 6 : 4 }))
}

function setDnsError() {
  mockDnsResult = new Error('ENOTFOUND')
}

describe('SSRF guard — validateOriginServerUrl', () => {
  beforeEach(() => {
    setDns(['203.0.113.10']) // default: public IP (TEST-NET-3)
  })

  afterEach(() => {
    mockDnsResult = []
  })

  // ── URL parsing ─────────────────────────────────────────────────────

  test('rejects non-URL strings', async () => {
    const result = await validateOriginServerUrl('not a url')
    expect(result.valid).toBe(false)
    expect(result.error).toContain('Invalid URL')
  })

  test('rejects non-http(s) schemes', async () => {
    const result = await validateOriginServerUrl('file:///etc/passwd')
    expect(result.valid).toBe(false)
    expect(result.error).toContain('Unsupported protocol')
  })

  test('rejects ftp://', async () => {
    const result = await validateOriginServerUrl('ftp://example.com')
    expect(result.valid).toBe(false)
  })

  test('rejects gopher://', async () => {
    const result = await validateOriginServerUrl('gopher://example.com/')
    expect(result.valid).toBe(false)
  })

  // ── Literal private IPs ─────────────────────────────────────────────

  test('rejects localhost', async () => {
    const result = await validateOriginServerUrl('http://localhost:8080')
    expect(result.valid).toBe(false)
    expect(result.error).toContain('Loopback')
  })

  test('rejects *.localhost', async () => {
    const result = await validateOriginServerUrl('http://foo.localhost')
    expect(result.valid).toBe(false)
  })

  test('rejects 127.0.0.1', async () => {
    const result = await validateOriginServerUrl('http://127.0.0.1')
    expect(result.valid).toBe(false)
    expect(result.error).toContain('Private IP')
  })

  test('rejects 127.x.x.x range', async () => {
    const result = await validateOriginServerUrl('http://127.255.1.1')
    expect(result.valid).toBe(false)
  })

  test('rejects 0.0.0.0', async () => {
    const result = await validateOriginServerUrl('http://0.0.0.0')
    expect(result.valid).toBe(false)
  })

  test('rejects 10.0.0.0/8', async () => {
    const result = await validateOriginServerUrl('http://10.1.2.3')
    expect(result.valid).toBe(false)
  })

  test('rejects 192.168.0.0/16', async () => {
    const result = await validateOriginServerUrl('http://192.168.1.1')
    expect(result.valid).toBe(false)
  })

  test('rejects 172.16.0.0/12 boundary (172.16)', async () => {
    const result = await validateOriginServerUrl('http://172.16.0.1')
    expect(result.valid).toBe(false)
  })

  test('rejects 172.16.0.0/12 boundary (172.31)', async () => {
    const result = await validateOriginServerUrl('http://172.31.255.255')
    expect(result.valid).toBe(false)
  })

  test('accepts 172.15.x.x (outside private range)', async () => {
    setDns(['172.15.0.1'])
    const result = await validateOriginServerUrl('http://172.15.0.1')
    expect(result.valid).toBe(true)
  })

  test('accepts 172.32.x.x (outside private range)', async () => {
    setDns(['172.32.0.1'])
    const result = await validateOriginServerUrl('http://172.32.0.1')
    expect(result.valid).toBe(true)
  })

  test('rejects 169.254.x.x link-local', async () => {
    const result = await validateOriginServerUrl('http://169.254.169.254')
    expect(result.valid).toBe(false)
  })

  test('rejects multicast (224.0.0.0/4)', async () => {
    const result = await validateOriginServerUrl('http://224.0.0.1')
    expect(result.valid).toBe(false)
  })

  // ── IPv6 ────────────────────────────────────────────────────────────

  test('rejects IPv6 loopback ::1', async () => {
    const result = await validateOriginServerUrl('http://[::1]')
    expect(result.valid).toBe(false)
  })

  test('rejects IPv6 link-local fe80::/10', async () => {
    const result = await validateOriginServerUrl('http://[fe80::1]')
    expect(result.valid).toBe(false)
  })

  test('rejects IPv6 unique-local fc00::/7', async () => {
    const result = await validateOriginServerUrl('http://[fc00::1]')
    expect(result.valid).toBe(false)
  })

  // ── DNS rebinding protection ────────────────────────────────────────

  test('rejects hostname that resolves to private IP (DNS rebinding)', async () => {
    setDns(['10.0.0.1'])
    const result = await validateOriginServerUrl('https://evil.example.com')
    expect(result.valid).toBe(false)
    expect(result.error).toContain('private IP')
  })

  test('rejects hostname where ANY resolved IP is private (multi-A)', async () => {
    // Attacker returns both a public and a private IP — fetch may pick either.
    setDns(['203.0.113.1', '192.168.1.100'])
    const result = await validateOriginServerUrl('https://mixed.example.com')
    expect(result.valid).toBe(false)
  })

  test('rejects when DNS lookup fails', async () => {
    setDnsError()
    const result = await validateOriginServerUrl('https://nonexistent.example.com')
    expect(result.valid).toBe(false)
    expect(result.error).toContain('DNS')
  })

  // ── Valid URLs ──────────────────────────────────────────────────────

  test('accepts https://example.com (public IP)', async () => {
    setDns(['203.0.113.5'])
    const result = await validateOriginServerUrl('https://example.com')
    expect(result.valid).toBe(true)
    expect(result.error).toBeUndefined()
  })

  test('accepts https with explicit port', async () => {
    setDns(['203.0.113.5'])
    const result = await validateOriginServerUrl('https://example.com:8443')
    expect(result.valid).toBe(true)
  })

  test('accepts http (not only https) — transport-layer security is a separate concern', async () => {
    setDns(['203.0.113.5'])
    const result = await validateOriginServerUrl('http://example.com')
    expect(result.valid).toBe(true)
  })
})
