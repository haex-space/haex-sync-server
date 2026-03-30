/**
 * Server Identity Service
 *
 * Manages the server's Ed25519 keypair for federation.
 * The private key is loaded from the FEDERATION_PRIVATE_KEY env var (Base64-encoded raw 32-byte seed).
 * The public key and DID (did:web:<domain>) are derived from it.
 *
 * Generate a key with: bun run scripts/generate-federation-key.ts
 */

let serverIdentity: {
  privateKey: CryptoKey
  publicKey: CryptoKey
  publicKeyBytes: Uint8Array
  did: string
  serverUrl: string
} | null = null

function base64Decode(str: string): Uint8Array {
  const binary = atob(str)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

function base64Encode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Build a did:web DID from a server URL.
 * https://sync.example.com → did:web:sync.example.com
 * https://sync.example.com:8443 → did:web:sync.example.com%3A8443
 */
function serverUrlToDid(serverUrl: string): string {
  const url = new URL(serverUrl)
  let host = url.hostname
  if (url.port) {
    host += `%3A${url.port}`
  }
  return `did:web:${host}`
}

/**
 * Initialize server identity from environment variables.
 * Must be called once at startup before any federation operations.
 *
 * Required env vars:
 * - FEDERATION_PRIVATE_KEY: Base64-encoded 32-byte Ed25519 seed
 * - FEDERATION_SERVER_URL: Public URL of this server (e.g. https://sync.example.com)
 */
export async function initializeServerIdentityAsync(): Promise<void> {
  const privateKeyBase64 = process.env.FEDERATION_PRIVATE_KEY
  const serverUrl = process.env.FEDERATION_SERVER_URL

  if (!privateKeyBase64 || !serverUrl) {
    console.log('[Federation] FEDERATION_PRIVATE_KEY or FEDERATION_SERVER_URL not set — federation disabled')
    return
  }

  const seed = base64Decode(privateKeyBase64)
  if (seed.length !== 32) {
    throw new Error(`[Federation] FEDERATION_PRIVATE_KEY must be exactly 32 bytes, got ${seed.length}`)
  }

  // Import as PKCS8 (Ed25519 PKCS8 wraps the 32-byte seed in a standard envelope)
  const pkcs8 = new Uint8Array([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ...seed,
  ])

  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    pkcs8,
    { name: 'Ed25519' },
    false,
    ['sign'],
  )

  // Export public key from a sign+verify keypair re-derived from the seed
  const publicKeyJwk = await derivePublicKeyFromSeed(seed)
  const publicKeyBytes = base64urlDecodeJwk(publicKeyJwk.x!)

  const publicKey = await crypto.subtle.importKey(
    'raw',
    publicKeyBytes,
    { name: 'Ed25519' },
    true,
    ['verify'],
  )

  const did = serverUrlToDid(serverUrl)

  serverIdentity = {
    privateKey,
    publicKey,
    publicKeyBytes,
    did,
    serverUrl,
  }

  console.log(`[Federation] Server identity initialized: ${did}`)
  console.log(`[Federation] Public key: ${bytesToHex(publicKeyBytes)}`)
}

/**
 * Derive the Ed25519 public key from a 32-byte seed.
 * We import as a keypair and export the public portion.
 */
async function derivePublicKeyFromSeed(seed: Uint8Array): Promise<{ x?: string }> {
  const pkcs8 = new Uint8Array([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ...seed,
  ])

  const keyPair = await crypto.subtle.importKey(
    'pkcs8',
    pkcs8,
    { name: 'Ed25519' },
    true,
    ['sign'],
  )

  const jwk = await crypto.subtle.exportKey('jwk', keyPair)
  return jwk
}

function base64urlDecodeJwk(str: string): Uint8Array {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/')
  while (base64.length % 4 !== 0) {
    base64 += '='
  }
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

/**
 * Get the initialized server identity. Returns null if federation is not configured.
 */
export function getServerIdentity() {
  return serverIdentity
}

/**
 * Check if federation is enabled (server identity is configured).
 */
export function isFederationEnabled(): boolean {
  return serverIdentity !== null
}

/**
 * Build the DID Document for this server.
 * Served at GET /.well-known/did.json
 */
export function buildDidDocument() {
  if (!serverIdentity) {
    return null
  }

  const publicKeyMultibase = `z${base64Encode(new Uint8Array([0xed, 0x01, ...serverIdentity.publicKeyBytes]))}`

  return {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1',
    ],
    id: serverIdentity.did,
    verificationMethod: [
      {
        id: `${serverIdentity.did}#key-1`,
        type: 'Ed25519VerificationKey2020',
        controller: serverIdentity.did,
        publicKeyMultibase,
      },
    ],
    authentication: [`${serverIdentity.did}#key-1`],
    assertionMethod: [`${serverIdentity.did}#key-1`],
  }
}

/**
 * Sign arbitrary data with the server's private key.
 */
export async function signWithServerKeyAsync(data: Uint8Array): Promise<Uint8Array> {
  if (!serverIdentity) {
    throw new Error('[Federation] Server identity not initialized')
  }

  const signature = await crypto.subtle.sign('Ed25519', serverIdentity.privateKey, data)
  return new Uint8Array(signature)
}

/**
 * Get the server's public key as hex string.
 */
export function getServerPublicKeyHex(): string | null {
  if (!serverIdentity) return null
  return bytesToHex(serverIdentity.publicKeyBytes)
}
