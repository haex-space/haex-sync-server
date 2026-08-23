import {
  createUcan,
  createUcanPopHeader,
  createSignedAuthHeader,
  createWebCryptoSigner,
  decodeUcan,
  spaceResource,
  multibaseEncode,
  spaceCapabilitySetFromEntries,
  POP_HEADER_NAME,
  type Capabilities,
  type SpaceCap,
  type SignFn,
} from '@haex-space/ucan'
import {
  buildFederationAuthHeader as sdkBuildFederationAuthHeader,
  createFederatedAuthHeader,
} from '@haex-space/federation-sdk'

// --- Base Encoding ---

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

export function base58btcEncode(bytes: Uint8Array): string {
  let leadingZeros = 0
  for (const b of bytes) {
    if (b !== 0) break
    leadingZeros++
  }

  let num = 0n
  for (const b of bytes) {
    num = num * 256n + BigInt(b)
  }

  let result = ''
  while (num > 0n) {
    const remainder = Number(num % 58n)
    num = num / 58n
    result = BASE58_ALPHABET[remainder] + result
  }

  return '1'.repeat(leadingZeros) + result
}

export function base64urlEncode(data: string | Uint8Array): string {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

// --- Identity ---

export interface Identity {
  did: string
  sign: SignFn
  keyPair: CryptoKeyPair
  rawPublicKey: Uint8Array
}

type LegacySpaceCap = `space/${SpaceCap}`

function normalizeSpaceCap(capability: SpaceCap | LegacySpaceCap): SpaceCap {
  return capability.replace('space/', '') as SpaceCap
}

export async function makeIdentity(): Promise<Identity> {
  const keyPair = (await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify'],
  )) as unknown as CryptoKeyPair

  const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey))

  const multicodec = new Uint8Array(2 + rawPublicKey.length)
  multicodec[0] = 0xed
  multicodec[1] = 0x01
  multicodec.set(rawPublicKey, 2)

  const did = `did:key:z${base58btcEncode(multicodec)}`

  return {
    did,
    sign: createWebCryptoSigner(keyPair.privateKey),
    keyPair,
    rawPublicKey,
  }
}

// --- DID-Auth Header ---

export async function createDidAuthHeader(
  privateKey: CryptoKey,
  did: string,
  request: { method?: string; path: string; rawQuery?: string; body?: string },
): Promise<string> {
  const headerValue = await createSignedAuthHeader({
    privateKey,
    did,
    method: request.method ?? 'GET',
    path: request.path,
    rawQuery: request.rawQuery ?? '',
    body: request.body ?? '',
  })
  return `DID ${headerValue}`
}

// --- UCAN Header ---

export async function createUcanHeader(
  identity: Identity,
  spaceId: string,
  capability: SpaceCap | LegacySpaceCap,
  options?: {
    audience?: string
    expiration?: number
    proofs?: string[]
    extraCapabilities?: Capabilities
  },
): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  const capabilities: Capabilities = {
    [spaceResource(spaceId)]: spaceCapabilitySetFromEntries([
      { cap: normalizeSpaceCap(capability), delegatable: true },
    ]),
    ...options?.extraCapabilities,
  }

  const token = await createUcan(
    {
      issuer: identity.did,
      audience: options?.audience ?? identity.did,
      capabilities,
      expiration: options?.expiration ?? now + 3600,
      proofs: options?.proofs ?? [],
    },
    identity.sign,
  )

  return `UCAN ${token}`
}

/**
 * Build a request-headers object for a UCAN-authed call that carries BOTH
 * `Authorization: UCAN <token>` and the companion `X-UCAN-PoP` header signed
 * by the token's audience against the request line + body.
 *
 * The PoP audience is decoded from the UCAN, so the same helper works whether
 * the token is self-issued (aud == iss) or delegated (aud == holder).
 * Method defaults to `GET` and body defaults to empty; `rawQuery` is the
 * query string without the leading `?`.
 */
export async function ucanRequestHeaders(
  holder: Identity,
  ucanAuthorization: string,
  request: { method?: string; path: string; rawQuery?: string; body?: string },
): Promise<Record<string, string>> {
  const token = ucanAuthorization.startsWith('UCAN ')
    ? ucanAuthorization.slice(5)
    : ucanAuthorization
  const aud = decodeUcan(token).payload.aud
  const method = (request.method ?? 'GET').toUpperCase()
  const body = request.body ?? ''
  const pop = await createUcanPopHeader({
    privateKey: holder.keyPair.privateKey,
    ucanAud: aud,
    method,
    path: request.path,
    rawQuery: request.rawQuery ?? '',
    body,
  })
  const headers: Record<string, string> = {
    Authorization: ucanAuthorization.startsWith('UCAN ')
      ? ucanAuthorization
      : `UCAN ${ucanAuthorization}`,
    [POP_HEADER_NAME]: pop,
  }
  // Body-bearing methods must present Content-Length so the middleware's size
  // guard is a real ceiling (returns 411 otherwise). `app.request` in Bun/Hono
  // does not auto-set it when the body option is a plain string, so we compute
  // it here from the body we already signed.
  const bodyBearing = method !== 'GET' && method !== 'DELETE' && method !== 'HEAD'
  if (bodyBearing) {
    headers['Content-Length'] = String(new TextEncoder().encode(body).length)
  }
  return headers
}

// --- Server Identity (for federation tests) ---

export interface ServerIdentity {
  did: string
  domain: string
  keyPair: CryptoKeyPair
  rawPublicKey: Uint8Array
  privateKeyPkcs8Base64: string
}

export async function makeServerIdentity(domain: string): Promise<ServerIdentity> {
  const keyPair = (await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify'],
  )) as unknown as CryptoKeyPair

  const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey))
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey))
  const privateKeyPkcs8Base64 = btoa(String.fromCharCode(...pkcs8))

  return {
    did: `did:web:${domain}`,
    domain,
    keyPair,
    rawPublicKey,
    privateKeyPkcs8Base64,
  }
}

export function buildDidDocument(server: ServerIdentity) {
  // DID document requires multicodec-prefixed key: 0xed 0x01 + raw 32-byte key
  const multicodecKey = new Uint8Array(2 + server.rawPublicKey.length)
  multicodecKey[0] = 0xed
  multicodecKey[1] = 0x01
  multicodecKey.set(server.rawPublicKey, 2)

  return {
    id: server.did,
    verificationMethod: [{
      publicKeyMultibase: multibaseEncode(multicodecKey),
    }],
  }
}

// --- FEDERATION Auth Header (via SDK) ---

export async function buildFederationHeader(options: {
  server: ServerIdentity
  action: string
  body: string
  ucanToken: string
  userAuthorization?: string
  expiresInMs?: number
}): Promise<string> {
  return sdkBuildFederationAuthHeader({
    serverDid: options.server.did,
    privateKeyPkcs8Base64: options.server.privateKeyPkcs8Base64,
    action: options.action,
    body: options.body,
    ucanToken: options.ucanToken,
    userAuthorization: options.userAuthorization,
    expiresInMs: options.expiresInMs,
  })
}

// --- Federated User Auth Header (via SDK) ---

export async function makePrivateKeyBase64(keyPair: CryptoKeyPair): Promise<string> {
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey))
  return btoa(String.fromCharCode(...pkcs8))
}

export { createFederatedAuthHeader }
