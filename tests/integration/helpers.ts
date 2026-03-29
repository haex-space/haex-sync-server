import {
  createUcan,
  createWebCryptoSigner,
  spaceResource,
  type Capabilities,
  type Capability,
  type SignFn,
} from '@haex-space/ucan'

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
  action: string,
  body?: string,
): Promise<string> {
  const bodyBytes = new TextEncoder().encode(body ?? '')
  const bodyHashBuffer = await crypto.subtle.digest('SHA-256', bodyBytes)
  const bodyHash = base64urlEncode(new Uint8Array(bodyHashBuffer))

  const payload = JSON.stringify({
    did,
    action,
    timestamp: Date.now(),
    bodyHash,
  })

  const payloadEncoded = base64urlEncode(payload)
  const payloadBytes = new TextEncoder().encode(payloadEncoded)
  const signature = new Uint8Array(
    await crypto.subtle.sign('Ed25519', privateKey, payloadBytes),
  )
  const signatureEncoded = base64urlEncode(signature)

  return `DID ${payloadEncoded}.${signatureEncoded}`
}

// --- UCAN Header ---

export async function createUcanHeader(
  identity: Identity,
  spaceId: string,
  capability: Capability,
  options?: {
    audience?: string
    expiration?: number
    proofs?: string[]
    extraCapabilities?: Capabilities
  },
): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  const capabilities: Capabilities = {
    [spaceResource(spaceId)]: capability,
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
