import { didToPublicKey } from '@haex-space/ucan'

/**
 * SPKI DER prefix for Ed25519 public keys.
 * Fixed structure: SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING { raw key } }
 */
const ED25519_SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
  0x70, 0x03, 0x21, 0x00,
])

/**
 * Wraps a raw 32-byte Ed25519 public key in SPKI DER encoding
 * and returns it as a base64 string.
 */
export function rawKeyToSpkiBase64(rawKey: Uint8Array): string {
  if (rawKey.length !== 32) {
    throw new Error(`Expected 32-byte Ed25519 public key, got ${rawKey.length} bytes`)
  }
  const spki = new Uint8Array(ED25519_SPKI_PREFIX.length + rawKey.length)
  spki.set(ED25519_SPKI_PREFIX)
  spki.set(rawKey, ED25519_SPKI_PREFIX.length)
  return Buffer.from(spki).toString('base64')
}

/**
 * Converts a did:key DID to an SPKI-encoded base64 public key string.
 * Uses didToPublicKey from @haex-space/ucan to extract the raw 32-byte
 * Ed25519 key, then wraps it in SPKI DER encoding.
 */
export function didToSpkiPublicKey(did: string): string {
  const rawKey = didToPublicKey(did)
  return rawKeyToSpkiBase64(rawKey)
}
