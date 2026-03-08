/**
 * ECDSA P-256 signature verification using WebCrypto API.
 * This utility will be replaced by @haex-space/vault-sdk's verifyRecordSignatureAsync in Task 8.
 */

interface RecordData {
  tableName: string
  rowPks: string
  columnName: string | null
  encryptedValue: string | null
  hlcTimestamp: string
}

/**
 * Build the canonical string for signature verification.
 * Format: fields joined by \0 (null byte), null values encoded as '\x01NULL'
 * Must match the SDK's canonicalize() in @haex-space/vault-sdk/src/crypto/recordSigning.ts
 */
function buildCanonicalString(record: RecordData): string {
  return [
    record.tableName,
    record.rowPks,
    record.columnName === null ? '\x01NULL' : record.columnName,
    record.encryptedValue === null ? '\x01NULL' : record.encryptedValue,
    record.hlcTimestamp,
  ].join('\0')
}

/**
 * Import a Base64-encoded SPKI public key for ECDSA P-256 verification.
 */
async function importPublicKey(base64Spki: string): Promise<CryptoKey> {
  const binaryDer = Uint8Array.from(atob(base64Spki), (c) => c.charCodeAt(0))
  return crypto.subtle.importKey(
    'spki',
    binaryDer,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  )
}

/**
 * Verify an ECDSA P-256 signature over a sync record.
 *
 * @param record - The record data to verify
 * @param signatureBase64 - Base64-encoded ECDSA signature
 * @param publicKeyBase64 - Base64-encoded SPKI public key
 * @returns true if signature is valid
 */
export async function verifyRecordSignature(
  record: RecordData,
  signatureBase64: string,
  publicKeyBase64: string,
): Promise<boolean> {
  try {
    const publicKey = await importPublicKey(publicKeyBase64)
    const canonical = buildCanonicalString(record)
    const data = new TextEncoder().encode(canonical)
    const signature = Uint8Array.from(atob(signatureBase64), (c) => c.charCodeAt(0))

    return crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      signature,
      data,
    )
  } catch {
    return false
  }
}
