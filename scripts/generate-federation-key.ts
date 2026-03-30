/**
 * Generate an Ed25519 keypair for federation server identity.
 *
 * Usage: bun run scripts/generate-federation-key.ts
 *
 * Outputs the Base64-encoded private key seed (32 bytes) for FEDERATION_PRIVATE_KEY env var.
 */

const keyPair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']) as CryptoKeyPair

// Export private key as JWK to extract the 32-byte seed (d parameter)
const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey)
const seed = privateJwk.d!

// Export public key as raw bytes for display
const publicKeyBuffer = await crypto.subtle.exportKey('raw', keyPair.publicKey)
const publicKeyHex = Array.from(new Uint8Array(publicKeyBuffer))
  .map(b => b.toString(16).padStart(2, '0'))
  .join('')

// Convert JWK base64url seed to standard base64 for env var
const seedBase64url = seed
let seedBase64 = seedBase64url.replace(/-/g, '+').replace(/_/g, '/')
while (seedBase64.length % 4 !== 0) {
  seedBase64 += '='
}

console.log('Federation Server Identity Generated')
console.log('====================================')
console.log()
console.log('Add these to your .env file:')
console.log()
console.log(`FEDERATION_PRIVATE_KEY=${seedBase64}`)
console.log(`FEDERATION_SERVER_URL=https://your-sync-server.example.com`)
console.log()
console.log(`Public Key (hex): ${publicKeyHex}`)
console.log()
console.log('Keep FEDERATION_PRIVATE_KEY secret! Anyone with this key can impersonate your server.')
