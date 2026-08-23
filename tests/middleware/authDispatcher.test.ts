import { describe, test, expect } from 'bun:test'
import { Hono } from 'hono'
import {
  createUcan,
  createUcanPopHeader,
  createSignedAuthHeader,
  createWebCryptoSigner,
  spaceCapabilitySet,
  spaceResource,
  POP_HEADER_NAME,
} from '@haex-space/ucan'
import { authDispatcher } from '../../src/middleware/authDispatcher'
import { destroyPopJtiCache } from '../../src/middleware/popJtiCache'

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

function base58btcEncode(bytes: Uint8Array): string {
  let num = 0n
  for (const b of bytes) num = num * 256n + BigInt(b)
  let str = ''
  while (num > 0n) {
    str = BASE58_ALPHABET[Number(num % 58n)] + str
    num = num / 58n
  }
  for (const b of bytes) {
    if (b !== 0) break
    str = '1' + str
  }
  return str
}

function base64urlEncode(data: string | Uint8Array): string {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function makeIdentity() {
  const keyPair = (await crypto.subtle.generateKey(
    { name: 'Ed25519' }, true, ['sign', 'verify'],
  )) as unknown as CryptoKeyPair
  const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey))
  const mc = new Uint8Array([0xed, 0x01, ...rawPub])
  const did = `did:key:z${base58btcEncode(mc)}`
  return { keyPair, did, sign: createWebCryptoSigner(keyPair.privateKey) }
}

async function createDidAuthHeader(privateKey: CryptoKey, did: string, _action: string, body: string) {
  const headerValue = await createSignedAuthHeader({
    privateKey,
    did,
    method: 'POST',
    path: '/test',
    rawQuery: '',
    body,
  })
  return `DID ${headerValue}`
}

function createApp() {
  const app = new Hono()
  app.use('*', authDispatcher)
  app.get('/test', (c) => c.json({ ucan: !!c.get('ucan'), did: !!c.get('didAuth') }))
  app.post('/test', (c) => c.json({ ucan: !!c.get('ucan'), did: !!c.get('didAuth') }))
  return app
}

describe('Auth Dispatcher', () => {
  test('returns 401 for missing Authorization header', async () => {
    const res = await createApp().request('/test')
    expect(res.status).toBe(401)
  })

  test('returns 401 for Bearer scheme (Supabase JWT)', async () => {
    const res = await createApp().request('/test', {
      headers: { Authorization: 'Bearer some-jwt' },
    })
    expect(res.status).toBe(401)
    const json = await res.json() as any
    expect(json.error).toContain('Unsupported')
  })

  test('dispatches to UCAN handler', async () => {
    destroyPopJtiCache()
    const id = await makeIdentity()
    const token = await createUcan({
      issuer: id.did,
      audience: id.did,
      capabilities: { [spaceResource('test')]: spaceCapabilitySet().admin(true).build() },
      expiration: Math.floor(Date.now() / 1000) + 3600,
    }, id.sign)

    const pop = await createUcanPopHeader({
      privateKey: id.keyPair.privateKey,
      ucanAud: id.did,
      method: 'GET',
      path: '/test',
      rawQuery: '',
      body: '',
    })

    const res = await createApp().request('/test', {
      headers: {
        Authorization: `UCAN ${token}`,
        [POP_HEADER_NAME]: pop,
      },
    })
    expect(res.status).toBe(200)
    const json = await res.json() as any
    expect(json.ucan).toBe(true)
    expect(json.did).toBe(false)
  })

  test('dispatches to DID handler', async () => {
    const id = await makeIdentity()
    const body = '{}'
    const header = await createDidAuthHeader(id.keyPair.privateKey, id.did, 'create-space', body)

    const res = await createApp().request('/test', {
      method: 'POST',
      headers: { Authorization: header },
      body,
    })
    expect(res.status).toBe(200)
    const json = await res.json() as any
    expect(json.ucan).toBe(false)
    expect(json.did).toBe(true)
  })

  test('attack: empty Authorization header', async () => {
    const res = await createApp().request('/test', {
      headers: { Authorization: '' },
    })
    expect(res.status).toBe(401)
  })

  test('attack: scheme injection via whitespace', async () => {
    const res = await createApp().request('/test', {
      headers: { Authorization: '  UCAN fake' },
    })
    expect(res.status).toBe(401)
  })
})
