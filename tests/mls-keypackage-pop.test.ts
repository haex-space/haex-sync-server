import { describe, test, expect, mock, beforeAll } from 'bun:test'
import { buildDbMock, emptyChain } from './helpers/db-mock'
import { makeIdentity, createDidAuthHeader } from './integration/helpers'

const VALID_UUID = '11111111-1111-4111-8111-111111111111'

mock.module('../src/services/federationClient', () => ({
  getFederationLinkForSpace: () => null,
  federatedProxyAsync: async () => ({ status: 500, data: { error: 'should not be called' } }),
}))
mock.module('../src/utils/didIdentity', () => ({ didToSpkiPublicKey: () => '' }))

let mlsRouter: { request: (path: string, init?: any) => Response | Promise<Response> }
let caller: { did: string; keyPair: CryptoKeyPair }

describe('mlsRouter — pops array must match keyPackages length', () => {
  beforeAll(async () => {
    const id = await makeIdentity()
    caller = { did: id.did, keyPair: id.keyPair }

    // requireCapability's DID-Auth branch looks up the space owner; an empty
    // result means "caller is not the owner" (see src/middleware/ucanAuth.ts),
    // so a request with a *valid* body shape still gets rejected — just with
    // 403, not 400. That's exactly what we want: these tests only assert on
    // the Zod validation layer, not on the authorization outcome.
    mock.module('../src/db', () => buildDbMock({
      select: () => emptyChain(),
    }))
    mlsRouter = (await import('../src/routes/mls')).default
  })

  // authDispatcher (src/routes/mls.ts) runs globally before zValidator and
  // rejects any request without an Authorization header (401) before the
  // request ever reaches Zod. So these requests need a real signed DID-Auth
  // header — matching the bodyHash — to actually exercise the schema.
  async function signedRequest(bodyObj: unknown) {
    const body = JSON.stringify(bodyObj)
    const header = await createDidAuthHeader(caller.keyPair.privateKey, caller.did, 'mls-write', body)
    return mlsRouter.request(`/${VALID_UUID}/mls/key-packages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: header },
      body,
    })
  }

  test('POST /:spaceId/mls/key-packages rejects mismatched pops length', async () => {
    const res = await signedRequest({ keyPackages: ['a', 'b'], pops: ['x'] })
    expect(res.status).toBe(400)
  })

  test('POST /:spaceId/mls/key-packages accepts equal-length arrays (shape only — capability check rejects next with 403)', async () => {
    const res = await signedRequest({ keyPackages: ['a', 'b'], pops: ['x', 'y'] })
    // Zod validation passes (no 400); requireCapability rejects next — the
    // mocked space lookup returns no owner match, which is a deterministic
    // 403 (see src/middleware/ucanAuth.ts requireCapability).
    expect(res.status).toBe(403)
  })
})
