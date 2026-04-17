/**
 * Tests for the federation-relay gating on MLS invite decline/withdraw
 * (fix 5.2). Before the fix, these two handlers bypassed federationRelay(),
 * so a federated space would accept the state change locally without ever
 * forwarding it to the origin server — leaving invite state drift across
 * the federation.
 *
 * Exercises the REAL mlsRouter with a REAL DID-Auth header. Only narrow
 * service-level concerns are mocked:
 *   - `getFederationLinkForSpace` → controls the federated/local branch
 *   - `federatedProxyAsync`       → spy so we can assert relay fires
 *   - `../src/db`                 → complete shape (see helpers/db-mock)
 */

import { describe, test, expect, mock, beforeAll } from 'bun:test'
import { buildDbMock } from './helpers/db-mock'
import { makeIdentity, createDidAuthHeader } from './integration/helpers'

const VALID_SPACE_ID = '11111111-1111-4111-8111-111111111111'
const VALID_INVITE_ID = '22222222-2222-4222-8222-222222222222'

type ProxyCall = {
  link: any
  method: string
  path: string
  userAuth: string
  body: string | undefined
  query: string | undefined
}

const relayLink = {
  originServerUrl: 'https://origin.example.com',
  ucanToken: 'fake-ucan-from-test',
}
let proxyCalls: ProxyCall[] = []
let federationEnabled = true

mock.module('../src/services/federationClient', () => ({
  getFederationLinkForSpace: () => federationEnabled ? relayLink : null,
  federatedProxyAsync: async (link: any, method: string, path: string, userAuth: string, body?: string, query?: string) => {
    proxyCalls.push({ link, method, path, userAuth, body, query })
    return {
      status: 200,
      data: { relayed: true, path, method },
    }
  },
}))

mock.module('../src/utils/didIdentity', () => ({ didToSpkiPublicKey: () => '' }))

// Shared caller DID for requireCapability's ownerId check.
let callerDidForDb = 'did:key:placeholder'
mock.module('../src/db', () => buildDbMock({
  select: () => {
    const chain: any = {}
    chain.from = () => chain
    chain.where = () => chain
    chain.orderBy = () => chain
    chain.limit = () => Promise.resolve([{ ownerId: callerDidForDb }])
    return chain
  },
  insert: () => {
    const chain: any = {}
    chain.values = () => chain
    chain.returning = () => Promise.resolve([])
    chain.onConflictDoNothing = () => chain
    chain.onConflictDoUpdate = () => chain
    return chain
  },
  update: () => {
    const chain: any = {}
    chain.set = () => chain
    chain.where = () => chain
    chain.returning = () => Promise.resolve([])
    return chain
  },
  delete: () => {
    const chain: any = {}
    chain.where = () => chain
    chain.returning = () => Promise.resolve([])
    return chain
  },
}))

let mlsRouter: { request: (path: string, init?: any) => Response | Promise<Response> }
let caller: { did: string; keyPair: CryptoKeyPair }

beforeAll(async () => {
  const id = await makeIdentity()
  caller = { did: id.did, keyPair: id.keyPair }
  callerDidForDb = id.did
  mlsRouter = (await import('../src/routes/mls')).default
})

async function didHeader(action: string, body: string) {
  return createDidAuthHeader(caller.keyPair.privateKey, caller.did, action, body)
}

// ── Tests ───────────────────────────────────────────────────────────────

describe('mlsRouter — federation relay on decline (fix 5.2)', () => {
  test('POST /invites/:inviteId/decline on federated space is relayed to origin', async () => {
    proxyCalls = []
    federationEnabled = true
    const header = await didHeader('mls-decline', '')

    const res = await mlsRouter.request(`/${VALID_SPACE_ID}/invites/${VALID_INVITE_ID}/decline`, {
      method: 'POST',
      headers: { Authorization: header },
    })
    expect(res.status).toBe(200)

    expect(proxyCalls.length).toBe(1)
    const call = proxyCalls[0]!
    expect(call.method).toBe('POST')
    expect(call.path).toBe(`/${VALID_SPACE_ID}/invites/${VALID_INVITE_ID}/decline`)
    // The originating user's Authorization header is forwarded so the origin
    // can perform its own auth — verify it's the real DID header, not stripped.
    expect(call.userAuth).toBe(header)
  })

  test('POST decline on non-federated space is NOT relayed', async () => {
    proxyCalls = []
    federationEnabled = false
    const header = await didHeader('mls-decline', '')

    await mlsRouter.request(`/${VALID_SPACE_ID}/invites/${VALID_INVITE_ID}/decline`, {
      method: 'POST',
      headers: { Authorization: header },
    })
    expect(proxyCalls.length).toBe(0)
  })

  test('attack: decline on federated space without Authorization fails before relay', async () => {
    proxyCalls = []
    federationEnabled = true

    const res = await mlsRouter.request(`/${VALID_SPACE_ID}/invites/${VALID_INVITE_ID}/decline`, {
      method: 'POST',
    })
    // authDispatcher rejects missing header with 401 before reaching the relay.
    expect(res.status).toBe(401)
    expect(proxyCalls.length).toBe(0)
  })
})

describe('mlsRouter — federation relay on withdraw/DELETE invite (fix 5.2)', () => {
  test('DELETE /invites/:inviteId on federated space is relayed', async () => {
    proxyCalls = []
    federationEnabled = true
    const header = await didHeader('mls-withdraw', '')

    const res = await mlsRouter.request(`/${VALID_SPACE_ID}/invites/${VALID_INVITE_ID}`, {
      method: 'DELETE',
      headers: { Authorization: header },
    })
    expect(res.status).toBe(200)

    expect(proxyCalls.length).toBe(1)
    const call = proxyCalls[0]!
    expect(call.method).toBe('DELETE')
    expect(call.path).toBe(`/${VALID_SPACE_ID}/invites/${VALID_INVITE_ID}`)
  })

  test('DELETE on non-federated space is NOT relayed', async () => {
    proxyCalls = []
    federationEnabled = false
    const header = await didHeader('mls-withdraw', '')

    await mlsRouter.request(`/${VALID_SPACE_ID}/invites/${VALID_INVITE_ID}`, {
      method: 'DELETE',
      headers: { Authorization: header },
    })
    expect(proxyCalls.length).toBe(0)
  })
})

describe('mlsRouter — regression: pre-existing relays still fire', () => {
  // These endpoints already had federationRelay() before the fix; a
  // passing test here guards against accidental regressions.
  const endpoints = [
    {
      name: 'POST /invites (create)',
      method: 'POST',
      pathSuffix: '/invites',
      body: JSON.stringify({ inviteeDid: 'did:key:x', ucan: 'ucan' }),
    },
    {
      name: 'POST /mls/messages',
      method: 'POST',
      pathSuffix: '/mls/messages',
      body: JSON.stringify({ payload: 'x', messageType: 'application' }),
    },
    {
      name: 'GET /mls/welcome',
      method: 'GET',
      pathSuffix: '/mls/welcome',
      body: '',
    },
    {
      name: 'POST /mls/rejoin',
      method: 'POST',
      pathSuffix: '/mls/rejoin',
      body: '',
    },
  ] as const

  for (const ep of endpoints) {
    test(`${ep.name} relays when federated`, async () => {
      proxyCalls = []
      federationEnabled = true
      const header = await didHeader('mls-regress', ep.body)

      const init: any = {
        method: ep.method,
        headers: { Authorization: header, 'Content-Type': 'application/json' },
      }
      if (ep.method !== 'GET') init.body = ep.body

      const res = await mlsRouter.request(`/${VALID_SPACE_ID}${ep.pathSuffix}`, init)
      expect(res.status).toBe(200)
      expect(proxyCalls.length).toBe(1)
      expect(proxyCalls[0]!.method).toBe(ep.method)
    })
  }
})
