import type { UcanContext } from '@haex-space/ucan'
import type { VerifiedFederatedAuth } from '@haex-space/federation-sdk'

export type { UcanContext }

export interface DidContext {
  did: string
  publicKey: string
  userId: string
  tier: string
  action: string
}

export interface FederationContext {
  serverDid: string
  serverPublicKey: Uint8Array
  issuerDid: string
  ucanToken: string
  ucanCapabilities: Record<string, string>
  action: string
  userAuth: VerifiedFederatedAuth | null
}

declare module 'hono' {
  interface ContextVariableMap {
    ucan: UcanContext | null
    didAuth: DidContext | null
    federation: FederationContext | null
  }
}
