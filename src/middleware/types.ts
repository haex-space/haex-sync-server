import type { VerifiedUcan, Capabilities } from '@haex-space/ucan'

export interface UcanContext {
  issuerDid: string
  publicKey: string
  capabilities: Capabilities
  verifiedUcan: VerifiedUcan
}

export interface DidContext {
  did: string
  publicKey: string
  userId: string
  tier: string
  action: string
}

declare module 'hono' {
  interface ContextVariableMap {
    ucan: UcanContext | null
    didAuth: DidContext | null
  }
}
