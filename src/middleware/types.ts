import type { Capabilities, UcanContext as LibUcanContext } from '@haex-space/ucan'
import type { VerifiedFederatedAuth } from '@haex-space/federation-sdk'

/**
 * Sync-server-local UcanContext.
 *
 * Extends the library shape with `audienceDid` because a UCAN says
 * "`iss` grants capabilities to `aud`" — the bearer is `aud`. The library's
 * `issuerDid` was previously used as the caller identity, which misfiled
 * data for delegated leaves. Both fields are exposed distinctly so
 * downstream code cannot confuse "who granted" with "who is calling".
 */
export type UcanContext = LibUcanContext & {
  /** Audience DID from the verified UCAN — this is the caller. */
  audienceDid: string
}

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
  ucanCapabilities: Capabilities
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
