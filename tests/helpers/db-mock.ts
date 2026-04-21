/**
 * Shared db mock shape. Bun's mock.module is process-global, so when multiple
 * test files each mock '../src/db' with different subsets of exports, whichever
 * file loads first can "win" and break transitive imports in later files.
 *
 * To avoid that, every test file that mocks db should export the SAME set of
 * table names from this shape. Tests can still supply custom implementations
 * for `db.select/insert/…` by overriding the returned object.
 *
 * The same hazard applies to any `mock.module('../src/services/…', …)` call:
 * a partial mock in file A will leak into file B's dynamic import. If you need
 * the real module in another test, either (a) don't mock at all and model the
 * behaviour in the db mock, or (b) ensure your mock factory exports every
 * function callers might access.
 */

export interface DbMockChain {
  from: (...args: any[]) => DbMockChain
  where: (...args: any[]) => DbMockChain
  orderBy: (...args: any[]) => DbMockChain
  limit: (...args: any[]) => Promise<any[]> | DbMockChain
  values: (...args: any[]) => DbMockChain
  set: (...args: any[]) => DbMockChain
  returning: (...args: any[]) => Promise<any[]> | DbMockChain
  onConflictDoNothing: (...args: any[]) => DbMockChain
  onConflictDoUpdate: (...args: any[]) => DbMockChain
}

/**
 * Build a chainable no-op that resolves to an empty array at the leaves.
 * Tests that need non-empty rows should construct their own chain.
 */
export function emptyChain(): DbMockChain {
  const chain: any = {}
  const passthrough = () => chain
  chain.from = passthrough
  chain.where = passthrough
  chain.orderBy = passthrough
  chain.set = passthrough
  chain.values = passthrough
  chain.onConflictDoNothing = passthrough
  chain.onConflictDoUpdate = passthrough
  chain.limit = () => Promise.resolve([])
  chain.returning = () => Promise.resolve([])
  return chain
}

/**
 * Build a db-module mock with every table exported. Pass a custom `db` to
 * control the select/insert/update/delete behaviour for your test.
 */
export function buildDbMock(db: Record<string, any> = {
  select: () => emptyChain(),
  insert: () => emptyChain(),
  update: () => emptyChain(),
  delete: () => emptyChain(),
  transaction: async (fn: (tx: any) => any) => fn({
    select: () => emptyChain(),
    insert: () => emptyChain(),
    update: () => emptyChain(),
    delete: () => emptyChain(),
  }),
  query: {},
}) {
  const tableStub = new Proxy({}, { get: () => 'col' })
  return {
    db,
    authChallenges: tableStub,
    authUsers: tableStub,
    federationEvents: tableStub,
    federationLinks: tableStub,
    federationServers: tableStub,
    identities: tableStub,
    mlsGroupInfo: tableStub,
    mlsKeyPackages: tableStub,
    mlsMessages: tableStub,
    mlsWelcomeMessages: tableStub,
    spaceInvites: tableStub,
    spaceInviteTokens: tableStub,
    spaceMembers: tableStub,
    spaces: tableStub,
    syncChanges: tableStub,
    tiers: tableStub,
    userStorageCredentials: tableStub,
    vaultKeys: tableStub,
  }
}
