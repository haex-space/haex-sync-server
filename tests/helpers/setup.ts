// Test preload — runs before any test file is imported.
// Referenced from bunfig.toml: [test].preload.
//
// Env vars set here are captured by source modules that read process.env
// at module-load time (module-scope constants). Setting them in a
// beforeAll or per-file would be too late: whichever test file loads the
// source module first wins, and later changes to process.env don't
// re-bind the captured constant.

process.env.STORAGE_ENCRYPTION_KEY ??= 'test-encryption-key-32-bytes-long!!'

// src/db/index.ts throws on load if DATABASE_URL is unset. Tests that touch
// the db mock the module; tests that pull it in only transitively (e.g. via
// src/routes/federation.helpers.ts) still trigger the top-level check before
// their mock.module() can take effect, because ESM imports are hoisted. Set a
// dummy URL here so module-load never throws — postgres() is lazy and does
// not connect until a query runs.
process.env.DATABASE_URL ??= 'postgres://test:test@localhost:5432/test'
