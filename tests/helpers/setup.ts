// Test preload — runs before any test file is imported.
// Referenced from bunfig.toml: [test].preload.
//
// Env vars set here are captured by source modules that read process.env
// at module-load time (module-scope constants). Setting them in a
// beforeAll or per-file would be too late: whichever test file loads the
// source module first wins, and later changes to process.env don't
// re-bind the captured constant.

process.env.STORAGE_ENCRYPTION_KEY ??= 'test-encryption-key-32-bytes-long!!'
