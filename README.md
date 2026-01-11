# HaexHub Sync Server

End-to-end encrypted sync backend for [HaexHub](https://github.com/haexhub/haex-hub) using Supabase.

## Features

- 🔐 **End-to-End Encryption** - All CRDT logs are encrypted client-side before syncing
- 🔑 **Hybrid Vault Key Management** - Password-encrypted vault keys stored securely
- 🚀 **High Performance** - Built with Bun and Hono for maximum speed
- 🛡️ **Row Level Security (RLS)** - Users can only access their own data
- 🔄 **CRDT-based Sync** - Conflict-free replicated data types for seamless multi-device sync
- 📡 **Realtime Updates** - Supabase Realtime for instant synchronization
- 🐳 **Docker Ready** - Includes Supabase local development stack
- 📦 **Self-Hostable** - Run on your own infrastructure

## Architecture

```
HaexHub Client (Desktop/Mobile)
    ↓ HTTPS + JWT (Encrypted CRDT Logs)
HaexHub Sync Server (this repo)
    ↓ PostgreSQL with RLS
Supabase (Auth + Database + Realtime)
```

### Key Concepts

- **Zero-Knowledge Architecture**: Server never sees unencrypted data
- **Vault Key**: 256-bit AES key generated client-side, encrypted with user password (PBKDF2 600k iterations)
- **CRDT Logs**: All changes are logged as encrypted CRDT operations
- **Supabase Auth**: Client authenticates directly with Supabase, server validates JWT tokens
- **Row Level Security**: PostgreSQL RLS ensures users can only access their own data
- **Sequence Numbers**: Auto-incrementing per-user sequence for efficient sync

## Quick Start

### Prerequisites

- [Bun](https://bun.sh) v1.3.1 or later
- [Docker](https://www.docker.com/) and Docker Compose (for local development)

### 1. Clone and Install

```bash
git clone https://github.com/haexhub/haex-sync-server.git
cd haex-sync-server
bun install
```

### 2. Start Local Supabase Stack

```bash
docker compose up -d
```

This starts:
- PostgreSQL with Supabase extensions (port 5432)
- Supabase Studio UI (http://localhost:3001)
- Kong API Gateway (port 8000)
- pg_meta API (port 8080)

Wait for services to be healthy:
```bash
docker compose ps
```

### 3. Setup Database

```bash
# Generate migration files
bun run db:generate

# Apply migrations to local database
bun run db:push
```

### 4. Configure Environment

Copy `.env.example` to `.env` and adjust if needed:

```bash
cp .env.example .env
```

Default values work for local development.

### 5. Start Development Server

```bash
bun run dev
```

The server starts on http://localhost:3000

## API Endpoints

### Health Check
```http
GET /
```

Response:
```json
{
  "name": "haex-sync-server",
  "version": "0.1.0",
  "status": "ok",
  "env": "development"
}
```

### Authentication

#### Register
```http
POST /auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "secure-password"
}
```

#### Login
```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "secure-password"
}
```

Response:
```json
{
  "message": "Login successful",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "createdAt": "2025-01-01T00:00:00.000Z"
  },
  "token": "jwt-token"
}
```

### Sync Operations

All sync endpoints require `Authorization: Bearer <token>` header.

#### Store Vault Key
```http
POST /sync/vault-key
Content-Type: application/json
Authorization: Bearer <token>

{
  "vaultId": "vault-uuid",
  "encryptedVaultKey": "base64-encrypted-key",
  "salt": "base64-salt",
  "nonce": "base64-nonce"
}
```

#### Retrieve Vault Key
```http
GET /sync/vault-key/:vaultId
Authorization: Bearer <token>
```

#### Push CRDT Logs
```http
POST /sync/push
Content-Type: application/json
Authorization: Bearer <token>

{
  "vaultId": "vault-uuid",
  "logs": [
    {
      "encryptedData": "base64-encrypted-log",
      "nonce": "base64-nonce",
      "haexTimestamp": "hlc-timestamp"
    }
  ]
}
```

#### Pull CRDT Logs
```http
POST /sync/pull
Content-Type: application/json
Authorization: Bearer <token>

{
  "vaultId": "vault-uuid",
  "afterSequence": 100,
  "limit": 100
}
```

Response:
```json
{
  "logs": [...],
  "hasMore": true
}
```

## Database Schema

### users
- `id` (uuid, primary key)
- `email` (text, unique)
- `password_hash` (text)
- `created_at`, `updated_at` (timestamp)

### vault_keys
- `id` (uuid, primary key)
- `user_id` (uuid, foreign key)
- `vault_id` (text)
- `encrypted_vault_key` (text) - AES-GCM encrypted with password-derived key
- `salt`, `nonce` (text) - For PBKDF2/AES-GCM
- `created_at`, `updated_at` (timestamp)

### sync_logs
- `id` (uuid, primary key)
- `user_id` (uuid, foreign key)
- `vault_id` (text)
- `encrypted_data` (text) - Encrypted CRDT log entry
- `nonce` (text) - AES-GCM IV
- `haex_timestamp` (text) - HLC timestamp from client
- `sequence` (integer) - Auto-incrementing per user
- `created_at` (timestamp)

## Development

### Commands

```bash
# Start development server with hot reload
bun run dev

# Start production server
bun run start

# Generate Drizzle migrations
bun run db:generate

# Apply migrations
bun run db:migrate

# Push schema directly to database (development)
bun run db:push

# Open Drizzle Studio (database GUI)
bun run db:studio
```

### Database Management

- **Supabase Studio**: http://localhost:3001 (full UI, requires Kong)
- **Drizzle Studio**: `bun run db:studio` (lightweight, direct connection)

## Deployment

### GitHub Actions (Automated)

This project uses GitHub Actions for automated deployment. On every push to `main`, the workflow:

1. Builds the Docker image
2. Pushes to GitHub Container Registry (ghcr.io)
3. Watchtower on the server automatically pulls and deploys the new image

The Docker image is available at:
```
ghcr.io/haex-space/haex-sync-server:latest
```

#### Manual Deployment

You can also trigger a build manually via the GitHub Actions UI (workflow_dispatch).

### Supabase Hosted

1. Create a Supabase project at https://supabase.com
2. Get your database connection string
3. Deploy as Supabase Edge Function or use a hosting service
4. Set environment variables

### Self-Hosted

#### Docker Compose (Production)

Use the provided `docker-compose.yml` as a base and add:

```yaml
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      DATABASE_URL: postgresql://postgres:postgres@db:5432/postgres
      JWT_SECRET: your-production-secret
      NODE_ENV: production
    depends_on:
      - db
```

#### Traditional Hosting

1. Set up PostgreSQL database
2. Configure environment variables
3. Run migrations: `bun run db:migrate`
4. Start server: `bun run start`

## Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DATABASE_URL` | PostgreSQL connection string | - | ✅ |
| `JWT_SECRET` | Secret for JWT token signing | - | ✅ |
| `JWT_EXPIRES_IN` | JWT token expiration | `7d` | ❌ |
| `PORT` | Server port | `3000` | ❌ |
| `NODE_ENV` | Environment | `development` | ❌ |
| `CORS_ORIGIN` | Allowed CORS origins (comma-separated or `*`) | `*` | ❌ |

## Security Considerations

- ✅ All CRDT logs are encrypted end-to-end (server never sees plaintext)
- ✅ Vault keys are encrypted with password-derived keys (PBKDF2 600k iterations)
- ✅ JWT-based authentication with configurable expiration
- ✅ HTTPS required in production
- ⚠️ Change `JWT_SECRET` in production
- ⚠️ Use strong database passwords
- ⚠️ Configure `CORS_ORIGIN` to specific client URLs in production

## Tech Stack

- **Runtime**: [Bun](https://bun.sh) - Fast all-in-one JavaScript runtime
- **Framework**: [Hono](https://hono.dev) - Ultrafast web framework
- **Database**: PostgreSQL (via Supabase)
- **ORM**: [Drizzle](https://orm.drizzle.team) - Type-safe SQL toolkit
- **Validation**: [Zod](https://zod.dev) - TypeScript-first schema validation
- **Auth**: JWT + bcrypt

## License

MIT

## Related Projects

- [haex-hub](https://github.com/haexhub/haex-hub) - HaexHub Desktop/Mobile Client
- [haexhub-sdk](https://github.com/haexhub/haexhub-sdk) - SDK for HaexHub Extensions

## Support

For issues and questions, please open an issue on [GitHub](https://github.com/haexhub/haex-sync-server/issues).
