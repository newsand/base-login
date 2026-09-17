# LoginBuskar - Identity Service

JWT authentication service for identity verification. No roles, no redirect — issues JWTs to prove who users are.

## Quick Start (Docker Compose)

```bash
# Clone and enter
git clone https://github.com/newsand/base-login.git
cd base-login

# Configure (optional, defaults work for local dev)
cp .env.example .env
# Edit .env: set JWT_SECRET and SERVICE_KEYS for production

# Start
docker compose up -d

# Verify
curl http://localhost:8080/health
# {"database":"ok","status":"ok","version":"alfa"}
```

## Configuration

All settings via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP port |
| `DATABASE_URL` | `postgres://...` | Postgres connection string |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `JWT_SECRET` | - | **Required in production**. Min 32 chars |
| `SERVICE_KEYS` | - | Comma-separated keys for CRUD API. Min 2 for rotation |
| `ACCESS_TOKEN_TTL` | `15m` | JWT access token lifetime |
| `REFRESH_TOKEN_TTL` | `336h` | Refresh token lifetime (14 days) |
| `MAGIC_LINK_TTL` | `15m` | Magic link expiry |
| `INVITE_TTL` | `168h` | Invite token expiry (7 days) |
| `RECOVER_TTL` | `1h` | Password recovery token expiry |
| `MAILER_STUB` | `true` | Log emails to console (set `false` for real mailer) |

## API Endpoints

All endpoints under `/v1` prefix.

### Health

```
GET /health
GET /v1/health
```

Returns `{"status":"ok","version":"alfa","database":"ok"}`.

### Authentication

```
POST /v1/auth/login          # Email + password → JWT
POST /v1/auth/refresh        # Refresh token → new JWT pair
POST /v1/auth/logout         # Revoke refresh tokens (requires JWT)
POST /v1/auth/magic-link     # Request magic link
POST /v1/auth/magic-link/consume  # Consume magic link token
GET  /v1/me                  # Get current user info (requires JWT)
```

### Password Recovery

```
POST /v1/password/forgot     # Request recovery email
POST /v1/password/reset      # Reset password with token
```

### 2FA

```
POST /v1/auth/2fa/verify     # Verify 2FA code during login
POST /v1/me/2fa/enable       # Enable 2FA (requires JWT)
POST /v1/me/2fa/disable      # Disable 2FA (requires JWT + reauth)
```

### User Management (Service Key Required)

```
POST   /v1/users             # Create user
GET    /v1/users             # List users
GET    /v1/users/:id         # Get user
PATCH  /v1/users/:id         # Update user (set disabled_at to disable)
POST   /v1/invites           # Create invite
POST   /v1/invites/accept    # Accept invite (public, rate limited)
```

## Authentication

### JWT Bearer Token

```bash
curl -H "Authorization: Bearer <access_token>" http://localhost:8080/v1/me
```

### Service Key

For user CRUD and invite creation:

```bash
curl -H "Authorization: Bearer <service_key>" http://localhost:8080/v1/users
```

Configure `SERVICE_KEYS=key1,key2` (comma-separated). Keep 2 keys active for rotation.

## Usage Examples

### Create User (Service Key)

```bash
curl -X POST http://localhost:8080/v1/users \
  -H "Authorization: Bearer your-service-key" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","nome":"User Name","password":"securepass123"}'
```

### Login

```bash
curl -X POST http://localhost:8080/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"securepass123"}'
```

Response:
```json
{
  "access_token": "eyJ...",
  "refresh_token": "a1b2c3...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

### Refresh Token

```bash
curl -X POST http://localhost:8080/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"a1b2c3..."}'
```

### Create Invite

```bash
curl -X POST http://localhost:8080/v1/invites \
  -H "Authorization: Bearer your-service-key" \
  -H "Content-Type: application/json" \
  -d '{"email":"newuser@example.com"}'
```

### Accept Invite

```bash
curl -X POST http://localhost:8080/v1/invites/accept \
  -H "Content-Type: application/json" \
  -d '{"token":"abc123...","password":"securepass123","nome":"New User"}'
```

## Deployment

### Nixpacks (Railway, Render, etc.)

The repo includes `nixpacks.toml`. Deploy by connecting to your Git repo.

Required secrets:
- `DATABASE_URL` - Postgres URL
- `JWT_SECRET` - Secure secret (32+ chars)
- `SERVICE_KEYS` - API keys for CRUD

### Docker

```bash
docker build -t loginbuskar .
docker run -p 8080:8080 \
  -e DATABASE_URL="postgres://..." \
  -e JWT_SECRET="your-secret" \
  -e SERVICE_KEYS="key1,key2" \
  loginbuskar
```

### Manual

```bash
# Install Go 1.22+
go build -o server .

# Run migrations
psql $DATABASE_URL -f migrations/001_initial.sql

# Start
./server
```

## Database

Postgres required. Run migrations before first start:

```bash
psql $DATABASE_URL -f migrations/001_initial.sql
```

Tables: `users`, `refresh_tokens`, `invites`, `magic_tokens`, `recover_tokens`, `two_fa_challenges`.

## Security Notes

- **JWT Secret**: Use 32+ character random string in production
- **Service Keys**: Rotate keys by adding new key, updating consumers, then removing old key
- **Refresh Tokens**: Stored as SHA-256 hashes. Rotation on each use. Reuse detection revokes entire family
- **Passwords**: bcrypt with default cost
- **Rate Limiting**: Built-in per-endpoint. Configure via `RATE_LIMIT_*` vars
- **Account Lockout**: After failed attempts. Configure via `LOCKOUT_*` vars

## Specs

See `AUTH-MVP.md` for product rules and `SPEC-DRIVEN.md` for architecture decisions.
