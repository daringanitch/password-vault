# About
Black-box Password Vault

A cryptographically opaque secret store. No UI, no enumeration, no listing.
Callers must know **both** a valid access token **and** the exact key name to retrieve any secret.
If the database is stolen it is useless without the master key.
If the master key is stolen, key names are still protected by HMAC — an attacker must brute-force every possible name.

```
GET /secret/github_token
Authorization: Bearer <token>
→ 200 {"value": "ghp_xxx"}

GET /secret/nonexistent       → 404  (indistinguishable from bad token)
GET /secrets                  → 404  (no listing endpoint)
sqlite3 vault.db "SELECT *…"  → UUIDs, HMAC hashes, AES-GCM blobs only
```

---

## Table of Contents

- [Security Model](#security-model)
- [Quick Start](#quick-start)
- [Docker](#docker)
- [API Reference](#api-reference)
- [CLI Reference](#cli-reference)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Development](#development)

---

## Security Model

| Threat | Defense |
|--------|---------|
| Database file stolen | All values encrypted with AES-256-GCM under a per-key derived key |
| DB + master key stolen | Key names stored as `HMAC-SHA256(master_key, name)` — not reversible |
| Access token stolen | Attacker still needs exact key names (no enumeration endpoint exists) |
| Brute-force key names via API | Rate limiting (5 req/s per IP) + constant-time comparison |
| Oracle attack (does key exist?) | Auth failure and missing key return identical `404 {"error":"not found"}` |

See [`docs/security.md`](docs/security.md) for a full breakdown of the cryptographic design.

---

## Quick Start

**Prerequisites:** [Go 1.22+](https://go.dev/dl/)

```bash
# 1. Clone and build
git clone https://github.com/daringanitch/password-vault
cd password-vault
go mod tidy
make build          # produces ./bin/vault and ./bin/vault-cli

# 2. Initialize — generates a master key and creates vault.db
./bin/vault-cli init

# 3. Export the printed key
export VAULT_MASTER_KEY=<key-from-above>

# 4. Add a secret
./bin/vault-cli secret add --key "github_token" --value "ghp_xxx"

# 5. Create an API access token (printed once — save it)
./bin/vault-cli token create --name "ci-runner"

# 6. Start the server
./bin/vault serve

# 7. Read the secret
curl -s -H "Authorization: Bearer <token>" \
  http://localhost:8080/secret/github_token
# → {"value":"ghp_xxx"}
```

---

## Docker

### Build the image

```bash
docker build -t password-vault .
# or
make docker-build
```

The image uses a two-stage build. The final image is based on `alpine:3.19` and contains only the two binaries — no Go toolchain, no source. The vault runs as a non-root user (`vault`) with a read-only root filesystem.

### Run with Docker

```bash
# 1. Generate a master key (first time only)
docker run --rm password-vault vault-cli init
# → prints VAULT_MASTER_KEY=...

# 2. Export the key
export VAULT_MASTER_KEY=<key-from-above>

# 3. Add a secret (admin operation via vault-cli)
docker run --rm \
  -e VAULT_MASTER_KEY \
  -v vault-data:/vault/data \
  --entrypoint vault-cli \
  password-vault secret add --key "db_password" --value "hunter2"

# 4. Create an access token
docker run --rm \
  -e VAULT_MASTER_KEY \
  -v vault-data:/vault/data \
  --entrypoint vault-cli \
  password-vault token create --name "ci-runner"

# 5. Start the API server
docker run -d \
  --name vault \
  -p 8080:8080 \
  -e VAULT_MASTER_KEY \
  -v vault-data:/vault/data \
  password-vault
```

### Run with Docker Compose

```bash
# Start the API server (VAULT_MASTER_KEY must be exported or in .env)
export VAULT_MASTER_KEY=<key>
docker compose up -d

# Run admin commands via the vault-cli service
docker compose run --rm vault-cli token list
docker compose run --rm vault-cli secret add --key "api_key" --value "sk-xxx"

# Stop
docker compose down
```

### Makefile shortcuts

```bash
make docker-build           # build image
make docker-run             # run server (requires VAULT_MASTER_KEY)
make docker-cli CMD="token list"   # run any vault-cli command
make docker-compose-up      # start via docker compose
make docker-compose-down    # stop
```

### Image details

| Property | Value |
|----------|-------|
| Base image | `alpine:3.19` |
| User | `vault` (non-root) |
| Filesystem | Read-only (only `/vault/data` volume is writable) |
| Capabilities | All dropped |
| Exposed port | `8080` |
| Default volume | `/vault/data` (mount here for persistence) |
| `VAULT_DB_PATH` default | `/vault/data/vault.db` |

> **Never bake `VAULT_MASTER_KEY` into the image.** Always inject it at runtime via `-e` or a secrets manager (Docker Swarm secrets, Kubernetes secrets, AWS Secrets Manager, etc.).

---

## API Reference

The server exposes **two** endpoints only. There is intentionally no `GET /secrets`, no `POST /secret`, and no token management via HTTP.

### `GET /secret/{key_name}`

Retrieves a secret value. Requires a valid `Authorization: Bearer` token.

**Request**

```
GET /secret/github_token HTTP/1.1
Host: localhost:8080
Authorization: Bearer <access_token>
```

**Responses**

| Status | Body | Condition |
|--------|------|-----------|
| `200 OK` | `{"value": "..."}` | Token valid AND key exists |
| `404 Not Found` | `{"error": "not found"}` | Token invalid OR key missing (indistinguishable) |
| `429 Too Many Requests` | — | Rate limit exceeded (5 req/s per IP) |

```bash
# Success
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/secret/database_password
# {"value":"super-secret-db-pass"}

# Missing key (same response as bad token)
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/secret/does_not_exist
# {"error":"not found"}

# Bad token (same response as missing key)
curl -s -H "Authorization: Bearer badtoken" \
  http://localhost:8080/secret/database_password
# {"error":"not found"}
```

### `GET /health`

Health check. No authentication required.

```bash
curl -s http://localhost:8080/health
# {"status":"ok"}
```

---

## CLI Reference

All commands except `init` require `VAULT_MASTER_KEY` to be exported.

### `vault serve`

Starts the HTTP API server.

```bash
VAULT_MASTER_KEY=<key> vault serve
# vault listening on :8080 (db=./vault.db, rate=5 req/s)
```

### `vault-cli init`

Generates a new master key and initializes the database schema.
If `VAULT_MASTER_KEY` is already set, skips key generation and just creates the DB.

```bash
vault-cli init [--db ./vault.db]
```

```
╔══════════════════════════════════════════════════════════════╗
║              VAULT MASTER KEY — SAVE THIS NOW               ║
╠══════════════════════════════════════════════════════════════╣
║  VAULT_MASTER_KEY=abc123...
╚══════════════════════════════════════════════════════════════╝
Vault database initialized: ./vault.db
```

> The master key is shown **once**. There is no recovery if it is lost.

### `vault-cli secret`

```bash
# Add a new secret (fails if key already exists)
vault-cli secret add    --key "github_token"  --value "ghp_xxx"

# Update an existing secret's value (fails if key doesn't exist)
vault-cli secret update --key "github_token"  --value "ghp_yyy"

# Delete a secret permanently
vault-cli secret delete --key "github_token"
```

There is no `secret list` command — this is intentional.

### `vault-cli token`

```bash
# Create an access token (raw token printed ONCE)
vault-cli token create --name "ci-runner"

# Revoke a token by name (takes effect within 5 minutes due to server cache)
vault-cli token revoke --name "ci-runner"

# List all tokens — shows name and status, never the raw token
vault-cli token list
```

```
NAME        STATUS   CREATED               LAST USED
────        ──────   ───────               ─────────
ci-runner   active   2026-01-01T00:00:00Z  2026-01-15T12:34:56Z
old-key     revoked  2025-12-01T00:00:00Z  never
```

---

## Configuration

All configuration is via environment variables. See [`.env.example`](.env.example).

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VAULT_MASTER_KEY` | **Yes** | — | Base64url-encoded 32-byte master key. Generate with `vault-cli init`. |
| `VAULT_DB_PATH` | No | `./vault.db` | Path to the SQLite database file. |
| `VAULT_PORT` | No | `8080` | TCP port the API server listens on. |
| `VAULT_RATE_LIMIT` | No | `5` | Max API requests per second per client IP. |

---

## Project Structure

```
password-vault/
├── cmd/
│   ├── vault/
│   │   └── main.go          # API server binary (vault serve)
│   └── vault-cli/
│       └── main.go          # Admin CLI binary
├── internal/
│   ├── config/
│   │   └── config.go        # Environment variable loading and validation
│   ├── crypto/
│   │   ├── crypto.go        # HMAC, HKDF, AES-GCM, Argon2id, token generation
│   │   └── crypto_test.go   # 14 unit tests for all crypto operations
│   ├── db/
│   │   └── db.go            # SQLite schema, CRUD (no list for secrets)
│   ├── auth/
│   │   └── auth.go          # chi middleware: Bearer token validation + cache
│   ├── api/
│   │   └── api.go           # HTTP handlers: GetSecret, Health
│   └── ratelimit/
│       └── ratelimit.go     # Per-IP token-bucket rate limiter
├── docs/
│   ├── security.md          # Cryptographic design and threat model
│   └── architecture.md      # Component architecture and data flow
├── .env.example             # Environment variable reference
├── .gitignore
├── go.mod
└── Makefile
```

See [`docs/architecture.md`](docs/architecture.md) for component diagrams and data flow.

---

## Development

```bash
# Run all tests (includes crypto round-trip and tamper detection)
make test

# Run only the crypto tests (fast, no network)
make test-crypto

# Lint
make lint

# Clean build artifacts
make clean
```

### Database schema

```sql
CREATE TABLE secrets (
    id            TEXT PRIMARY KEY,       -- UUID
    key_hash      TEXT UNIQUE NOT NULL,   -- HMAC-SHA256(master_key, key_name)
    encrypted_val TEXT NOT NULL,          -- base64(nonce || AES-GCM ciphertext)
    created_at    DATETIME NOT NULL,
    updated_at    DATETIME NOT NULL
);

CREATE TABLE access_tokens (
    id           TEXT PRIMARY KEY,
    token_hash   TEXT UNIQUE NOT NULL,   -- Argon2id hash
    token_sha256 TEXT UNIQUE NOT NULL,   -- SHA-256 for O(1) lookup
    name         TEXT UNIQUE NOT NULL,   -- human label
    created_at   DATETIME NOT NULL,
    last_used_at DATETIME,
    is_active    INTEGER NOT NULL DEFAULT 1
);
```

No plaintext key names, no audit log of which secrets were accessed.

### Key rotation

There is no automated key rotation. To rotate the master key:

1. Use `vault-cli secret` to read and re-add each secret under a new master key (requires knowing all key names — keep your own inventory).
2. Update `VAULT_MASTER_KEY` and restart the server.

---

## License

MIT
