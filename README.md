# password-vault

**A cryptographically opaque secret store. No UI, no enumeration, no listing.**

Callers must know **both** a valid access token **and** the exact key name to retrieve any secret. The API has two endpoints. Admin operations are CLI-only. Even with the database file and the master key, an attacker cannot list what secrets exist.

```
GET /secret/github_token
Authorization: Bearer <token>
→ 200 {"value": "ghp_xxx"}

GET /secret/nonexistent   → 404  (identical to a bad token — by design)
GET /secrets              → 404  (no listing endpoint exists)
sqlite3 vault.db "SELECT *…"  → UUIDs, HMAC hashes, AES-GCM blobs
```

[![Go](https://img.shields.io/badge/go-1.24-blue)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue)](https://ghcr.io/daringanitch/password-vault)

---

## Table of Contents

- [Security Model](#security-model)
- [How the Crypto Works](#how-the-crypto-works)
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
| Database file stolen | All values encrypted AES-256-GCM with a per-secret derived key |
| DB + master key stolen | Key names stored as `HMAC-SHA256(master_key, name)` — not reversible |
| Access token stolen | Attacker still needs exact key names; no enumeration endpoint exists |
| Brute-force via API | Per-IP rate limiting (5 req/s) + constant-time token comparison |
| Oracle attack (does this key exist?) | Auth failure and missing key return identical `404 {"error":"not found"}` |
| Container compromise | Non-root user, read-only root filesystem, all capabilities dropped |

See [`docs/security.md`](docs/security.md) for the full cryptographic threat model.

---

## How the Crypto Works

```
WRITE PATH (vault-cli)
──────────────────────
key_name ──┬── HMAC-SHA256(master_key) ──→ key_hash  (stored in DB)
           └── HKDF-SHA256(master_key, key_name, "vault-value") ──→ enc_key
                                                                        │
plaintext ──────────────────── AES-256-GCM(enc_key, random_nonce) ──→ blob (stored in DB)

READ PATH (API)
───────────────
Bearer token ──→ SHA-256 lookup in DB ──→ Argon2id verify ──→ authenticated
key_name     ──→ HMAC-SHA256(master_key) ──→ lookup blob ──→ HKDF derive enc_key ──→ decrypt ──→ plaintext
```

**Key properties:**
- Every secret gets its own encryption key (HKDF binds the derived key to the secret name)
- Nonces are randomly generated per encryption call — same value encrypted twice produces different blobs
- Access tokens are Argon2id-hashed (`t=2, m=64MB, p=4`); raw tokens are never stored anywhere
- A stolen database without the master key reveals nothing — no key names, no values

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
```

```
╔══════════════════════════════════════════════════════════════╗
║              VAULT MASTER KEY — SAVE THIS NOW               ║
╠══════════════════════════════════════════════════════════════╣
║  VAULT_MASTER_KEY=abc123...
╚══════════════════════════════════════════════════════════════╝
```

> The master key is shown **once**. There is no recovery mechanism if it is lost.

```bash
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

### Pull from GitHub Container Registry

```bash
docker pull ghcr.io/daringanitch/password-vault:latest
```

### Run with Docker

```bash
# 1. Generate a master key (first time only)
docker run --rm --entrypoint vault-cli \
  ghcr.io/daringanitch/password-vault init
# → prints VAULT_MASTER_KEY=...

# 2. Export the key
export VAULT_MASTER_KEY=<key-from-above>

# 3. Add a secret
docker run --rm \
  -e VAULT_MASTER_KEY \
  -v vault-data:/vault/data \
  --entrypoint vault-cli \
  ghcr.io/daringanitch/password-vault secret add --key "db_password" --value "hunter2"

# 4. Create an access token
docker run --rm \
  -e VAULT_MASTER_KEY \
  -v vault-data:/vault/data \
  --entrypoint vault-cli \
  ghcr.io/daringanitch/password-vault token create --name "ci-runner"

# 5. Start the API server
docker run -d \
  --name vault \
  -p 8080:8080 \
  -e VAULT_MASTER_KEY \
  -v vault-data:/vault/data \
  ghcr.io/daringanitch/password-vault
```

### Run with Docker Compose

```bash
# VAULT_MASTER_KEY must be exported or in .env
export VAULT_MASTER_KEY=<key>
docker compose up -d

# Admin commands via the vault-cli service
docker compose run --rm vault-cli secret add --key "api_key" --value "sk-xxx"
docker compose run --rm vault-cli token list

docker compose down
```

### Makefile shortcuts

```bash
make docker-build                    # build image
make docker-run                      # start server (requires VAULT_MASTER_KEY)
make docker-cli CMD="token list"     # run any vault-cli command
make docker-compose-up               # start via docker compose
make docker-compose-down             # stop
```

### Image details

| Property | Value |
|----------|-------|
| Registry | `ghcr.io/daringanitch/password-vault` |
| Base image | `alpine:3.19` |
| Image size | ~12 MB |
| User | `vault` (non-root) |
| Filesystem | Read-only (only `/vault/data` volume is writable) |
| Capabilities | All dropped |
| Exposed port | `8080` |
| Default volume | `/vault/data` |

> **Never bake `VAULT_MASTER_KEY` into the image.** Inject it at runtime via `-e` or a secrets manager.

---

## API Reference

The server exposes **two endpoints only**. There is no `GET /secrets`, no `POST /secret`, and no token management via HTTP — all admin operations require CLI access to the host running the vault.

### `GET /secret/{key_name}`

Retrieves a secret value. Requires a valid `Authorization: Bearer` token.

```
GET /secret/github_token HTTP/1.1
Host: localhost:8080
Authorization: Bearer <access_token>
```

| Status | Body | Condition |
|--------|------|-----------|
| `200 OK` | `{"value": "..."}` | Token valid AND key exists |
| `404 Not Found` | `{"error": "not found"}` | Token invalid OR key missing — indistinguishable by design |
| `429 Too Many Requests` | — | Rate limit exceeded |

```bash
# Success
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/secret/database_password
# {"value":"super-secret-db-pass"}

# Missing key — same response as bad token
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/secret/does_not_exist
# {"error":"not found"}
```

Response headers on `200`: `Cache-Control: no-store`, `Pragma: no-cache`.

### `GET /health`

Unauthenticated health check for load balancers and container probes.

```bash
curl -s http://localhost:8080/health
# {"status":"ok"}
```

---

## CLI Reference

All commands except `init` require `VAULT_MASTER_KEY` to be set in the environment.

### `vault serve`

```bash
VAULT_MASTER_KEY=<key> vault serve
# vault listening on :8080 (db=./vault.db, rate=5 req/s)
```

### `vault-cli init`

Generates a new master key and initializes the database. If `VAULT_MASTER_KEY` is already set, skips key generation and only creates the DB schema.

```bash
vault-cli init [--db ./vault.db]
```

### `vault-cli secret`

```bash
# Add (fails if key already exists)
vault-cli secret add    --key "github_token"  --value "ghp_xxx"

# Update (fails if key doesn't exist)
vault-cli secret update --key "github_token"  --value "ghp_yyy"

# Delete permanently
vault-cli secret delete --key "github_token"
```

There is no `secret list` command — this is intentional.

### `vault-cli token`

```bash
# Create — raw token printed once
vault-cli token create --name "ci-runner"

# Revoke — takes effect within 5 minutes (server-side cache TTL)
vault-cli token revoke --name "ci-runner"

# List — shows name and status only, never the raw token
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

All configuration via environment variables. See [`.env.example`](.env.example).

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VAULT_MASTER_KEY` | **Yes** | — | Base64url-encoded 32-byte master key. Generate with `vault-cli init`. |
| `VAULT_DB_PATH` | No | `./vault.db` | Path to the SQLite database file. |
| `VAULT_PORT` | No | `8080` | TCP port the API server listens on. |
| `VAULT_RATE_LIMIT` | No | `5` | Max requests per second per client IP. |

---

## Project Structure

```
password-vault/
├── cmd/
│   ├── vault/main.go            # API server (vault serve)
│   └── vault-cli/main.go        # Admin CLI
├── internal/
│   ├── api/api.go               # HTTP handlers: GetSecret, Health
│   ├── auth/auth.go             # Bearer token middleware + 5-min cache
│   ├── crypto/
│   │   ├── crypto.go            # HMAC, HKDF, AES-GCM, Argon2id, token generation
│   │   └── crypto_test.go       # 14 unit tests
│   ├── db/db.go                 # SQLite schema and CRUD (no secret listing)
│   ├── config/config.go         # Env var loading and validation
│   └── ratelimit/ratelimit.go   # Per-IP token-bucket limiter
├── docs/
│   ├── security.md              # Cryptographic design and threat model
│   └── architecture.md          # Component diagrams and data flow
├── .env.example
├── Dockerfile
├── docker-compose.yml
├── go.mod
└── Makefile
```

---

## Development

```bash
make test         # All tests with race detector and coverage
make test-crypto  # Crypto unit tests only (fast)
make lint         # go vet
make clean        # Remove build artifacts
```

### Database schema

```sql
CREATE TABLE secrets (
    id            TEXT PRIMARY KEY,       -- random UUID
    key_hash      TEXT UNIQUE NOT NULL,   -- HMAC-SHA256(master_key, key_name)
    encrypted_val TEXT NOT NULL,          -- base64(nonce || AES-GCM ciphertext+tag)
    created_at    DATETIME NOT NULL,
    updated_at    DATETIME NOT NULL
);

CREATE TABLE access_tokens (
    id           TEXT PRIMARY KEY,
    token_hash   TEXT UNIQUE NOT NULL,   -- Argon2id hash
    token_sha256 TEXT UNIQUE NOT NULL,   -- SHA-256 for O(1) DB lookup
    name         TEXT UNIQUE NOT NULL,
    created_at   DATETIME NOT NULL,
    last_used_at DATETIME,
    is_active    INTEGER NOT NULL DEFAULT 1
);
```

No plaintext key names. No audit log of which secrets were accessed.

### Key rotation

There is no automated rotation. To rotate the master key:

1. Read and re-add each secret under a new master key using `vault-cli` (requires knowing all key names — maintain your own inventory separately).
2. Update `VAULT_MASTER_KEY` and restart the server.

---

## License

MIT
