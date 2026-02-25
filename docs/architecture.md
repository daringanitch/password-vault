# Architecture

## Overview

The vault is split into two binaries that share the same internal packages:

```
┌─────────────────────────────────────────────────────────────┐
│  vault serve                     vault-cli                   │
│  (API server)                    (admin CLI)                 │
│                                                              │
│  cmd/vault/main.go               cmd/vault-cli/main.go      │
└────────────┬─────────────────────────────┬──────────────────┘
             │                             │
             ▼                             ▼
┌────────────────────────────────────────────────────────────┐
│                    internal packages                        │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐  │
│  │  config  │  │  crypto  │  │    db    │  │   auth    │  │
│  └──────────┘  └──────────┘  └──────────┘  └───────────┘  │
│                                                             │
│  ┌──────────┐  ┌────────────┐                              │
│  │   api    │  │ ratelimit  │                              │
│  └──────────┘  └────────────┘                              │
└────────────────────────────────────────────────────────────┘
             │
             ▼
      SQLite (vault.db)
```

---

## Package Responsibilities

### `internal/config`

Loads and validates all configuration from environment variables. Decodes the base64url master key into `[]byte`. Returns a typed `Config` struct. Both binaries call this on startup.

### `internal/crypto`

Pure functions — no I/O, no global state. All cryptographic operations live here:

| Function | Input | Output | Algorithm |
|----------|-------|--------|-----------|
| `KeyHash` | master key, key name | hex string | HMAC-SHA256 |
| `DeriveEncKey` | master key, key name | 32 bytes | HKDF-SHA256 |
| `Encrypt` | derived key, plaintext | base64 blob | AES-256-GCM |
| `Decrypt` | derived key, base64 blob | plaintext | AES-256-GCM |
| `GenerateToken` | — | raw bytes + base64url | `crypto/rand` |
| `HashToken` | raw token bytes | `salt$hash` string | Argon2id |
| `VerifyToken` | raw token bytes, hash string | bool | Argon2id + `hmac.Equal` |
| `TokenSHA256` | raw token bytes | hex string | SHA-256 |
| `GenerateMasterKey` | — | base64url string | `crypto/rand` |

### `internal/db`

Manages the SQLite connection and all database operations. Uses `modernc.org/sqlite` (pure Go, no CGo). Opens the database with WAL journal mode for better concurrent read performance and limits to one writer.

Key design decisions:
- `UpsertSecret` uses `ON CONFLICT … DO UPDATE` so add and update share one SQL path.
- `GetSecretByKeyHash` is the **only** way to retrieve a secret — there is no `ListSecrets`.
- `ListTokenNames` returns only metadata (name, status, timestamps) — never hashes or raw tokens.

### `internal/auth`

chi middleware. Extracts the Bearer token, looks it up by SHA-256 in the DB, verifies with Argon2id, and caches valid results for 5 minutes. On any failure (missing header, bad encoding, wrong token), calls `notFound` — the same response as a missing secret key.

The cache is a `map[string]*cacheEntry` protected by `sync.Mutex`. A background goroutine evicts expired entries every minute.

### `internal/api`

HTTP handlers. `GetSecret` computes the HMAC key hash, fetches from DB, derives the encryption key, and decrypts. Any error at any step returns the same `notFound` response. `Health` always returns `200 {"status":"ok"}`.

The `Cache-Control: no-store` and `Pragma: no-cache` headers on secret responses instruct clients and proxies not to cache the secret value.

### `internal/ratelimit`

Per-IP token bucket. Each IP starts with `rate` tokens (one second's worth). Tokens refill continuously up to the burst cap. A background goroutine evicts idle buckets (no traffic for 10 minutes) every 5 minutes to prevent memory growth.

---

## Request Flow: `GET /secret/{key_name}`

```
Client
  │
  │  GET /secret/github_token
  │  Authorization: Bearer <token>
  │
  ▼
chi router
  │
  ├── middleware.RealIP       rewrites RemoteAddr from X-Real-IP
  ├── middleware.Logger       logs method, path, status, latency
  ├── middleware.Recoverer    catches panics, returns 500
  ├── middleware.Timeout      30s request deadline
  ├── ratelimit.Middleware    token bucket per IP → 429 if exceeded
  │
  └── auth.Authenticate (group middleware)
        │
        ├── decode Bearer token from base64url
        ├── compute SHA-256 of raw token bytes
        ├── check in-memory cache (5-min TTL)
        │     hit  → skip Argon2id, proceed
        │     miss ↓
        ├── DB lookup by token_sha256
        │     not found → 404 (same as missing key)
        ├── Argon2id verify(raw_token, stored_hash)
        │     mismatch  → 404
        ├── async: UPDATE last_used_at
        ├── write cache entry
        └── set AuthKey in context, call next
              │
              ▼
          api.GetSecret
              │
              ├── keyHash = HMAC-SHA256(masterKey, key_name)
              ├── DB: SELECT … WHERE key_hash = ?
              │     not found → 404
              ├── encKey = HKDF-SHA256(masterKey, key_name, "vault-value")
              ├── plaintext = AES-256-GCM.Decrypt(encKey, encrypted_val)
              │     auth failure → 404
              └── 200 {"value": plaintext}
                    Cache-Control: no-store
```

---

## Data Flow: `vault-cli secret add`

```
vault-cli secret add --key "github_token" --value "ghp_xxx"
  │
  ├── config.Load()           read + decode VAULT_MASTER_KEY
  ├── db.Init(dbPath)         open SQLite, run migrations if needed
  │
  ├── keyHash  = HMAC-SHA256(masterKey, "github_token")
  ├── encKey   = HKDF-SHA256(masterKey, "github_token", "vault-value")
  ├── nonce    = 12 random bytes
  ├── sealed   = AES-256-GCM(encKey, nonce, "ghp_xxx")
  ├── encoded  = base64(nonce || sealed)
  │
  └── db.UpsertSecret(keyHash, encoded)
        INSERT INTO secrets (id, key_hash, encrypted_val, …)
        ON CONFLICT(key_hash) DO UPDATE …
```

---

## Data Flow: `vault-cli token create`

```
vault-cli token create --name "ci-runner"
  │
  ├── config.Load()
  ├── db.Init(dbPath)
  │
  ├── rawToken    = 32 random bytes (crypto/rand)
  ├── encoded     = base64url(rawToken)     ← shown to user, never stored
  ├── tokenHash   = Argon2id(rawToken, salt, t=2, m=64MB, p=4)
  ├── tokenSHA256 = SHA-256(rawToken)
  │
  └── db.CreateToken(tokenHash, tokenSHA256, "ci-runner")
        INSERT INTO access_tokens (id, token_hash, token_sha256, name, …)
```

---

## Database Schema

```
secrets
┌──────────────┬──────────────────────────────────────────────────────┐
│ id           │ UUID (primary key)                                    │
│ key_hash     │ hex(HMAC-SHA256(master_key, key_name))  UNIQUE        │
│ encrypted_val│ base64(nonce || AES-GCM ciphertext+tag)               │
│ created_at   │ UTC datetime                                          │
│ updated_at   │ UTC datetime                                          │
└──────────────┴──────────────────────────────────────────────────────┘

access_tokens
┌──────────────┬──────────────────────────────────────────────────────┐
│ id           │ UUID (primary key)                                    │
│ token_hash   │ Argon2id(raw_token, salt)               UNIQUE        │
│ token_sha256 │ hex(SHA-256(raw_token))                 UNIQUE        │
│ name         │ human label (e.g. "ci-runner")          UNIQUE        │
│ created_at   │ UTC datetime                                          │
│ last_used_at │ UTC datetime, nullable                               │
│ is_active    │ 0 or 1                                               │
└──────────────┴──────────────────────────────────────────────────────┘
```

No indexes on names — by design. No `key_name` column, no audit table.

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `github.com/go-chi/chi/v5` | v5.0.12 | HTTP routing and middleware |
| `github.com/google/uuid` | v1.6.0 | UUID generation for DB primary keys |
| `github.com/spf13/cobra` | v1.8.1 | CLI framework for vault-cli and vault |
| `golang.org/x/crypto` | v0.21.0 | Argon2id (`argon2`), HKDF (`hkdf`) |
| `modernc.org/sqlite` | v1.29.5 | Pure-Go SQLite driver (no CGo required) |
