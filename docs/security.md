# Security Design

This document describes the cryptographic primitives used by the vault, the reasoning behind each choice, and the limits of the security model.

---

## Threat Model

The vault is designed to protect secrets at rest and to prevent API-level enumeration. It assumes:

- The **server process** is trusted (running on infrastructure you control).
- The **master key** is stored outside the database (environment variable, secrets manager, HSM).
- The **API** is not exposed to the public internet without a reverse proxy + TLS.

It does **not** protect against:
- A compromised server process with access to the process environment (master key is in memory).
- A side-channel attack measuring Argon2id computation time to distinguish "bad token" from "valid token + bad key" on the *first* request (before the auth cache warms up).
- Physical access to a running machine with the master key in memory.

---

## Encryption at Rest

### Key names

Key names are **never stored in the database**. Instead, the vault stores:

```
key_hash = HMAC-SHA256(master_key, key_name)
```

HMAC is a one-way function when the key is secret: without `master_key`, an attacker with the database cannot reverse `key_hash` to recover any key name. They would need to brute-force every possible name — and with a 32-byte random master key, HMAC-SHA256 provides 256 bits of pre-image resistance.

### Secret values

Each secret gets its own encryption key derived from the master key:

```
enc_key = HKDF-SHA256(
    ikm  = master_key,
    salt = key_name,       # binds the key to this specific secret
    info = "vault-value",  # domain separation
    len  = 32 bytes
)
```

Using HKDF means:
- Even if two secrets have the same value, their ciphertexts are unrelated (different `enc_key`).
- Compromising one derived key does not compromise the master key or any other derived key.

The value is then encrypted:

```
nonce      = 12 random bytes (generated fresh per Encrypt call)
ciphertext = AES-256-GCM(enc_key, nonce, plaintext)
stored     = base64(nonce || ciphertext || 16-byte GCM tag)
```

AES-256-GCM provides both confidentiality and integrity. A tampered ciphertext will fail authentication at decrypt time and the vault returns 404.

### Why a fresh nonce per call?

AES-GCM is only secure when a (key, nonce) pair is never reused. Since `enc_key` is deterministic for a given `(master_key, key_name)` pair, reusing the nonce would be catastrophic. Generating a fresh random nonce on every `Encrypt` call eliminates this risk.

---

## Access Token Design

### Token generation

```
raw_token = 32 random bytes      (256 bits of entropy from crypto/rand)
bearer    = base64url(raw_token) (what the client sends)
```

256 bits of entropy makes brute-force attacks computationally infeasible even against fast hardware.

### Token storage

```
token_hash   = Argon2id(raw_token, salt=random_16_bytes, t=2, m=64MB, p=4)
token_sha256 = SHA-256(raw_token)
```

Two hashes serve different purposes:

| Hash | Purpose | Stored in DB | Properties |
|------|---------|-------------|------------|
| `token_sha256` | Fast O(1) lookup | Yes | Deterministic; safe because raw_token is 256-bit random |
| `token_hash` | Brute-force resistance | Yes | Slow (64 MB, 2 passes); attacker cannot precompute |

**Why is SHA-256 safe to store here?**
SHA-256 is fast (~10⁹ H/s on GPU). But raw_token has 256 bits of entropy. At 10⁹ H/s, brute-forcing a random 256-bit value would take ~10⁶⁰ years. The SHA-256 lookup hash does not weaken the security of the token.

**Why use Argon2id at all if SHA-256 is safe?**
Argon2id provides defense-in-depth. If the token space were ever reduced (e.g., a weak RNG), the memory-hard function ensures an attacker cannot accelerate brute-force with custom hardware.

### Token verification flow

```
Client sends:  Authorization: Bearer <base64url_token>

Server:
  1. Decode base64url → raw_token (32 bytes)
  2. sha256_hex = hex(SHA-256(raw_token))
  3. DB lookup: SELECT … WHERE token_sha256 = sha256_hex AND is_active = 1
     → Not found: return 404 (no cache write for missing tokens)
     → Found: proceed
  4. Argon2id verify: recompute with stored salt, compare with hmac.Equal
     → Mismatch: return 404
     → Match: cache (sha256_hex → token_id, TTL=5min), proceed to handler
```

The Argon2id check runs once per token per 5-minute window. Subsequent requests hit the in-memory cache.

---

## Oracle Resistance

The vault must not allow an attacker to learn whether a key exists or whether their token is valid via the HTTP response.

| Scenario | Response |
|----------|----------|
| Valid token + key exists | `200 {"value":"..."}` |
| Valid token + key missing | `404 {"error":"not found"}` |
| Invalid token | `404 {"error":"not found"}` |
| No Authorization header | `404 {"error":"not found"}` |

All failure cases return the same status code and body. This prevents:
- **Token oracle**: An attacker cannot probe whether their token is valid.
- **Key enumeration oracle**: A valid token cannot be used to discover which key names exist.

### Timing consideration

There is a timing side-channel on the *first* unauthenticated request: Argon2id takes ~500ms, while a DB miss is ~microseconds. A determined attacker with network access could use this to distinguish "token found in DB" from "token not found". Mitigations:
- The rate limiter (5 req/s) limits the measurement bandwidth.
- The 5-minute cache means subsequent requests from a valid token are timing-indistinguishable from a fast path.
- Deploying behind a reverse proxy that buffers responses can further obscure timing.

---

## Rate Limiting

A per-IP token bucket allows `VAULT_RATE_LIMIT` (default: 5) requests per second with a burst equal to one second's worth of tokens. Exceeding the limit returns `429 Too Many Requests` with a `Retry-After: 1` header.

The limiter uses `r.RemoteAddr` after chi's `RealIP` middleware rewrites it from `X-Real-IP` (set by a trusted reverse proxy). In direct-exposure deployments, `RemoteAddr` is the client's address.

---

## What This Vault Does Not Provide

- **Audit logging** — no record of which secrets were accessed, by whom, or when (black-box by design).
- **Secret versioning** — `secret update` overwrites in place.
- **Automatic key rotation** — see the [README key rotation section](../README.md#key-rotation).
- **TLS termination** — deploy behind nginx/caddy/a load balancer with TLS in production.
- **Multi-tenancy** — all secrets share one master key; use separate instances for isolation.
