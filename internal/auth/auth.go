// Package auth provides chi middleware for Bearer token authentication.
//
// Security design:
//   - Invalid tokens return HTTP 404 (identical to "key not found") — callers
//     cannot distinguish auth failure from missing secret.
//   - Argon2id verification is cached per-token (TTL=5min) so the intentional
//     slowness only applies on first use or after cache expiry.
//   - Cache keyed by SHA-256(rawToken) — never stores the raw token in memory.
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/local/password-vault/internal/crypto"
	"github.com/local/password-vault/internal/db"
)

type contextKey int

// AuthKey is the context key set on authenticated requests.
const AuthKey contextKey = 0

type cacheEntry struct {
	tokenID string
	valid   bool
	expiry  time.Time
}

// Middleware validates Bearer tokens using Argon2id with an in-memory cache.
type Middleware struct {
	db       *db.DB
	mu       sync.Mutex
	cache    map[string]*cacheEntry
	cacheTTL time.Duration
}

// New creates a new auth Middleware for the given database.
func New(database *db.DB) *Middleware {
	m := &Middleware{
		db:       database,
		cache:    make(map[string]*cacheEntry),
		cacheTTL: 5 * time.Minute,
	}
	go m.cleanupLoop()
	return m
}

func (m *Middleware) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		for k, v := range m.cache {
			if now.After(v.expiry) {
				delete(m.cache, k)
			}
		}
		m.mu.Unlock()
	}
}

// InvalidateCache clears all cached tokens (call after token revocation).
func (m *Middleware) InvalidateCache() {
	m.mu.Lock()
	m.cache = make(map[string]*cacheEntry)
	m.mu.Unlock()
}

// Authenticate is the chi middleware function.
// On any auth failure it calls notFound so the response is indistinguishable
// from a missing secret key.
func (m *Middleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			notFound(w)
			return
		}

		rawTokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		rawToken, err := base64.RawURLEncoding.DecodeString(rawTokenStr)
		if err != nil {
			notFound(w)
			return
		}
		if len(rawToken) != 32 {
			notFound(w)
			return
		}

		// SHA-256 hash used as cache key and DB lookup key
		h := sha256.Sum256(rawToken)
		sha256Hex := hex.EncodeToString(h[:])

		// Fast path: check the cache first
		m.mu.Lock()
		if entry, ok := m.cache[sha256Hex]; ok && time.Now().Before(entry.expiry) {
			m.mu.Unlock()
			if !entry.valid {
				notFound(w)
				return
			}
			ctx := context.WithValue(r.Context(), AuthKey, entry.tokenID)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		m.mu.Unlock()

		// Slow path: DB lookup then Argon2id verification
		token, err := m.db.GetTokenBySHA256(sha256Hex)
		if err != nil || token == nil {
			m.setCache(sha256Hex, "", false)
			notFound(w)
			return
		}

		if !crypto.VerifyToken(rawToken, token.TokenHash) {
			// SHA-256 matched but Argon2id didn't — shouldn't happen with correct DB,
			// but treat as invalid to be safe.
			m.setCache(sha256Hex, "", false)
			notFound(w)
			return
		}

		// Update last_used_at asynchronously (don't block the request)
		go func() { _ = m.db.TouchToken(token.ID) }()

		m.setCache(sha256Hex, token.ID, true)
		ctx := context.WithValue(r.Context(), AuthKey, token.ID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *Middleware) setCache(sha256Hex, tokenID string, valid bool) {
	m.mu.Lock()
	m.cache[sha256Hex] = &cacheEntry{
		tokenID: tokenID,
		valid:   valid,
		expiry:  time.Now().Add(m.cacheTTL),
	}
	m.mu.Unlock()
}

// notFound writes a JSON 404. Same body as a missing-secret response so that
// auth failures are indistinguishable from "key doesn't exist".
func notFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
}
