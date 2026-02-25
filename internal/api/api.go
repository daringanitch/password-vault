// Package api implements the HTTP handlers for the vault API.
//
// The API surface is intentionally minimal — no listing, no enumeration.
// Callers must know both a valid token AND the exact secret key name.
package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/local/password-vault/internal/crypto"
	"github.com/local/password-vault/internal/db"
)

// Handler holds dependencies for the HTTP handlers.
type Handler struct {
	db        *db.DB
	masterKey []byte
}

// New creates a Handler.
func New(database *db.DB, masterKey []byte) *Handler {
	return &Handler{db: database, masterKey: masterKey}
}

// GetSecret handles GET /secret/{key_name}.
// Returns 200+value or 404 for any failure (missing key, decrypt error, etc.).
// Authentication is enforced by the auth middleware before this handler runs.
func (h *Handler) GetSecret(w http.ResponseWriter, r *http.Request) {
	keyName := chi.URLParam(r, "key_name")
	if keyName == "" {
		h.notFound(w)
		return
	}

	keyHash := crypto.KeyHash(h.masterKey, keyName)

	secret, err := h.db.GetSecretByKeyHash(keyHash)
	if err != nil || secret == nil {
		h.notFound(w)
		return
	}

	encKey, err := crypto.DeriveEncKey(h.masterKey, keyName)
	if err != nil {
		h.notFound(w)
		return
	}

	plaintext, err := crypto.Decrypt(encKey, secret.EncryptedVal)
	if err != nil {
		// Decryption failure (e.g. key rotation mismatch) — still return 404
		h.notFound(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(map[string]string{"value": plaintext})
}

// Health handles GET /health (unauthenticated).
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (h *Handler) notFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
}
