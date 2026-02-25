// Package crypto provides all cryptographic primitives for the password vault.
//
// Security design:
//   - Key names are stored as HMAC-SHA256(master_key, name) — never in plaintext.
//   - Each secret value gets its own encryption key derived via HKDF-SHA256.
//   - Values are encrypted with AES-256-GCM (authenticated encryption).
//   - Access tokens are hashed with Argon2id (brute-force resistant).
//   - Token lookup uses SHA-256 (fast, safe because tokens are 256-bit random).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// Argon2id parameters. time=2, mem=64MB, threads=4 per OWASP recommendations.
const (
	argon2Time    uint32 = 2
	argon2Memory  uint32 = 64 * 1024 // 64 MiB
	argon2Threads uint8  = 4
	argon2KeyLen  uint32 = 32
	argon2SaltLen        = 16
)

// KeyHash returns HMAC-SHA256(masterKey, keyName) as a lowercase hex string.
// This is stored in the database instead of the plaintext key name.
func KeyHash(masterKey []byte, keyName string) string {
	mac := hmac.New(sha256.New, masterKey)
	mac.Write([]byte(keyName))
	return hex.EncodeToString(mac.Sum(nil))
}

// DeriveEncKey derives a 32-byte per-secret encryption key using HKDF-SHA256.
// The key name acts as the salt so each secret gets a unique encryption key.
func DeriveEncKey(masterKey []byte, keyName string) ([]byte, error) {
	r := hkdf.New(sha256.New, masterKey, []byte(keyName), []byte("vault-value"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf derive: %w", err)
	}
	return key, nil
}

// Encrypt encrypts plaintext with AES-256-GCM and returns base64(nonce || ciphertext+tag).
// A fresh 12-byte nonce is generated for every call.
func Encrypt(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm init: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce gen: %w", err)
	}

	// Seal appends ciphertext+tag to nonce, producing nonce||ciphertext+tag
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt decrypts base64(nonce || ciphertext+tag) produced by Encrypt.
func Decrypt(key []byte, encoded string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm init: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize+1 {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("gcm decrypt: %w", err) // authentication failure
	}
	return string(plaintext), nil
}

// HashToken creates an Argon2id hash of rawToken and returns it as
// "<base64(salt)>$<base64(hash)>" — same format used by VerifyToken.
func HashToken(rawToken []byte) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("salt gen: %w", err)
	}
	hash := argon2.IDKey(rawToken, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return fmt.Sprintf("%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyToken checks rawToken against a storedHash produced by HashToken.
// Uses constant-time comparison to prevent timing attacks.
func VerifyToken(rawToken []byte, storedHash string) bool {
	parts := strings.SplitN(storedHash, "$", 2)
	if len(parts) != 2 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	computed := argon2.IDKey(rawToken, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return hmac.Equal(computed, expected)
}

// TokenSHA256 returns hex(SHA-256(rawToken)) for O(1) database lookup.
// Safe to store in plaintext: rawToken is 256-bit random so SHA-256
// cannot be brute-forced even with fast hardware.
func TokenSHA256(rawToken []byte) string {
	h := sha256.Sum256(rawToken)
	return hex.EncodeToString(h[:])
}

// GenerateToken produces 32 cryptographically random bytes and returns them
// as both the raw bytes and a base64url-encoded string (no padding).
// The encoded string is what gets shown to the user and sent as the Bearer token.
func GenerateToken() (rawToken []byte, encoded string, err error) {
	rawToken = make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, rawToken); err != nil {
		return nil, "", fmt.Errorf("generate token: %w", err)
	}
	return rawToken, base64.RawURLEncoding.EncodeToString(rawToken), nil
}

// GenerateMasterKey produces a 32-byte random master key and returns it
// base64url-encoded (no padding), suitable for VAULT_MASTER_KEY.
func GenerateMasterKey() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", fmt.Errorf("generate master key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(key), nil
}
