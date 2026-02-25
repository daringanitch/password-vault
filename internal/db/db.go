// Package db provides the SQLite persistence layer for the password vault.
//
// Security notes:
//   - No plaintext key names are stored. Only HMAC-SHA256 hashes.
//   - No listing of secrets is possible via the API (no SELECT without WHERE).
//   - Access tokens are stored as Argon2id hashes + a SHA-256 lookup hash.
//   - No audit log of which secrets were accessed (black-box design).
package db

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// DB wraps a SQLite connection.
type DB struct {
	conn *sql.DB
}

// Secret is a row from the secrets table.
type Secret struct {
	ID           string
	KeyHash      string
	EncryptedVal string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// AccessToken is a row from the access_tokens table.
type AccessToken struct {
	ID          string
	TokenHash   string // Argon2id hash
	TokenSHA256 string // SHA-256 for fast lookup
	Name        string
	CreatedAt   time.Time
	LastUsedAt  *time.Time
	IsActive    bool
}

// TokenInfo is used for vault-cli token list (no raw token or hash exposed).
type TokenInfo struct {
	Name       string
	IsActive   bool
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// Init opens (or creates) the SQLite database at path and applies the schema.
func Init(path string) (*DB, error) {
	// Use WAL mode for better concurrent read performance
	conn, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	conn.SetMaxOpenConns(1) // SQLite is single-writer

	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}

	if err := migrate(conn); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return &DB{conn: conn}, nil
}

func migrate(conn *sql.DB) error {
	_, err := conn.Exec(`
		CREATE TABLE IF NOT EXISTS secrets (
			id            TEXT PRIMARY KEY,
			key_hash      TEXT UNIQUE NOT NULL,
			encrypted_val TEXT NOT NULL,
			created_at    DATETIME NOT NULL,
			updated_at    DATETIME NOT NULL
		);

		CREATE TABLE IF NOT EXISTS access_tokens (
			id           TEXT PRIMARY KEY,
			token_hash   TEXT UNIQUE NOT NULL,
			token_sha256 TEXT UNIQUE NOT NULL,
			name         TEXT UNIQUE NOT NULL,
			created_at   DATETIME NOT NULL,
			last_used_at DATETIME,
			is_active    INTEGER NOT NULL DEFAULT 1
		);
	`)
	return err
}

// Close closes the database connection.
func (d *DB) Close() error {
	return d.conn.Close()
}

// ─── Secrets ──────────────────────────────────────────────────────────────────

// UpsertSecret inserts a new secret or replaces the encrypted value if the
// key_hash already exists. keyHash is HMAC(masterKey, keyName).
func (d *DB) UpsertSecret(keyHash, encryptedVal string) error {
	now := time.Now().UTC()
	id := uuid.New().String()
	_, err := d.conn.Exec(`
		INSERT INTO secrets (id, key_hash, encrypted_val, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(key_hash) DO UPDATE SET
			encrypted_val = excluded.encrypted_val,
			updated_at    = excluded.updated_at
	`, id, keyHash, encryptedVal, now, now)
	return err
}

// GetSecretByKeyHash retrieves a secret by its HMAC key hash.
// Returns nil, nil when not found.
func (d *DB) GetSecretByKeyHash(keyHash string) (*Secret, error) {
	row := d.conn.QueryRow(`
		SELECT id, key_hash, encrypted_val, created_at, updated_at
		FROM secrets WHERE key_hash = ?
	`, keyHash)

	var s Secret
	err := row.Scan(&s.ID, &s.KeyHash, &s.EncryptedVal, &s.CreatedAt, &s.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// DeleteSecret removes a secret by key hash.
// Returns true if a row was deleted, false if the key didn't exist.
func (d *DB) DeleteSecret(keyHash string) (bool, error) {
	result, err := d.conn.Exec(`DELETE FROM secrets WHERE key_hash = ?`, keyHash)
	if err != nil {
		return false, err
	}
	n, _ := result.RowsAffected()
	return n > 0, nil
}

// ─── Access Tokens ────────────────────────────────────────────────────────────

// CreateToken stores a new access token. tokenHash is the Argon2id hash;
// tokenSHA256 is SHA-256(rawToken) for fast O(1) lookup.
func (d *DB) CreateToken(tokenHash, tokenSHA256, name string) error {
	now := time.Now().UTC()
	id := uuid.New().String()
	_, err := d.conn.Exec(`
		INSERT INTO access_tokens (id, token_hash, token_sha256, name, created_at, is_active)
		VALUES (?, ?, ?, ?, ?, 1)
	`, id, tokenHash, tokenSHA256, name, now)
	return err
}

// GetTokenBySHA256 looks up an active token by its SHA-256 hash.
// Returns nil, nil when not found or inactive.
func (d *DB) GetTokenBySHA256(sha256Hash string) (*AccessToken, error) {
	row := d.conn.QueryRow(`
		SELECT id, token_hash, token_sha256, name, created_at, last_used_at, is_active
		FROM access_tokens
		WHERE token_sha256 = ? AND is_active = 1
	`, sha256Hash)

	var t AccessToken
	var lastUsed sql.NullTime
	var isActive int
	err := row.Scan(&t.ID, &t.TokenHash, &t.TokenSHA256, &t.Name,
		&t.CreatedAt, &lastUsed, &isActive)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t.IsActive = isActive == 1
	if lastUsed.Valid {
		t.LastUsedAt = &lastUsed.Time
	}
	return &t, nil
}

// TouchToken updates last_used_at for a token (called asynchronously after auth).
func (d *DB) TouchToken(tokenID string) error {
	_, err := d.conn.Exec(
		`UPDATE access_tokens SET last_used_at = ? WHERE id = ?`,
		time.Now().UTC(), tokenID,
	)
	return err
}

// RevokeToken marks all tokens with the given name as inactive.
// Returns true if at least one token was revoked.
func (d *DB) RevokeToken(name string) (bool, error) {
	result, err := d.conn.Exec(
		`UPDATE access_tokens SET is_active = 0 WHERE name = ? AND is_active = 1`,
		name,
	)
	if err != nil {
		return false, err
	}
	n, _ := result.RowsAffected()
	return n > 0, nil
}

// ListTokenNames returns name, status, and timestamps for all tokens.
// Never returns the raw token or any hash — used only by vault-cli token list.
func (d *DB) ListTokenNames() ([]TokenInfo, error) {
	rows, err := d.conn.Query(`
		SELECT name, is_active, created_at, last_used_at
		FROM access_tokens
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []TokenInfo
	for rows.Next() {
		var t TokenInfo
		var isActive int
		var lastUsed sql.NullTime
		if err := rows.Scan(&t.Name, &isActive, &t.CreatedAt, &lastUsed); err != nil {
			return nil, err
		}
		t.IsActive = isActive == 1
		if lastUsed.Valid {
			t.LastUsedAt = &lastUsed.Time
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}
