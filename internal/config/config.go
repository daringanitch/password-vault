package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
)

// Config holds all runtime configuration loaded from environment variables.
type Config struct {
	MasterKey []byte
	DBPath    string
	Port      int
	RateLimit float64
}

// Load reads and validates all required environment variables.
// VAULT_MASTER_KEY is required; all others have defaults.
func Load() (*Config, error) {
	masterKeyStr := os.Getenv("VAULT_MASTER_KEY")
	if masterKeyStr == "" {
		return nil, fmt.Errorf("VAULT_MASTER_KEY is required")
	}

	masterKey, err := decodeMasterKey(masterKeyStr)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		MasterKey: masterKey,
		DBPath:    envOrDefault("VAULT_DB_PATH", "./vault.db"),
		Port:      8080,
		RateLimit: 5.0,
	}

	if portStr := os.Getenv("VAULT_PORT"); portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("VAULT_PORT must be a valid port number (1-65535)")
		}
		cfg.Port = port
	}

	if rlStr := os.Getenv("VAULT_RATE_LIMIT"); rlStr != "" {
		rl, err := strconv.ParseFloat(rlStr, 64)
		if err != nil || rl <= 0 {
			return nil, fmt.Errorf("VAULT_RATE_LIMIT must be a positive number")
		}
		cfg.RateLimit = rl
	}

	return cfg, nil
}

// LoadDBOnly loads only the DB path and port (no master key required).
// Used by vault-cli init which generates its own key.
func LoadDBOnly() string {
	return envOrDefault("VAULT_DB_PATH", "./vault.db")
}

// decodeMasterKey accepts base64url (no padding) or standard base64.
// The result must be exactly 32 bytes.
func decodeMasterKey(s string) ([]byte, error) {
	key, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		// Fallback: standard base64 with padding
		key, err = base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("VAULT_MASTER_KEY must be base64url-encoded 32 bytes: %w", err)
		}
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("VAULT_MASTER_KEY must decode to exactly 32 bytes, got %d", len(key))
	}
	return key, nil
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
