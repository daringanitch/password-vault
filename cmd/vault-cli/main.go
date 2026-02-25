// vault-cli — Admin CLI for managing secrets and access tokens.
// All commands (except init) require VAULT_MASTER_KEY to be set.
package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/local/password-vault/internal/config"
	"github.com/local/password-vault/internal/crypto"
	"github.com/local/password-vault/internal/db"
)

func main() {
	root := &cobra.Command{
		Use:   "vault-cli",
		Short: "Admin CLI for the password vault",
		Long: `vault-cli manages secrets and access tokens.
All commands except 'init' require VAULT_MASTER_KEY to be set.`,
	}

	root.AddCommand(initCmd())
	root.AddCommand(secretCmd())
	root.AddCommand(tokenCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// mustOpenDB loads config + opens DB. Calls log.Fatal on any error.
func mustOpenDB() (*db.DB, []byte) {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v\n\nSet VAULT_MASTER_KEY and try again.", err)
	}
	database, err := db.Init(cfg.DBPath)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	return database, cfg.MasterKey
}

// ─── init ─────────────────────────────────────────────────────────────────────

func initCmd() *cobra.Command {
	var dbPath string

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate a master key and initialize the vault database",
		Long: `Generates a new VAULT_MASTER_KEY and creates the vault.db schema.
If VAULT_MASTER_KEY is already set, skips key generation and uses it.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var masterKeyEnc string

			if existing := os.Getenv("VAULT_MASTER_KEY"); existing != "" {
				// Validate the existing key
				b, err := base64.RawURLEncoding.DecodeString(existing)
				if err != nil || len(b) != 32 {
					return fmt.Errorf("existing VAULT_MASTER_KEY is invalid (must be base64url-encoded 32 bytes)")
				}
				masterKeyEnc = existing
				fmt.Fprintln(os.Stderr, "Note: using existing VAULT_MASTER_KEY from environment")
			} else {
				// Generate a new master key
				var err error
				masterKeyEnc, err = crypto.GenerateMasterKey()
				if err != nil {
					return fmt.Errorf("generate master key: %w", err)
				}
				fmt.Println("╔══════════════════════════════════════════════════════════════╗")
				fmt.Println("║              VAULT MASTER KEY — SAVE THIS NOW               ║")
				fmt.Println("╠══════════════════════════════════════════════════════════════╣")
				fmt.Printf("║  VAULT_MASTER_KEY=%s\n", masterKeyEnc)
				fmt.Println("╠══════════════════════════════════════════════════════════════╣")
				fmt.Println("║  This key is shown ONCE. Store it in a secure location.     ║")
				fmt.Println("║  Loss of this key means all vault secrets are unrecoverable. ║")
				fmt.Println("╚══════════════════════════════════════════════════════════════╝")
				fmt.Println()
			}

			// Open/create DB (tables are created by db.Init)
			os.Setenv("VAULT_MASTER_KEY", masterKeyEnc)
			os.Setenv("VAULT_DB_PATH", dbPath)
			database, err := db.Init(dbPath)
			if err != nil {
				return fmt.Errorf("init db: %w", err)
			}
			defer database.Close()

			fmt.Printf("Vault database initialized: %s\n", dbPath)
			fmt.Println()
			fmt.Println("Next steps:")
			fmt.Printf("  export VAULT_MASTER_KEY=%s\n", masterKeyEnc)
			fmt.Printf("  vault-cli secret add --key \"my_secret\" --value \"hunter2\"\n")
			fmt.Printf("  vault-cli token create --name \"ci-runner\"\n")
			fmt.Printf("  vault serve\n")
			return nil
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", "./vault.db", "Path to vault database file")
	return cmd
}

// ─── secret ───────────────────────────────────────────────────────────────────

func secretCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Manage vault secrets (add, update, delete)",
	}
	cmd.AddCommand(secretAddCmd(), secretUpdateCmd(), secretDeleteCmd())
	return cmd
}

func secretAddCmd() *cobra.Command {
	var key, value string

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new secret",
		RunE: func(cmd *cobra.Command, args []string) error {
			if key == "" || value == "" {
				return fmt.Errorf("--key and --value are required")
			}

			database, masterKey := mustOpenDB()
			defer database.Close()

			// Check for duplicate
			keyHash := crypto.KeyHash(masterKey, key)
			existing, err := database.GetSecretByKeyHash(keyHash)
			if err != nil {
				return fmt.Errorf("db lookup: %w", err)
			}
			if existing != nil {
				return fmt.Errorf("secret %q already exists; use 'secret update' to change it", key)
			}

			encKey, err := crypto.DeriveEncKey(masterKey, key)
			if err != nil {
				return fmt.Errorf("derive key: %w", err)
			}
			encrypted, err := crypto.Encrypt(encKey, value)
			if err != nil {
				return fmt.Errorf("encrypt: %w", err)
			}
			if err := database.UpsertSecret(keyHash, encrypted); err != nil {
				return fmt.Errorf("store: %w", err)
			}

			fmt.Printf("Secret %q added.\n", key)
			return nil
		},
	}

	cmd.Flags().StringVar(&key, "key", "", "Secret key name")
	cmd.Flags().StringVar(&value, "value", "", "Secret value")
	_ = cmd.MarkFlagRequired("key")
	_ = cmd.MarkFlagRequired("value")
	return cmd
}

func secretUpdateCmd() *cobra.Command {
	var key, value string

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update an existing secret's value",
		RunE: func(cmd *cobra.Command, args []string) error {
			if key == "" || value == "" {
				return fmt.Errorf("--key and --value are required")
			}

			database, masterKey := mustOpenDB()
			defer database.Close()

			keyHash := crypto.KeyHash(masterKey, key)

			// Verify the secret exists before updating
			existing, err := database.GetSecretByKeyHash(keyHash)
			if err != nil {
				return fmt.Errorf("db lookup: %w", err)
			}
			if existing == nil {
				return fmt.Errorf("secret %q not found; use 'secret add' to create it", key)
			}

			encKey, err := crypto.DeriveEncKey(masterKey, key)
			if err != nil {
				return fmt.Errorf("derive key: %w", err)
			}
			encrypted, err := crypto.Encrypt(encKey, value)
			if err != nil {
				return fmt.Errorf("encrypt: %w", err)
			}
			if err := database.UpsertSecret(keyHash, encrypted); err != nil {
				return fmt.Errorf("store: %w", err)
			}

			fmt.Printf("Secret %q updated.\n", key)
			return nil
		},
	}

	cmd.Flags().StringVar(&key, "key", "", "Secret key name")
	cmd.Flags().StringVar(&value, "value", "", "New secret value")
	_ = cmd.MarkFlagRequired("key")
	_ = cmd.MarkFlagRequired("value")
	return cmd
}

func secretDeleteCmd() *cobra.Command {
	var key string

	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a secret",
		RunE: func(cmd *cobra.Command, args []string) error {
			if key == "" {
				return fmt.Errorf("--key is required")
			}

			database, masterKey := mustOpenDB()
			defer database.Close()

			keyHash := crypto.KeyHash(masterKey, key)
			deleted, err := database.DeleteSecret(keyHash)
			if err != nil {
				return fmt.Errorf("delete: %w", err)
			}
			if !deleted {
				return fmt.Errorf("secret %q not found", key)
			}

			fmt.Printf("Secret %q deleted.\n", key)
			return nil
		},
	}

	cmd.Flags().StringVar(&key, "key", "", "Secret key name to delete")
	_ = cmd.MarkFlagRequired("key")
	return cmd
}

// ─── token ────────────────────────────────────────────────────────────────────

func tokenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Manage API access tokens (create, revoke, list)",
	}
	cmd.AddCommand(tokenCreateCmd(), tokenRevokeCmd(), tokenListCmd())
	return cmd
}

func tokenCreateCmd() *cobra.Command {
	var name string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new access token (raw token shown ONCE)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return fmt.Errorf("--name is required")
			}

			database, _ := mustOpenDB()
			defer database.Close()

			rawToken, encoded, err := crypto.GenerateToken()
			if err != nil {
				return fmt.Errorf("generate token: %w", err)
			}

			tokenHash, err := crypto.HashToken(rawToken)
			if err != nil {
				return fmt.Errorf("hash token: %w", err)
			}

			tokenSHA256 := crypto.TokenSHA256(rawToken)

			if err := database.CreateToken(tokenHash, tokenSHA256, name); err != nil {
				return fmt.Errorf("store token: %w", err)
			}

			fmt.Println("╔══════════════════════════════════════════════════════════════╗")
			fmt.Println("║           ACCESS TOKEN — SHOWN ONCE, SAVE NOW               ║")
			fmt.Println("╠══════════════════════════════════════════════════════════════╣")
			fmt.Printf("║  Name:  %s\n", name)
			fmt.Printf("║  Token: %s\n", encoded)
			fmt.Println("╠══════════════════════════════════════════════════════════════╣")
			fmt.Println("║  Authorization: Bearer <token>                               ║")
			fmt.Println("╚══════════════════════════════════════════════════════════════╝")
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Human-readable label for this token (e.g. \"ci-runner\")")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func tokenRevokeCmd() *cobra.Command {
	var name string

	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke an access token by name",
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return fmt.Errorf("--name is required")
			}

			database, _ := mustOpenDB()
			defer database.Close()

			revoked, err := database.RevokeToken(name)
			if err != nil {
				return fmt.Errorf("revoke: %w", err)
			}
			if !revoked {
				return fmt.Errorf("no active token found with name %q", name)
			}

			fmt.Printf("Token %q revoked.\n", name)
			fmt.Println("Note: the server-side token cache will expire within 5 minutes.")
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Token name to revoke")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func tokenListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all tokens (name and status only — raw tokens never shown)",
		RunE: func(cmd *cobra.Command, args []string) error {
			database, _ := mustOpenDB()
			defer database.Close()

			tokens, err := database.ListTokenNames()
			if err != nil {
				return fmt.Errorf("list: %w", err)
			}

			if len(tokens) == 0 {
				fmt.Println("No tokens found.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tSTATUS\tCREATED\tLAST USED")
			fmt.Fprintln(w, "────\t──────\t───────\t─────────")
			for _, t := range tokens {
				status := "active"
				if !t.IsActive {
					status = "revoked"
				}
				lastUsed := "never"
				if t.LastUsedAt != nil {
					lastUsed = t.LastUsedAt.Format(time.RFC3339)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
					t.Name,
					status,
					t.CreatedAt.Format(time.RFC3339),
					lastUsed,
				)
			}
			return w.Flush()
		},
	}
}
