// vault — API server binary.
// Usage: VAULT_MASTER_KEY=<key> vault serve [--port 8080]
package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/spf13/cobra"

	"github.com/local/password-vault/internal/api"
	"github.com/local/password-vault/internal/auth"
	"github.com/local/password-vault/internal/config"
	"github.com/local/password-vault/internal/db"
	"github.com/local/password-vault/internal/ratelimit"
)

func main() {
	root := &cobra.Command{
		Use:   "vault",
		Short: "Password vault API server",
	}
	root.AddCommand(serveCmd())
	if err := root.Execute(); err != nil {
		log.Fatal(err)
	}
}

func serveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the vault HTTP API server",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("config: %w", err)
			}

			database, err := db.Init(cfg.DBPath)
			if err != nil {
				return fmt.Errorf("db: %w", err)
			}
			defer database.Close()

			authMiddleware := auth.New(database)
			handler := api.New(database, cfg.MasterKey)
			limiter := ratelimit.New(cfg.RateLimit)

			r := chi.NewRouter()

			// Standard middleware stack
			r.Use(middleware.RequestID)
			r.Use(middleware.RealIP) // trust X-Real-IP from reverse proxy
			r.Use(middleware.Logger)
			r.Use(middleware.Recoverer)
			r.Use(middleware.Timeout(30 * time.Second))
			r.Use(limiter.Middleware)

			// Public endpoints
			r.Get("/health", handler.Health)

			// Protected endpoints — auth middleware wraps this group
			r.Group(func(r chi.Router) {
				r.Use(authMiddleware.Authenticate)
				r.Get("/secret/{key_name}", handler.GetSecret)
			})

			// Return 404 for everything else (no endpoint discovery)
			r.NotFound(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			})

			addr := fmt.Sprintf(":%d", cfg.Port)
			log.Printf("vault listening on %s (db=%s, rate=%.0f req/s)", addr, cfg.DBPath, cfg.RateLimit)
			return http.ListenAndServe(addr, r)
		},
	}
}
