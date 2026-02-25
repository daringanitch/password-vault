# ─── Stage 1: Build ───────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

# git is needed by go mod download for some VCS dependencies
RUN apk add --no-cache git

WORKDIR /build

# Copy everything. Once go.sum is committed, split this into two COPY steps
# (go.mod+go.sum first, then source) to cache the dependency download layer.
COPY . .

# Generate go.sum if it doesn't exist, then download all verified dependencies.
RUN go mod tidy && go mod download

# Build both static binaries. CGO_ENABLED=0 → pure Go, links to nothing.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/vault ./cmd/vault && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/vault-cli ./cmd/vault-cli

# ─── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM alpine:3.19

# ca-certificates: needed if vault ever makes outbound TLS calls
# tzdata: correct timestamps in last_used_at / created_at columns
RUN apk add --no-cache ca-certificates tzdata && \
    # Create a dedicated non-root user
    addgroup -S vault && \
    adduser  -S vault -G vault -h /vault

WORKDIR /vault

# Copy both binaries from the builder stage
COPY --from=builder /out/vault     /usr/local/bin/vault
COPY --from=builder /out/vault-cli /usr/local/bin/vault-cli

# Data directory for vault.db — mount a named volume here in production
RUN mkdir -p /vault/data && chown -R vault:vault /vault/data

USER vault

# ─── Runtime configuration ────────────────────────────────────────────────────
# VAULT_MASTER_KEY must be injected at runtime (never bake it into the image).
ENV VAULT_DB_PATH=/vault/data/vault.db
ENV VAULT_PORT=8080
ENV VAULT_RATE_LIMIT=5

VOLUME ["/vault/data"]

EXPOSE 8080

# Default command: start the API server.
# Override with vault-cli for admin operations:
#   docker run --rm -it -e VAULT_MASTER_KEY=... vault vault-cli token list
ENTRYPOINT ["vault"]
CMD ["serve"]

# ─── Image metadata ───────────────────────────────────────────────────────────
LABEL org.opencontainers.image.title="password-vault" \
      org.opencontainers.image.description="Black-box password vault: AES-256-GCM, Argon2id tokens, no enumeration" \
      org.opencontainers.image.source="https://github.com/daringanitch/password-vault" \
      org.opencontainers.image.licenses="MIT"
