GOFLAGS  := -trimpath
LDFLAGS  := -s -w
BIN_DIR  := ./bin

.PHONY: all build build-vault build-cli run test lint clean tidy

all: build

## build: compile both binaries to ./bin/
build: build-vault build-cli

build-vault:
	@mkdir -p $(BIN_DIR)
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/vault ./cmd/vault

build-cli:
	@mkdir -p $(BIN_DIR)
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/vault-cli ./cmd/vault-cli

## run: start the vault server (requires VAULT_MASTER_KEY)
run: build-vault
	$(BIN_DIR)/vault serve

## test: run all tests with coverage
test:
	go test ./... -v -race -count=1 -coverprofile=coverage.out
	@go tool cover -func=coverage.out | tail -1

## test-crypto: run only the crypto package tests (fast, no Argon2id in most tests)
test-crypto:
	go test ./internal/crypto/... -v -race -count=1

## lint: run go vet
lint:
	go vet ./...

## tidy: update go.sum
tidy:
	go mod tidy

## clean: remove build artifacts
clean:
	rm -rf $(BIN_DIR) coverage.out

## init-vault: one-liner to generate a key and initialize vault.db
init-vault: build-cli
	$(BIN_DIR)/vault-cli init
