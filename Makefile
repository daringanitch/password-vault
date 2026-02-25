GOFLAGS    := -trimpath
LDFLAGS    := -s -w
BIN_DIR    := ./bin
IMAGE_NAME := password-vault
IMAGE_TAG  := latest

.PHONY: all build build-vault build-cli run test lint clean tidy \
        docker-build docker-run docker-push docker-compose-up docker-compose-down

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

# ─── Docker targets ───────────────────────────────────────────────────────────

## docker-build: build the Docker image
docker-build:
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

## docker-build-no-cache: force a clean Docker build
docker-build-no-cache:
	docker build --no-cache -t $(IMAGE_NAME):$(IMAGE_TAG) .

## docker-run: run the vault server in Docker (requires VAULT_MASTER_KEY)
docker-run:
	@test -n "$$VAULT_MASTER_KEY" || (echo "Error: VAULT_MASTER_KEY is not set" && exit 1)
	docker run --rm \
	  -p 8080:8080 \
	  -e VAULT_MASTER_KEY="$$VAULT_MASTER_KEY" \
	  -v vault-data:/vault/data \
	  $(IMAGE_NAME):$(IMAGE_TAG)

## docker-cli: run a vault-cli command in Docker (e.g. make docker-cli CMD="token list")
docker-cli:
	@test -n "$$VAULT_MASTER_KEY" || (echo "Error: VAULT_MASTER_KEY is not set" && exit 1)
	docker run --rm \
	  -e VAULT_MASTER_KEY="$$VAULT_MASTER_KEY" \
	  -v vault-data:/vault/data \
	  --entrypoint vault-cli \
	  $(IMAGE_NAME):$(IMAGE_TAG) $(CMD)

## docker-compose-up: start via docker compose
docker-compose-up:
	docker compose up -d

## docker-compose-down: stop and remove containers
docker-compose-down:
	docker compose down

## docker-push: push image to a registry (set REGISTRY=ghcr.io/youruser to override)
docker-push:
	@test -n "$(REGISTRY)" || (echo "Error: set REGISTRY=ghcr.io/youruser" && exit 1)
	docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
	docker push $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
