PLUGIN_NAME := vault-plugin-secrets-aap
PLUGIN_DIR  := vault/plugins
BIN         := $(PLUGIN_DIR)/$(PLUGIN_NAME)
GOBIN       := $(shell go env GOPATH)/bin

.PHONY: all build test testacc lint fmt vet tidy clean enable dev snapshot vault-smoke

# Local release dry-run (no publish). Requires goreleaser; produces dist/.
snapshot:
	goreleaser release --snapshot --clean

all: fmt vet lint test build

build:
	@mkdir -p $(PLUGIN_DIR)
	CGO_ENABLED=0 go build -o $(BIN) ./cmd/$(PLUGIN_NAME)

# Unit tests (no network).
test:
	go test -race -cover ./...

# Acceptance tests against a live AAP. Source a .env (see .env.example) first:
#   set -a && . ./.env && set +a && make testacc
testacc:
	VAULT_ACC=1 go test -v -count=1 -run TestAcceptance ./...

vault-smoke: build
	./scripts/vault-dev-smoke.sh

lint:
	golangci-lint run ./...

fmt:
	gofmt -w -s .
	@command -v goimports >/dev/null 2>&1 && goimports -w -local github.com/hashi-demo-lab/$(PLUGIN_NAME) . || true

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -rf $(PLUGIN_DIR) bin dist coverage.*

# Register + enable the freshly built plugin in a running dev Vault.
# Requires VAULT_ADDR and VAULT_TOKEN in the environment.
enable: build
	@SHA=$$(shasum -a 256 $(BIN) | cut -d' ' -f1); \
	vault plugin register -sha256=$$SHA secret $(PLUGIN_NAME); \
	vault secrets enable -path=aap $(PLUGIN_NAME)

# Run a local dev Vault with this plugin directory mounted.
dev: build
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=$(PLUGIN_DIR)
