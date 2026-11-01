VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.DEFAULT_GOAL := help

##@ Develop

test: ## Tests with the race detector, vet and gofmt
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }
	go vet ./...
	go test -race ./...

build: ## Build bin/edge-guard for this machine
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/edge-guard ./cmd/edge-guard

##@ Release

dist: ## Build every OS/CPU into dist/ with SHA256SUMS
	rm -rf dist && mkdir -p dist
	for os in linux darwin windows freebsd; do for arch in amd64 arm64; do \
		ext=""; [ $$os = windows ] && ext=".exe"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/edge-guard-$$os-$$arch$$ext ./cmd/edge-guard || exit 1; \
	done; done
	cd dist && sha256sum edge-guard-* > SHA256SUMS 2>/dev/null || shasum -a 256 edge-guard-* > SHA256SUMS

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

.PHONY: test build dist help
