.DEFAULT_GOAL := help

VERSION := $(shell git describe --tags --abbrev=0)

tests: ## Run tests with coverage
	go test -v -cover ./...

profile_tests: ## Run tests and output coverage profiling
	go test -v -coverprofile=coverage.out .
	go tool cover -html=coverage.out

cli: ## Build CLI binary
	go build -o ./dist/bip39 -ldflags "-X main.version=${VERSION}" ./cmd/*.go

clean: ## Clear all build artifacts
	rm -r ./dist

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
