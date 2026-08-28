.PHONY: build test fmt lint check

GOLANGCI_LINT_VERSION ?= v2.13.2

build:
	go build ./cmd/radare2-mcp

test:
	go test ./...

fmt:
	gofmt -w $$(find . -name '*.go' -type f)

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run

check: fmt test lint build
