.PHONY: build run clean cleanup fmt vet

BINARY  := bin/golan
MODULE  := github.com/mcrn/goLAN
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

build:
	@echo "Building $(BINARY)..."
	@mkdir -p bin
	@go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY) ./cmd/golan

run: build
	@echo "Starting goLAN (requires sudo)..."
	@sudo ./$(BINARY)

clean:
	@rm -rf bin/
	@echo "Cleaned."

cleanup: build
	@echo "Cleaning up stale bridges..."
	@sudo ./$(BINARY) --cleanup

fmt:
	@go fmt ./...

vet:
	@go vet ./...

test:
	@go test ./...
