.PHONY: build run clean cleanup fmt vet

BINARY  := golan
MODULE  := github.com/mcrn/goLAN
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

build:
	@echo "Building $(BINARY)..."
	@go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY) ./cmd/golan

install: build
	@echo "Installing goLAN..."
	@go install ./cmd/golan

run: build
	@echo "Starting goLAN (requires sudo)..."
	@sudo ./$(BINARY)

clean:
	@rm -f $(BINARY)
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
