.PHONY: build install run clean fmt vet test

BINARY  := golan
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

build:
	@echo "Building $(BINARY)..."
	@go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY) ./cmd/golan

install: build
	@echo "Installing golan..."
	@go install ./cmd/golan

run: build
	@echo "Starting golan (requires sudo)..."
	@sudo ./$(BINARY)

clean:
	@rm -f $(BINARY)
	@echo "Cleaned."

fmt:
	@go fmt ./...

vet:
	@go vet ./...

test:
	@go test ./...
