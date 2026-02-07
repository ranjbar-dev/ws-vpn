.PHONY: all build build-server build-client clean deps test

# Build output directory
BUILD_DIR := build

# Binary names
SERVER_BINARY := vpn-server
CLIENT_BINARY := vpn-client.exe

# Go build flags
LDFLAGS := -s -w

all: deps build

deps:
	go mod download
	go mod tidy

build: build-server build-client

build-server:
	@echo "Building server for Linux..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(SERVER_BINARY) ./cmd/server

build-client:
	@echo "Building client for Windows..."
	@mkdir -p $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(CLIENT_BINARY) ./cmd/client

build-local:
	@echo "Building for current platform..."
	@mkdir -p $(BUILD_DIR)
	go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/ ./cmd/...

test:
	go test -v ./...

test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

lint:
	golangci-lint run ./...

clean:
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# Generate self-signed certificate for testing
gen-cert:
	@mkdir -p certs
	openssl req -x509 -newkey rsa:4096 \
		-keyout certs/server.key \
		-out certs/server.crt \
		-days 365 \
		-nodes \
		-subj "/CN=vpn-server"
	@echo "Certificates generated in certs/"

# Copy example configs
init-config:
	@mkdir -p /etc/vpn 2>/dev/null || true
	cp configs/server.yaml.example server.yaml
	cp configs/client.yaml.example client.yaml
	@echo "Configuration files created. Edit them before running."

help:
	@echo "Available targets:"
	@echo "  all          - Download deps and build everything"
	@echo "  deps         - Download and tidy dependencies"
	@echo "  build        - Build server (Linux) and client (Windows)"
	@echo "  build-server - Build server for Linux"
	@echo "  build-client - Build client for Windows"
	@echo "  build-local  - Build for current platform"
	@echo "  test         - Run tests"
	@echo "  test-coverage- Run tests with coverage"
	@echo "  lint         - Run linter"
	@echo "  clean        - Remove build artifacts"
	@echo "  gen-cert     - Generate self-signed TLS certificates"
	@echo "  init-config  - Copy example configs"
	@echo "  help         - Show this help"
