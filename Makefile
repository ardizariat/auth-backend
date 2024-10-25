# Makefile
APP_NAME = goauth
SRC_DIR = ./cmd/web
BUILD_DIR = ./bin
GO_FILES = $(wildcard $(SRC_DIR)/*.go)

# Default target
.PHONY: all
all: build

# Build the application
.PHONY: build
build:
	@echo "Building the application..."
	@if [ -z "$(GO_FILES)" ]; then \
		echo "No Go files found in $(SRC_DIR)."; \
		exit 1; \
	fi
	go build -o $(BUILD_DIR)/$(APP_NAME) $(GO_FILES)

# Run the application
.PHONY: run
run: build
	@echo "Running the application..."
	$(BUILD_DIR)/$(APP_NAME)

# Test the application
.PHONY: test
test:
	@echo "Running tests..."
#go test -v ./... -cover
	go test -v -coverprofile=coverage.out ./...

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning up..."
	rm -rf $(BUILD_DIR)/$(APP_NAME)

# Install dependencies
.PHONY: install
install:
	@echo "Installing dependencies..."
	go mod tidy

# Help
.PHONY: help
help:
	@echo "Makefile commands:"
	@echo "  make all       - Build the application (default target)"
	@echo "  make build     - Build the application"
	@echo "  make run       - Build and run the application"
	@echo "  make test      - Run tests"
	@echo "  make clean     - Clean build artifacts"
	@echo "  make install   - Install dependencies"
	@echo "  make help      - Show this help message"