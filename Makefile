# Makefile
APP_NAME = oauth
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
	go test -v ./...

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


# Linting
.PHONY: lint
lint:
	@echo "Linting code..."
	golangci-lint run ./...

.PHONY: build-development
build-development: ## Build the development docker image.
	docker compose -f docker/development/docker-compose.yaml build

.PHONY: start-development
start-development: ## Start the development docker container.
	docker compose -f docker/development/docker-compose.yaml up -d

.PHONY: stop-development
stop-development: ## Stop the development docker container.
	docker compose -f docker/development/docker-compose.yaml down

.PHONY: build-staging
build-staging: ## Build the staging docker image.
	docker compose -f docker/staging/docker-compose.yaml build

.PHONY: start-staging
start-staging: ## Start the staging docker container.
	docker compose -f docker/staging/docker-compose.yaml up -d

.PHONY: stop-staging
stop-staging: ## Stop the staging docker container.
	docker compose -f docker/staging/docker-compose.yaml down
  
.PHONY: build-production
build-production: ## Build the production docker image.
	docker compose -f docker/production/docker-compose.yaml build

.PHONY: start-production
start-production: ## Start the production docker container.
	docker compose -f docker/production/docker-compose.yaml up -d --force-recreate

.PHONY: stop-production
stop-production: ## Stop the production docker container.
	docker compose -f docker/production/docker-compose.yaml down