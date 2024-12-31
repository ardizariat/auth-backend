# # Build Stage
# FROM golang:1.23 AS builder

# WORKDIR /app

# # Install the migrate CLI
# RUN go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

# # Copy go.mod and go.sum files and download dependencies
# COPY go.* .
# RUN go mod download

# # Copy the rest of the application files
# COPY . .

# # Build the application
# RUN CGO_ENABLED=0 GOOS=linux go build -o main cmd/web/main.go

# # Final Stage
# FROM alpine:latest

# # Label
# LABEL DEVELOPER="ardizariat"

# # Install CA certificates and other dependencies
# RUN apk update && apk upgrade && apk add --no-cache git ca-certificates && apk add vim

# # Set the working directory
# WORKDIR /app

# # Copy application binary, config, and migration files
# COPY --from=builder /app/main ./main
# COPY --from=builder /app/config-docker.yaml ./config.yaml
# COPY --from=builder /app/database/migrations ./migrations

# # Copy migrate binary
# COPY --from=builder /go/bin/migrate /usr/local/bin/migrate

# # Expose the application port
# EXPOSE 9000

# # Run migrations and start the application
# CMD ["sh", "-c", "migrate -path ./migrations -database postgres://postgres:postgres@postgres-16:5432/oauth?sslmode=disable up && ./main"]


# Build Stage
FROM golang:1.23 AS builder

WORKDIR /app

# Copy go.mod and go.sum files and download dependencies
COPY go.* .
RUN go mod download

# Copy the rest of the application files
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o main cmd/web/main.go

# Final Stage
FROM alpine:latest

# Label
LABEL DEVELOPER="ardizariat"

# Install CA certificates for HTTPS requests
RUN apk update && apk upgrade && apk add --no-cache git ca-certificates && apk add vim

# Set the working directory for the final image
WORKDIR /app

# Copy the binary and the configuration file from the builder stage
COPY --from=builder /app/main ./
COPY --from=builder /app/config-docker.yaml ./config.yaml

EXPOSE 9000

# Run migrations and then start the application
CMD ["./main"]