# Build Stage
FROM golang:1.23 AS builder

WORKDIR /app


# Copy go.mod and go.sum files and download dependencies
COPY ../../go.* .
RUN go mod download

# Copy the rest of the application files
COPY ../../. .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o main ../../cmd/web/main.go

# Final Stage
FROM alpine:latest

# Install CA certificates for HTTPS requests
RUN apk update && apk upgrade && apk add --no-cache git ca-certificates

# Set the working directory for the final image
WORKDIR /app

# Copy the binary and the configuration file from the builder stage
COPY --from=builder /app/main ./
COPY --from=builder /app/config.yaml ./

# Run migrations and then start the application
CMD ["./main"]