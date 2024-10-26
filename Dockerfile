# Build Stage
FROM golang:1.23 AS builder

WORKDIR /app

# Copy go.mod and go.sum files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application files
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o cmd/web/main ./cmd/web/main.go

# Final Stage
FROM alpine:latest

# Install CA certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

# Set the working directory for the final image
WORKDIR /root/

# Copy the binary and the configuration file from the builder stage
COPY --from=builder /app/cmd/web/main .
COPY --from=builder /app/config.yml .

# Run the executable
CMD ["./main"]