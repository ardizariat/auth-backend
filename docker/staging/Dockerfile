# Build Stage
FROM golang:1.23 AS builder

WORKDIR /app

# Copy go.mod and go.sum files and download dependencies
COPY go.* .
RUN go mod download

# Install go-migrate tool
RUN go install -tags 'postgres mysql' github.com/golang-migrate/migrate/v4/cmd/migrate@latest


# Copy the rest of the application files
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o main cmd/web/main.go

# Final Stage
FROM alpine:latest

# Label
LABEL DEVELOPER="ardizariat"

# Install CA certificates for HTTPS requests
RUN apk update && apk upgrade && apk add --no-cache git ca-certificates

# Set the working directory for the final image
WORKDIR /app

# Copy the binary and the configuration file from the builder stage
COPY --from=builder /app/main ./
COPY --from=builder /app/config-docker.yaml config.yaml

EXPOSE 9000

# Run migrations and then start the application
CMD ["./main"]
# CMD ["sh", "-c", "if [ \"$DB_TYPE\" = 'postgres' ]; then migrate -path /app/migrations -database 'postgres://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME?sslmode=disable' up; elif [ \"$DB_TYPE\" = 'mysql' ]; then migrate -path /app/migrations -database 'mysql://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME' up; else echo 'Unsupported DB_TYPE: $DB_TYPE'; exit 1; fi && ./main"]
