# Build Stage
FROM golang:1.23 AS build-stage

WORKDIR /app

# Copy all files and download dependencies
COPY . .

# Download dependencies
RUN go mod download

# Build the Go app
RUN CGO_ENABLED=0 GOOS=linux go build -o /goapp ./cmd/web/main.go

# Final Stage
FROM gcr.io/distroless/base-debian11 AS build-release-stage

WORKDIR /

# Copy the built app
COPY --from=build-stage /goapp /goapp

# Copy the config.yaml file to the root directory in the final image
COPY --from=build-stage /app/config.yaml /config.yaml

EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT ["./goapp"]
