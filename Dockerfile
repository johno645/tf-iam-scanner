# Build stage
FROM golang:1.23-alpine AS builder

# Set working directory
WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -o tf-iam-scanner \
    .

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -S scanner && \
    adduser -S scanner -G scanner

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/tf-iam-scanner .
COPY --from=builder /build/permissions.json .

# Change ownership to non-root user
RUN chown scanner:scanner /app/tf-iam-scanner /app/permissions.json

# Switch to non-root user
USER scanner

# Make binary executable
RUN chmod +x tf-iam-scanner

# Set entrypoint
ENTRYPOINT ["/app/tf-iam-scanner"]

