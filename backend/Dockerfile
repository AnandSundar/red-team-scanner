# =============================================================================
# Build Stage
# =============================================================================
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /build

# Copy go mod files first for better layer caching
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the application with optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o /build/server \
    ./cmd/server

# =============================================================================
# Development Stage (includes debug tools)
# =============================================================================
FROM golang:1.23-alpine AS development

RUN apk add --no-cache git ca-certificates curl wget

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

# Install delve for debugging (optional, don't fail if it doesn't work)
RUN go install github.com/go-delve/delve/cmd/dlv@latest || echo "Delve installation skipped"

COPY . .

EXPOSE 8080 40000

CMD ["go", "run", "./cmd/server"]

# =============================================================================
# Runtime Stage (minimal, production-ready)
# =============================================================================
FROM alpine:latest AS runtime

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates curl

# Create non-root user for security
RUN addgroup -g 1000 -S appgroup && \
    adduser -u 1000 -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /build/server .

# Change ownership to non-root user
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose application port
EXPOSE 8080

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost:8080/health || exit 1

# Run the binary
CMD ["./server"]

# =============================================================================
# Distroless Stage (ultra-minimal, maximum security)
# =============================================================================
FROM gcr.io/distroless/static-debian12:latest AS distroless

WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /build/server .

# Copy CA certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Use nonroot user (65532:65532 in distroless)
USER nonroot:nonroot

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/app/server", "--health-check"] || exit 1

ENTRYPOINT ["./server"]
