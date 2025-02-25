# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache bash curl sh busybox

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o llmass

# Final stage
FROM alpine:latest

WORKDIR /app

# Install necessary runtime dependencies
RUN apk add --no-cache bash curl

# Copy binary from builder
COPY --from=builder /app/llmass .
COPY --from=builder /app/README.md .
COPY --from=builder /app/CONTEXT.md .

# Create sessions directory
RUN mkdir -p sessions

# Set environment variables
ENV PORT=8083
ENV SESSIONS_DIR=sessions

# Expose the port
EXPOSE 8083

# Run the application
CMD ["./llmass"]