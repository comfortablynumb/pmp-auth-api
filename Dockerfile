# Multi-stage build for Rust application

# Build stage
FROM rust:1.91-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY ./src ./src
COPY ./static ./static
COPY ./migrations ./migrations
COPY ./keys ./keys

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/target/release/pmp-auth-api /app/pmp-auth-api

# Copy configuration files
COPY config /app/config
COPY keys /app/keys

# Create data directory
RUN mkdir -p /app/data

# Expose port
EXPOSE 3000

# Set environment variables
ENV RUST_LOG=info
ENV CONFIG_PATH=/app/config/config.docker.yaml

# Run the application
CMD ["/app/pmp-auth-api"]
