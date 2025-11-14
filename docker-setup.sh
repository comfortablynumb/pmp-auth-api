#!/bin/bash
# Docker environment setup script for PMP Auth API

set -e

echo "🚀 Setting up PMP Auth API Docker environment..."

# Create keys directory
echo "📁 Creating keys directory..."
mkdir -p keys

# Check if keys already exist
if [ -f "keys/demo-private.pem" ]; then
    echo "✅ Keys already exist, skipping generation"
else
    echo "🔑 Generating RSA keys for JWT signing..."

    # Generate private key
    openssl genrsa -out keys/demo-private.pem 2048 2>/dev/null

    # Extract public key
    openssl rsa -in keys/demo-private.pem -pubout -out keys/demo-public.pem 2>/dev/null

    echo "✅ RSA keys generated successfully"
fi

# Create data directory
echo "📁 Creating data directory..."
mkdir -p data

echo ""
echo "✨ Setup complete! You can now run:"
echo ""
echo "  docker-compose up -d         # Start all services"
echo "  docker-compose logs -f       # View logs"
echo "  docker-compose ps            # Check status"
echo ""
echo "📚 See DOCKER.md for detailed usage instructions"
echo ""
echo "🌐 Services will be available at:"
echo "  - API:           http://localhost:3000"
echo "  - phpLDAPadmin:  http://localhost:8080"
echo "  - Grafana:       http://localhost:3001"
echo "  - Prometheus:    http://localhost:9090"
echo "  - Mailhog:       http://localhost:8025"
echo ""
